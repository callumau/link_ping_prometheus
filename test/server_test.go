package prober_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"net"
	"strings"
	"testing"
	"time"

	"link_ping_prometheus/internal/prober"
)

// mustAllow builds a test allowlist; panics on the (constant) parse
// error so test tables stay one-liners.
func mustAllow(s string) *prober.Allowlist {
	a, err := prober.ParseAllowlist(s)
	if err != nil {
		panic(err)
	}
	return a
}

// testAllow is the fail-closed client allowlist used by server tests:
// all dial from the loopback IP, so it is the sole permitted prober.
var testAllow = mustAllow("127.0.0.1")

// startServer starts ServePacketConn on an ephemeral loopback port with
// the standard test allowlist, returning the port address. The socket is
// closed on ctx cancel; t.Cleanup waits for the echo loop to return so a
// leaked server goroutine cannot race a later test writing the shared
// rate-limit cap variables.
func startServer(t *testing.T, ctx context.Context) string {
	t.Helper()
	pc := listenUDP(t, ctx)
	done := make(chan struct{})
	go func() {
		prober.ServePacketConn(ctx, pc, testSource, testAllow, "")
		close(done)
	}()
	t.Cleanup(func() { <-done })
	return pc.LocalAddr().String()
}

// startServerDone is startServer with a channel that is closed when
// ServePacketConn returns, for tests that assert shutdown behavior.
func startServerDone(t *testing.T, ctx context.Context) (string, <-chan struct{}) {
	t.Helper()
	pc := listenUDP(t, ctx)
	done := make(chan struct{})
	go func() {
		prober.ServePacketConn(ctx, pc, testSource, testAllow, "")
		close(done)
	}()
	return pc.LocalAddr().String(), done
}

// dialProbe opens a UDP conn to addr and builds one valid probe frame.
func dialProbe(t *testing.T, addr string) (net.Conn, []byte) {
	t.Helper()
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	probe := make([]byte, prober.PayloadSize)
	copy(probe[0:8], prober.MagicBytes)
	return conn, probe
}

// TestGarbageData_Server: a peer that answers probes with garbage (wrong
// size, wrong magic) must never be counted as a valid response.
func TestGarbageData_Server(t *testing.T) {
	prober.InitMetrics()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fake, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer fake.Close()

	go func() {
		buf := make([]byte, 1500)
		for {
			n, raddr, err := fake.ReadFrom(buf)
			if err != nil {
				return
			}
			if n == prober.PayloadSize {
				// Same size but invalid magic.
				bad := make([]byte, prober.PayloadSize)
				copy(bad[0:8], "BADHEADR")
				fake.WriteTo(bad, raddr)
			} else {
				fake.WriteTo([]byte("garbage data garbage data garbage data"), raddr)
			}
		}
	}()

	targetName := "garbage_test"
	cfg := cfgWith(false, 100*time.Millisecond, 100*time.Millisecond, prober.Target{Name: targetName, Address: fake.LocalAddr().String()})
	startRecv := getHistogramCount(prober.RTTSeconds, targetName, fake.LocalAddr().String())

	go prober.RunClient(ctx, cfg)
	time.Sleep(500 * time.Millisecond)
	cancel()

	endRecv := getHistogramCount(prober.RTTSeconds, targetName, fake.LocalAddr().String())
	endSent := getCounterValue(prober.ProbesSent, targetName, fake.LocalAddr().String())
	// Vacuous-pass guard: the client must actually have probed.
	if endSent < 1 {
		t.Fatalf("client sent no probes; assertion below is vacuous (cpu load?)")
	}
	if endRecv > startRecv {
		t.Errorf("Garbage data counted as valid response? %v -> %v", startRecv, endRecv)
	}
}

func TestServer_EnforceSizeAndHeader(t *testing.T) {
	prober.InitMetrics()
	ctx := t.Context()

	addr := startServer(t, ctx)

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	reply := make([]byte, 24)

	// A datagram beyond the bounded payload window (header +
	// MaxPayloadBytes) is an arbitrary-payload reflector attempt: no
	// echo. Bounded extensions (header ≤ size ≤ header+1400) are echoed
	// whole — covered in TestServer_BoundedPayloadSizeRange.
	oversized := make([]byte, prober.PayloadSize+prober.MaxPayloadBytes+1)
	copy(oversized[0:8], prober.MagicBytes)
	conn.Write(oversized)
	conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, _ := conn.Read(reply); n != 0 {
		t.Errorf("oversized datagram must not be echoed, got %d bytes", n)
	}

	// Valid 24-byte probe: echoed.
	probe := make([]byte, prober.PayloadSize)
	copy(probe[0:8], prober.MagicBytes)
	conn.Write(probe)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := conn.Read(reply); err != nil || n != prober.PayloadSize {
		t.Fatalf("valid probe must be echoed: n=%d err=%v", n, err)
	}
	if string(reply[0:8]) != prober.MagicBytes {
		t.Errorf("Reply header invalid")
	}

	// 24-byte datagram with bad magic: no echo.
	bad := make([]byte, prober.PayloadSize)
	copy(bad[0:8], "BADHEADR")
	conn.Write(bad)
	conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, _ := conn.Read(reply); n != 0 {
		t.Errorf("bad-magic datagram must not be echoed, got %d bytes", n)
	}

	if got := getCounterValue(prober.ServerProbesReceived, "127.0.0.1"); got < 1 {
		t.Errorf("Server should have counted the valid probe, got %v", got)
	}
}

// TestServer_PerIPRateLimit: packets beyond MaxPktsPerIP from one remote
// IP within a rate window must be dropped, while packets within the
// limit keep being echoed.
func TestServer_PerIPRateLimit(t *testing.T) {
	prober.InitMetrics()
	oldIP, oldGlobal := prober.MaxPktsPerIP, prober.MaxPktsGlobal
	prober.MaxPktsPerIP = 3

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr, done := startServerDone(t, ctx)
	// Restore the shared test variables after ServePacketConn has
	// returned; it reads them at startup.
	defer func() {
		cancel()
		<-done
		prober.MaxPktsPerIP, prober.MaxPktsGlobal = oldIP, oldGlobal
	}()

	conn, probe := dialProbe(t, addr)
	defer conn.Close()

	got := 0
	for range 3 {
		conn.Write(probe)
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		if n, err := conn.Read(make([]byte, prober.PayloadSize)); err == nil && n == prober.PayloadSize {
			got++
		}
	}
	if got != 3 {
		t.Fatalf("expected 3 echoes within the per-IP limit, got %d", got)
	}

	// 4th datagram in the same rate window must be dropped.
	conn.Write(probe)
	conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, _ := conn.Read(make([]byte, prober.PayloadSize)); n != 0 {
		t.Error("packet beyond per-IP limit must be dropped")
	}
}

// TestServer_ProbeCounterIgnoresInvalid: link_server_probes_received_total
// must count only validated probes — garbage datagrams must not inflate it.
// pi-lens-ignore: jscpd:duplicate
func TestServer_ProbeCounterIgnoresInvalid(t *testing.T) {
	prober.InitMetrics()
	ctx := t.Context()

	addr := startServer(t, ctx)

	before := getCounterValue(prober.ServerProbesReceived, "127.0.0.1")

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Valid probe -> counted + echoed.
	probe := make([]byte, prober.PayloadSize)
	copy(probe[0:8], prober.MagicBytes)
	conn.Write(probe)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := conn.Read(make([]byte, prober.PayloadSize)); err != nil || n != prober.PayloadSize {
		t.Fatalf("valid echo failed: n=%d err=%v", n, err)
	}

	// Garbage (invalid magic) -> dropped, must not count.
	conn.Write([]byte("this is not a valid probe frame"))

	// Give the server a beat to process both datagrams.
	time.Sleep(200 * time.Millisecond)

	if got := getCounterValue(prober.ServerProbesReceived, "127.0.0.1") - before; got != 1 {
		t.Errorf("Server counter must increase by exactly 1 (valid probe only), got %v", got)
	}
}

// TestServer_ShutdownOnCancel: ServePacketConn must return promptly on
// context cancellation (the socket is closed to unblock the read loop).
func TestServer_ShutdownOnCancel(t *testing.T) {
	prober.InitMetrics()
	ctx, cancel := context.WithCancel(context.Background())

	pc := listenUDP(t, ctx)

	done := make(chan error, 1)
	go func() {
		done <- prober.ServePacketConn(ctx, pc, testSource, testAllow, "")
	}()

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("ServePacketConn returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ServePacketConn did not return within 5s of cancel")
	}
}

// TestServer_NoEchoAfterShutdown: after cancellation the server must stop
// answering probes (no goroutine left echoing).
func TestServer_NoEchoAfterShutdown(t *testing.T) {
	prober.InitMetrics()
	ctx, cancel := context.WithCancel(context.Background())

	addr, done := startServerDone(t, ctx)

	conn, probe := dialProbe(t, addr)
	defer conn.Close()
	conn.Write(probe)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := conn.Read(make([]byte, prober.PayloadSize)); err != nil || n != prober.PayloadSize {
		t.Fatalf("initial echo failed: n=%d err=%v", n, err)
	}

	cancel()
	<-done

	conn.Write(probe)
	conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, _ := conn.Read(make([]byte, prober.PayloadSize)); n != 0 {
		t.Error("server still echoing after shutdown")
	}
}

// TestServer_AllowlistDropsUnlisted: a valid probe from a source not in
// the fail-closed allowlist must be neither echoed nor counted (fixes
// the reflector and the metric-label-cardinality DoS).
// pi-lens-ignore: jscpd:duplicate
func TestServer_AllowlistDropsUnlisted(t *testing.T) {
	prober.InitMetrics()
	ctx := t.Context()

	addr := startServer(t, ctx)

	before := getCounterValue(prober.ServerProbesReceived, "127.0.0.1")

	// Dial from a loopback alias that is NOT in the allowlist.
	dst, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 0}, dst)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	probe := make([]byte, prober.PayloadSize)
	copy(probe[0:8], prober.MagicBytes)
	conn.Write(probe)
	conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	if n, _ := conn.Read(make([]byte, prober.PayloadSize)); n != 0 {
		t.Error("probe from non-allowlisted source must not be echoed")
	}

	// A probe from 127.0.0.1 (allowlisted) is still echoed + counted.
	ok, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer ok.Close()
	ok.Write(probe)
	ok.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := ok.Read(make([]byte, prober.PayloadSize)); err != nil || n != prober.PayloadSize {
		t.Fatalf("allowlisted echo failed: n=%d err=%v", n, err)
	}

	if got := getCounterValue(prober.ServerProbesReceived, "127.0.0.1") - before; got != 1 {
		t.Errorf("only the allowlisted probe must be counted, got %v", got)
	}
}

// TestServer_FailClosed: RunServer refuses to start with an empty
// allowlist (an empty set admits no clients).
func TestServer_FailClosed(t *testing.T) {
	ctx := t.Context()
	if err := prober.RunServer(ctx, "127.0.0.1:0", testSource, nil, ""); err == nil {
		t.Error("RunServer with empty allowlist must fail closed")
	}
}

// hmacTag computes the 8-byte wire tag independently of the prober
// package internals: truncated HMAC-SHA256 over magic+LE(seq)+LE(ts).
// Deliberately not a call into the code under test so the security
// contract is validated against its own implementation.
func hmacTag(secret string, seq, ts uint64) [8]byte {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(prober.MagicBytes))
	var tmp [16]byte
	binary.LittleEndian.PutUint64(tmp[0:8], seq)
	binary.LittleEndian.PutUint64(tmp[8:16], ts)
	mac.Write(tmp[:])
	var out [8]byte
	copy(out[:], mac.Sum(nil)[:8])
	return out
}

// buildHMACFrame builds one 32-byte probe frame with an authentic tag.
func buildHMACFrame(secret string, seq, ts uint64) []byte {
	frame := make([]byte, prober.PayloadSizeWithHMAC)
	copy(frame[0:8], prober.MagicBytes)
	binary.LittleEndian.PutUint64(frame[8:16], seq)
	binary.LittleEndian.PutUint64(frame[16:24], ts)
	tag := hmacTag(secret, seq, ts)
	copy(frame[24:32], tag[:])
	return frame
}

// startHMACServer starts ServePacketConn with echo authentication
// enabled, returning its port address. Closed on ctx cancel; like
// startServer, t.Cleanup joins the goroutine before the next test runs.
func startHMACServer(t *testing.T, ctx context.Context, secret string) string {
	t.Helper()
	pc := listenUDP(t, ctx)
	done := make(chan struct{})
	go func() {
		prober.ServePacketConn(ctx, pc, testSource, testAllow, secret)
		close(done)
	}()
	t.Cleanup(func() { <-done })
	return pc.LocalAddr().String()
}

// TestServer_HMACAuth: the SEC22 echo-authentication path must accept
// only valid, fresh 32-byte frames from allowed sources — good tags are
// echoed; bad tags, wrong sizes, and stale/replayed timestamps are all
// silently dropped.
func TestServer_HMACAuth(t *testing.T) {
	prober.InitMetrics()
	ctx := t.Context()

	const secret = "test-secret"
	addr := startHMACServer(t, ctx, secret)

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	now := uint64(time.Now().UnixNano())
	// Margins are 61s — twice the replay window plus slack for the
	// accumulated read deadlines of the preceding drop cases — so the
	// assertion can't be flaked away by test-runtime drift.
	stale := uint64(time.Now().Add(-61 * time.Second).UnixNano())
	future := uint64(time.Now().Add(61 * time.Second).UnixNano())

	badMagic24 := make([]byte, prober.PayloadSize)
	copy(badMagic24[0:8], prober.MagicBytes) // right magic, wrong size for an HMAC server

	flipped := buildHMACFrame(secret, 2, now)
	flipped[30] ^= 0xFF // corrupt one tag byte

	cases := []struct {
		name     string
		frame    []byte
		wantEcho bool
	}{
		{"valid fresh frame is echoed", buildHMACFrame(secret, 1, now), true},
		{"corrupted tag is dropped", flipped, false},
		{"24-byte frame at an HMAC server is dropped", badMagic24, false},
		{"stale timestamp (well past window) is dropped", buildHMACFrame(secret, 3, stale), false},
		{"future timestamp (well past window) is dropped", buildHMACFrame(secret, 4, future), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn.Write(tc.frame)
			conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
			n, _ := conn.Read(make([]byte, 1500))
			if tc.wantEcho && n != prober.PayloadSizeWithHMAC {
				t.Fatalf("valid authenticated frame must be echoed, got %d bytes", n)
			}
			if !tc.wantEcho && n != 0 {
				t.Errorf("invalid frame must be dropped, got %d bytes back", n)
			}
		})
	}

	// The drops above must not have wedged the responder: a final valid
	// frame still gets echoed.
	conn.Write(buildHMACFrame(secret, 5, uint64(time.Now().UnixNano())))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, _ := conn.Read(make([]byte, 1500)); n != prober.PayloadSizeWithHMAC {
		t.Errorf("server must keep echoing valid frames after drops, got %d bytes", n)
	}
}

// TestServer_HMACRotation: during a zero-downtime rotation the server
// accepts frames authenticated under either the new or the previous
// secret; an unknown secret is still dropped.
// pi-lens-ignore: go-test-functions
func TestServer_HMACRotation(t *testing.T) {
	prober.InitMetrics()
	ctx := t.Context()

	const newSecret = "test-secret-new"
	const oldSecret = "test-secret"

	pc := listenUDP(t, ctx)
	done := make(chan struct{})
	go func() {
		prober.ServePacketConn(ctx, pc, testSource, testAllow, newSecret, oldSecret)
		close(done)
	}()
	t.Cleanup(func() { <-done })
	addr := pc.LocalAddr().String()

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	now := uint64(time.Now().UnixNano())
	send := func(frame []byte) int {
		conn.Write(frame)
		conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
		n, _ := conn.Read(make([]byte, 1500))
		return n
	}

	if n := send(buildHMACFrame(oldSecret, 1, now)); n != prober.PayloadSizeWithHMAC {
		t.Errorf("old-secret frame must still be echoed during rotation, got %d bytes", n)
	}
	if n := send(buildHMACFrame(newSecret, 2, now)); n != prober.PayloadSizeWithHMAC {
		t.Errorf("new-secret frame must be echoed, got %d bytes", n)
	}
	if n := send(buildHMACFrame("test-secret-unknown", 3, now)); n != 0 {
		t.Errorf("unknown-secret frame must be dropped, got %d bytes", n)
	}

	// Without the rotation secret configured, an old-secret frame is a
	// plain hmac drop again.
	pc2 := listenUDP(t, ctx)
	done2 := make(chan struct{})
	go func() {
		prober.ServePacketConn(ctx, pc2, testSource, testAllow, newSecret)
		close(done2)
	}()
	t.Cleanup(func() { <-done2 })
	conn2, err := net.Dial("udp", pc2.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()
	conn2.Write(buildHMACFrame(oldSecret, 4, uint64(time.Now().UnixNano())))
	conn2.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, _ := conn2.Read(make([]byte, 1500)); n != 0 {
		t.Errorf("old-secret frame without -echo-secret-old must be dropped, got %d bytes", n)
	}
}

// TestServer_PerIPRateLimitResumesNextWindow: exhausting the per-IP
// budget must be temporary — probes resume once the fixed window ticks
// over, so one burst cannot permanently starve a legitimate prober.
func TestServer_PerIPRateLimitResumesNextWindow(t *testing.T) {
	prober.InitMetrics()
	oldIP, oldGlobal := prober.MaxPktsPerIP, prober.MaxPktsGlobal
	prober.MaxPktsPerIP, prober.MaxPktsGlobal = 2, oldGlobal

	ctx, cancel := context.WithCancel(context.Background())
	addr, done := startServerDone(t, ctx)
	defer func() {
		cancel()
		<-done
		prober.MaxPktsPerIP, prober.MaxPktsGlobal = oldIP, oldGlobal
	}()

	conn, probe := dialProbe(t, addr)
	defer conn.Close()

	echo := func(wait time.Duration) bool {
		t.Helper()
		conn.Write(probe)
		conn.SetReadDeadline(time.Now().Add(wait))
		n, _ := conn.Read(make([]byte, prober.PayloadSize))
		return n == prober.PayloadSize
	}

	for i := range 2 {
		if !echo(2 * time.Second) {
			t.Fatalf("probe %d within the per-IP limit must be echoed", i+1)
		}
	}
	if echo(300 * time.Millisecond) {
		t.Fatal("probe beyond the per-IP limit must be dropped")
	}

	// Next fixed-window tick (the limiter window is 1s): budget restored.
	time.Sleep(1200 * time.Millisecond)
	if !echo(2 * time.Second) {
		t.Error("probes must be echoed again after the rate window resets")
	}
}

// TestServer_GlobalRateLimitStarvesExcess: MaxPktsGlobal caps total
// echoed probes across ALL allowed sources — two clients that each stay
// under their own per-IP cap jointly may not exceed the global budget,
// and the excess beyond it is dropped.
func TestServer_GlobalRateLimitStarvesExcess(t *testing.T) {
	prober.InitMetrics()
	oldIP, oldGlobal := prober.MaxPktsPerIP, prober.MaxPktsGlobal
	prober.MaxPktsPerIP, prober.MaxPktsGlobal = 100, 4

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	defer func() {
		cancel()
		<-done // server must have exited before the shared caps are restored
		prober.MaxPktsPerIP, prober.MaxPktsGlobal = oldIP, oldGlobal
	}()

	pc := listenUDP(t, ctx)
	allowed := mustAllow("127.0.0.1,127.0.0.2")
	go func() {
		prober.ServePacketConn(ctx, pc, testSource, allowed, "")
		close(done)
	}()
	addr := pc.LocalAddr().String()

	echoCount := func(conn net.Conn, sends int) int {
		t.Helper()
		probe := make([]byte, prober.PayloadSize)
		copy(probe[0:8], prober.MagicBytes)
		got := 0
		for range sends {
			conn.Write(probe)
			conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			if n, _ := conn.Read(make([]byte, prober.PayloadSize)); n == prober.PayloadSize {
				got++
				continue
			}
			break // budget exhausted; remaining sends would drop too
		}
		return got
	}

	c1 := dialFrom(t, addr, net.IPv4(127, 0, 0, 1))
	defer c1.Close()
	c2 := dialFrom(t, addr, net.IPv4(127, 0, 0, 2))
	defer c2.Close()

	if n := echoCount(c1, 3); n != 3 {
		t.Fatalf("first client under both caps must get 3 echoes, got %d", n)
	}
	// Exactly one slot of the global budget remains for the second client.
	if n := echoCount(c2, 3); n != 1 {
		t.Errorf("second client must get exactly the remaining global budget (1), got %d", n)
	}
}

// TestServer_ReplayWindowEdges: the freshness-window boundary itself —
// timestamp skews just inside the ±30s replay window are live probes and
// must be echoed; skews just outside are capture-replays and must be
// dropped. Guards off-by-one regressions in the skew comparison.
func TestServer_ReplayWindowEdges(t *testing.T) {
	prober.InitMetrics()
	ctx := t.Context()

	const secret = "edge-secret"
	addr := startHMACServer(t, ctx, secret)

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	now := time.Now()
	// Margins ±4s from the 30s boundary: the four subtests share one conn
	// and the negative-read cases each burn a 400ms deadline, so elapsed
	// wall time between timestamp capture and server processing can
	// reach ~1.5s under CI load — 2s margins would erode to flaky.
	cases := []struct {
		name     string
		skew     time.Duration
		wantEcho bool
	}{
		{"stale 26s (inside window) is echoed", -26 * time.Second, true},
		{"future 26s (inside window) is echoed", 26 * time.Second, true},
		{"stale 34s (outside window) is dropped", -34 * time.Second, false},
		{"future 34s (outside window) is dropped", 34 * time.Second, false},
	}
	var seq uint64 = 100
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seq++
			frame := buildHMACFrame(secret, seq, uint64(now.Add(tc.skew).UnixNano()))
			conn.Write(frame)
			conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
			n, _ := conn.Read(make([]byte, 1500))
			if tc.wantEcho && n != prober.PayloadSizeWithHMAC {
				t.Fatalf("frame %v from server clock must be echoed, got %d bytes", tc.skew, n)
			}
			if !tc.wantEcho && n != 0 {
				t.Errorf("replayed frame %v from server clock must be dropped, got %d bytes", tc.skew, n)
			}
		})
	}

	// Hostile non-time values: the uint64→int64 conversion must fail
	// closed (pre-1970 negatives and far-future overflow), pinning the
	// signed-comparison behavior against future refactors.
	hostile := []struct {
		name string
		ts   uint64
	}{
		{"zero timestamp", 0},
		{"max uint64 timestamp", math.MaxUint64},
		{"sign-bit timestamp (year 2262+ overflow)", 1 << 63},
	}
	for _, tc := range hostile {
		t.Run(tc.name+" is dropped", func(t *testing.T) {
			seq++
			frame := buildHMACFrame(secret, seq, tc.ts)
			conn.Write(frame)
			conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			if n, _ := conn.Read(make([]byte, 1500)); n != 0 {
				t.Errorf("hostile ts %#x must be dropped, got %d byte echo", tc.ts, n)
			}
		})
	}
}

// TestServer_UnlistedValidHMACStillDropped: ordering regression guard —
// the allowlist check runs AHEAD of HMAC validation, so even a perfectly
// authenticated frame from a NON-allowlisted source earns neither an echo
// nor a counter increment (untrusted hosts must not buy crypto work or
// metric cardinality).
func TestServer_UnlistedValidHMACStillDropped(t *testing.T) {
	prober.InitMetrics()
	ctx := t.Context()

	const secret = "order-secret"
	pc := listenUDP(t, ctx)
	done := make(chan struct{})
	go func() {
		prober.ServePacketConn(ctx, pc, testSource, testAllow, secret) // allowlist: 127.0.0.1 only
		close(done)
	}()
	t.Cleanup(func() { <-done }) // join before global rate-cap vars are restored
	addr := pc.LocalAddr().String()

	dst, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	unlisted, err := net.DialUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 0}, dst)
	if err != nil {
		t.Fatal(err)
	}
	defer unlisted.Close()

	beforeAllowed := getCounterValue(prober.ServerProbesReceived, "127.0.0.1")
	beforeUnlisted := getCounterValue(prober.ServerProbesReceived, "127.0.0.2")

	unlisted.Write(buildHMACFrame(secret, 7, uint64(time.Now().UnixNano())))
	unlisted.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	if n, _ := unlisted.Read(make([]byte, 1500)); n != 0 {
		t.Error("valid HMAC frame from a non-allowlisted source must not be echoed")
	}
	time.Sleep(200 * time.Millisecond)

	if got := getCounterValue(prober.ServerProbesReceived, "127.0.0.2") - beforeUnlisted; got != 0 {
		t.Errorf("a non-allowlisted source must never appear in the counter, got +%v", got)
	}

	// The responder is still fully operational for allowed sources.
	ok, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer ok.Close()
	ok.Write(buildHMACFrame(secret, 8, uint64(time.Now().UnixNano())))
	ok.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, _ := ok.Read(make([]byte, 1500)); n != prober.PayloadSizeWithHMAC {
		t.Errorf("allowlisted frame must still be echoed after the drop, got %d bytes", n)
	}
	if got := getCounterValue(prober.ServerProbesReceived, "127.0.0.1") - beforeAllowed; got != 1 {
		t.Errorf("only the allowlisted probe must be counted, got +%v", got)
	}
}

// TestServer_MalformedFramesKeepServing: truncated (<24B) and oversized
// (> MaxDatagramSize) datagrams are dropped without disturbing the
// responder — subsequent valid probes still echo.
func TestServer_MalformedFramesKeepServing(t *testing.T) {
	prober.InitMetrics()
	ctx := t.Context()

	addr := startServer(t, ctx)
	conn, probe := dialProbe(t, addr)
	defer conn.Close()

	reply := make([]byte, prober.MaxDatagramSize)

	// Truncated: shorter than any legal probe frame.
	truncated := make([]byte, 10)
	copy(truncated[0:8], prober.MagicBytes)
	conn.Write(truncated)
	conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, _ := conn.Read(reply); n != 0 {
		t.Errorf("truncated datagram must be dropped, got %d bytes", n)
	}

	// Oversized: larger than the server's read buffer.
	oversized := make([]byte, prober.MaxDatagramSize+500)
	copy(oversized[0:8], prober.MagicBytes)
	conn.Write(oversized)
	conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, _ := conn.Read(reply); n != 0 {
		t.Errorf("oversized datagram must be dropped, got %d bytes", n)
	}

	// Neither malformed frame wedged the responder.
	conn.Write(probe)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := conn.Read(reply); err != nil || n != prober.PayloadSize {
		t.Errorf("valid probe must be echoed after malformed frames: n=%d err=%v", n, err)
	}
}

// panicConn is a PacketConn whose ReadFrom panics, used to prove that a
// recovered echo-loop panic surfaces as a returned error instead of a
// clean nil exit.
type panicConn struct {
	net.PacketConn
}

func (panicConn) ReadFrom([]byte) (int, net.Addr, error) { panic("boom") }

// TestServer_PanicReturnsError: ServePacketConn must convert a recovered
// panic into a returned error so callers can treat it as fatal (server
// mode exits non-zero, both mode tears down the client) instead of
// shutting down cleanly while appearing healthy.
func TestServer_PanicReturnsError(t *testing.T) {
	prober.InitMetrics()
	ctx := t.Context()

	pc := listenUDP(t, ctx)
	done := make(chan error, 1)
	go func() {
		done <- prober.ServePacketConn(ctx, panicConn{pc}, testSource, testAllow, "")
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("recovered panic must be returned as an error, got nil")
		}
		if !strings.Contains(err.Error(), "panic") {
			t.Errorf("error should mention the panic, got: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ServePacketConn did not return after panic within 5s")
	}
}

// TestServer_CIDRAllowlist: a CIDR entry admits any source IP inside
// the prefix and drops sources outside it.
func TestServer_CIDRAllowlist(t *testing.T) {
	prober.InitMetrics()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	defer func() {
		cancel()
		<-done
	}()

	pc := listenUDP(t, ctx)
	allowed := mustAllow("127.0.0.2/32")
	go func() {
		prober.ServePacketConn(ctx, pc, testSource, allowed, "")
		close(done)
	}()
	addr := pc.LocalAddr().String()

	in := dialFrom(t, addr, net.IPv4(127, 0, 0, 2))
	defer in.Close()
	if !echoOnce(t, in) {
		t.Error("source inside the allowlist prefix must be echoed")
	}

	out := dialFrom(t, addr, net.IPv4(127, 0, 0, 3))
	defer out.Close()
	if echoOnce(t, out) {
		t.Error("source outside the allowlist prefix must be dropped")
	}
}

// TestServer_ClientSeriesOverflow: prefix-matched clients resolve their
// per-client metric series on demand up to MaxClientSeries; further
// distinct sources are dropped with the client_overflow reason instead
// of growing the label space (H1 cardinality guard).
func TestServer_ClientSeriesOverflow(t *testing.T) {
	prober.InitMetrics()
	old := prober.MaxClientSeries
	prober.MaxClientSeries = 2
	defer func() { prober.MaxClientSeries = old }()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	defer func() {
		cancel()
		<-done
	}()

	pc := listenUDP(t, ctx)
	allowed := mustAllow("127.0.0.0/8")
	go func() {
		prober.ServePacketConn(ctx, pc, testSource, allowed, "")
		close(done)
	}()
	addr := pc.LocalAddr().String()

	var conns []net.Conn
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	for i, ip := range []net.IP{net.IPv4(127, 0, 0, 1), net.IPv4(127, 0, 0, 2), net.IPv4(127, 0, 0, 3)} {
		c := dialFrom(t, addr, ip)
		conns = append(conns, c)
		if i < prober.MaxClientSeries {
			if !echoOnce(t, c) {
				t.Errorf("source %s below cap must be echoed", ip)
			}
		} else {
			if echoOnce(t, c) {
				t.Errorf("source %s beyond cap must be dropped", ip)
			}
		}
	}
	if n := getCounterValue(prober.ServerProbesDropped, "client_overflow"); n < 1 {
		t.Errorf("expected at least 1 client_overflow drop, got %v", n)
	}
}

// TestServer_BoundedPayloadRange: the server echoes the header frame
// plus any bounded payload extension (clients can probe with a payload
// without coordinating server config) but still rejects oversized
// arbitrary-payload reflection attempts.
// pi-lens-ignore: go-test-functions
func TestServer_BoundedPayloadSizeRange(t *testing.T) {
	prober.InitMetrics()
	ctx, cancel := context.WithCancel(context.Background())
	addr, done := startServerDone(t, ctx)
	defer func() {
		cancel()
		<-done
	}()

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Header + payload extension: echoed whole.
	withPayload := make([]byte, prober.PayloadSize+64)
	copy(withPayload[0:8], prober.MagicBytes)
	conn.Write(withPayload)
	conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	if n, _ := conn.Read(make([]byte, 1500)); n != len(withPayload) {
		t.Errorf("header+64-byte frame must be echoed whole, got %d bytes", n)
	}

	// Oversized: dropped as an arbitrary-payload reflector attempt.
	oversized := make([]byte, prober.PayloadSize+prober.MaxPayloadBytes+10)
	copy(oversized[0:8], prober.MagicBytes)
	conn.Write(oversized)
	conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, _ := conn.Read(make([]byte, 1500)); n != 0 {
		t.Errorf("oversized frame must be dropped, got %d bytes", n)
	}
}
