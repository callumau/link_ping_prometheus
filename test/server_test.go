package prober_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

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

// erroringConn embeds a real PacketConn but fails every ReadFrom with a
// non-ICMP error: the "this socket is genuinely broken" case, as opposed to
// the ICMP-derived unreachability the loop classifies out. counts the calls
// so the test can prove the loop backs off instead of spinning.
type erroringConn struct {
	net.PacketConn
	reads atomic.Int64
}

func (c *erroringConn) ReadFrom([]byte) (int, net.Addr, error) {
	c.reads.Add(1)
	return 0, nil, errors.New("injected read failure")
}

// TestServer_ReadErrorsAreBoundedNotFatal: an unexpected read error must not
// spin the echo loop at Debug level (invisible at default verbosity, and a
// pegged core on a latency-measuring box), and must NOT kill the responder
// either — a spoofed source inside the allowlist, or a peer that vanishes,
// must never be able to take the echo server down. The loop therefore retries
// on an Error-logged backoff.
func TestServer_ReadErrorsAreBoundedNotFatal(t *testing.T) {
	prober.InitMetrics()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pc := &erroringConn{PacketConn: listenUDP(t, ctx)}
	done := make(chan error, 1)
	go func() { done <- prober.ServePacketConn(ctx, pc, testSource, testAllow, "") }()

	// Without a backoff this would be millions of iterations; with one it is
	// ~10 fast failures followed by ~3 per 100ms window.
	time.Sleep(350 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("read errors must not kill the responder, got: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ServePacketConn did not return after cancel")
	}

	if n := pc.reads.Load(); n > 100 {
		t.Errorf("the read-error path must back off, not spin: %d ReadFrom calls in 350ms", n)
	} else if n < 10 {
		t.Errorf("the loop must keep retrying after read errors, got only %d calls", n)
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

// TestServer_UnauthenticatedSourceCannotSpendSeriesSlot: dynamic
// {source,client} series allocation (resolve) must happen only AFTER a frame
// authenticates. Resolving first let any off-path attacker able to spoof a
// source inside an allowlisted CIDR allocate a series pair per source and pin
// every MaxClientSeries slot, so a real CIDR client was dropped as
// client_overflow — manufactured 100% loss with only a cardinality drop
// counter to explain it. Pins both halves: no series for the unauthenticated
// source, and the single slot still free for an authenticated one.
//
// Uses loopback aliases nothing else in the suite touches so the
// non-mutating Gather() assertion cannot be satisfied by an earlier test's
// series (metrics are process-global and never reset).
func TestServer_UnauthenticatedSourceCannotSpendSeriesSlot(t *testing.T) {
	prober.InitMetrics()
	old := prober.MaxClientSeries
	prober.MaxClientSeries = 1
	defer func() { prober.MaxClientSeries = old }()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	// Restore MaxClientSeries only after the server has returned: it reads
	// the var from its own goroutine (race detector).
	defer func() {
		cancel()
		<-done
	}()

	const secret = "resolve-after-auth"
	pc := listenUDP(t, ctx)
	allowed := mustAllow("127.0.0.0/8") // CIDR entry -> the dynamic resolve path
	go func() {
		prober.ServePacketConn(ctx, pc, testSource, allowed, secret)
		close(done)
	}()
	addr := pc.LocalAddr().String()

	// Correct size, magic and fresh timestamp — only the tag is wrong, so the
	// frame reaches the authentication step and nothing else.
	bad := dialFrom(t, addr, net.IPv4(127, 0, 0, 9))
	defer bad.Close()
	frame := buildHMACFrame(secret, 1, uint64(time.Now().UnixNano()))
	frame[31] ^= 0xFF
	bad.Write(frame)

	// Wait for proof the server processed it: the hmac drop counter only
	// moves once the frame reached authentication.
	before := getCounterValue(prober.ServerProbesDropped, "hmac")
	deadline := time.Now().Add(2 * time.Second)
	for getCounterValue(prober.ServerProbesDropped, "hmac") == before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if getCounterValue(prober.ServerProbesDropped, "hmac") == before {
		t.Fatal("the unauthenticated frame was never processed (cpu load?)")
	}
	if serverSeriesExists(t, "link_server_probes_received_total", map[string]string{"source": testSource, "client": "127.0.0.9"}) {
		t.Error("an unauthenticated source must not create a {source,client} series")
	}

	// The one available slot must still serve a correctly authenticated
	// client; with resolve-before-auth this frame is client_overflow and the
	// read below times out.
	good := dialFrom(t, addr, net.IPv4(127, 0, 0, 8))
	defer good.Close()
	good.Write(buildHMACFrame(secret, 2, uint64(time.Now().UnixNano())))
	good.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, _ := good.Read(make([]byte, 1500)); n != prober.PayloadSizeWithHMAC {
		t.Errorf("an authenticated client must get the free slot, got %d bytes back (client_overflow?)", n)
	}
}

// TestAllowlist_IPv4Mapped: allowlist entries written in 4-in-6 form
// (::ffff:127.0.0.1, ::ffff:127.0.0.0/104) must match the dotted-quad
// source a UDP datagram actually reports. netip does not unmap addresses
// or prefixes on its own, so without the ParseAllowlist normalisation a
// 4-in-6 entry silently admitted nothing. Table-driven per AGENTS.md's
// rule that security controls get good/bad-frame coverage.
func TestAllowlist_IPv4Mapped(t *testing.T) {
	cases := []struct {
		name      string
		entry     string
		norm      string
		wantAllow bool
	}{
		{"mapped exact admits canonical v4 source", "::ffff:127.0.0.1", "127.0.0.1", true},
		{"mapped exact rejects a different v4 source", "::ffff:127.0.0.1", "127.0.0.2", false},
		{"mapped /104 prefix admits an inside source", "::ffff:127.0.0.0/104", "127.0.0.1", true},
		{"mapped /104 prefix rejects an outside source", "::ffff:127.0.0.0/104", "10.0.0.1", false},
		{"plain v4 exact still admits its source", "127.0.0.1", "127.0.0.1", true},
		{"plain v4 exact still rejects other sources", "127.0.0.1", "127.0.0.2", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			al := mustAllow(tc.entry)
			ip := netip.MustParseAddr(tc.norm)
			if got := al.Contains(ip); got != tc.wantAllow {
				t.Errorf("Contains(%s) with entry %q = %v, want %v", ip, tc.entry, got, tc.wantAllow)
			}
		})
	}

	// End-to-end: a server armed with a 4-in-6 exact entry must echo a real
	// client whose datagram source canonicalises to 127.0.0.1 — the case
	// that silently admitted nothing before the Unmap fix.
	prober.InitMetrics()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	defer func() {
		cancel()
		<-done
	}()
	pc := listenUDP(t, ctx)
	allowed := mustAllow("::ffff:127.0.0.1")
	go func() {
		prober.ServePacketConn(ctx, pc, testSource, allowed, "")
		close(done)
	}()

	conn, probe := dialProbe(t, pc.LocalAddr().String())
	defer conn.Close()
	conn.Write(probe)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := conn.Read(make([]byte, prober.PayloadSize)); err != nil || n != prober.PayloadSize {
		t.Fatalf("client on 127.0.0.1 must be echoed by a ::ffff:127.0.0.1 allowlist: n=%d err=%v", n, err)
	}
}

// TestServer_RateLimit_JunkDoesNotSpendPerIPBudget (R3 case A): with HMAC
// enabled, forged frames that fail authentication must NOT consume the
// source's per-IP budget. The per-IP charge runs only after a frame
// authenticates, so a flood of spoofed junk (correct size+magic, bad tag)
// cannot push a real client's valid probe over MaxPktsPerIP and fake 100%
// loss for that client. Before the fix the forged frames spent the cap and
// the valid probe was dropped as rate_ip.
func TestServer_RateLimit_JunkDoesNotSpendPerIPBudget(t *testing.T) {
	prober.InitMetrics()
	oldIP, oldGlobal := prober.MaxPktsPerIP, prober.MaxPktsGlobal
	prober.MaxPktsPerIP = 1 // a single authenticated frame exhausts the budget

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	defer func() {
		cancel()
		<-done // join before restoring the shared cap vars
		prober.MaxPktsPerIP, prober.MaxPktsGlobal = oldIP, oldGlobal
	}()

	const secret = "rate-order-secret"
	pc := listenUDP(t, ctx)
	allowed := mustAllow("127.0.0.1")
	go func() {
		prober.ServePacketConn(ctx, pc, testSource, allowed, secret)
		close(done)
	}()
	addr := pc.LocalAddr().String()

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	beforeHMAC := getCounterValue(prober.ServerProbesDropped, "hmac")
	beforeIP := getCounterValue(prober.ServerProbesDropped, "rate_ip")

	now := uint64(time.Now().UnixNano())
	// Five correctly-sized, correctly-magicked frames with a wrong tag: all
	// reach the HMAC gate and are rejected there, never authenticating.
	for i := range 5 {
		conn.Write(buildHMACFrame("wrong-secret", uint64(i+1), now))
	}

	// The one legitimately authenticated probe must still be echoed: it is
	// the first frame to spend this source's per-IP budget. Reading its echo
	// is also the sync point proving the server processed the forged frames.
	conn.Write(buildHMACFrame(secret, 100, uint64(time.Now().UnixNano())))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ := conn.Read(make([]byte, 1500))
	if n != prober.PayloadSizeWithHMAC {
		t.Fatalf("valid probe must be echoed after forged frames, got %d bytes", n)
	}

	if got := getCounterValue(prober.ServerProbesDropped, "hmac") - beforeHMAC; got != 5 {
		t.Errorf("all 5 forged frames must be dropped as hmac, got +%v", got)
	}
	if got := getCounterValue(prober.ServerProbesDropped, "rate_ip") - beforeIP; got != 0 {
		t.Errorf("forged junk must not spend the per-IP budget (rate_ip must stay flat), got +%v", got)
	}
}

// TestServer_RateLimit_GlobalChargeBoundsCrypto (R3 case B): the global
// budget is charged BEFORE validation, so a forged-frame flood is bounded
// before any HMAC-SHA256 work and a following authenticated probe is also
// dropped once the global cap is exhausted — an untrusted source cannot buy
// crypto CPU per packet. Before the fix the global charge ran after
// validation, so forged frames were only counted after they had already
// cost the server a hash (and the valid probe would sail through).
func TestServer_RateLimit_GlobalChargeBoundsCrypto(t *testing.T) {
	prober.InitMetrics()
	oldIP, oldGlobal := prober.MaxPktsPerIP, prober.MaxPktsGlobal
	prober.MaxPktsGlobal = 3

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	defer func() {
		cancel()
		<-done // join before restoring the shared cap vars
		prober.MaxPktsPerIP, prober.MaxPktsGlobal = oldIP, oldGlobal
	}()

	const secret = "rate-order-secret"
	pc := listenUDP(t, ctx)
	allowed := mustAllow("127.0.0.1")
	go func() {
		prober.ServePacketConn(ctx, pc, testSource, allowed, secret)
		close(done)
	}()
	addr := pc.LocalAddr().String()

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	beforeGlobal := getCounterValue(prober.ServerProbesDropped, "rate_global")

	now := uint64(time.Now().UnixNano())
	// More forged frames than the global cap, all written back-to-back. The
	// limiter's 1s window is anchored at the first frame, so the whole test
	// fits inside one window.
	for i := range 5 {
		conn.Write(buildHMACFrame("wrong-secret", uint64(i+1), now))
	}
	// Authenticated, freshly timestamped, allowlisted — dropped solely
	// because the global budget was spent before validation ran.
	conn.Write(buildHMACFrame(secret, 100, uint64(time.Now().UnixNano())))

	conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	if n, _ := conn.Read(make([]byte, 1500)); n != 0 {
		t.Fatalf("probe beyond the global cap must be dropped, got %d bytes", n)
	}
	if got := getCounterValue(prober.ServerProbesDropped, "rate_global") - beforeGlobal; got < 1 {
		t.Errorf("frames beyond MaxPktsGlobal must be charged as rate_global before validation, got +%v", got)
	}
}

// TestServer_PerTargetIntervalOverride: a target's per-target Interval must
// drive its own probe schedule instead of the global BaseInterval (the
// override plumbing; 0 means inherit). Two targets share one echo server
// with a global BaseInterval of 1s, so only the 50ms/200ms overrides can
// produce a large sent-count gap. The ratio is 4 in a quiet run; asserting
// >= 1.5 leaves room for scheduler jitter under load while still failing if
// the override were ignored (ratio would be 1.0).
// pi-lens-ignore: go-test-functions
func TestServer_PerTargetIntervalOverride(t *testing.T) {
	prober.InitMetrics()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr := startEchoServer(ctx, t)
	cfg := cfgWith(false, time.Second, time.Second,
		prober.Target{Name: "fast", Address: addr, Interval: 50 * time.Millisecond},
		prober.Target{Name: "slow", Address: addr, Interval: 200 * time.Millisecond},
	)

	runClientFor(ctx, cfg, 2*time.Second)
	cancel()
	time.Sleep(100 * time.Millisecond)

	fast := getCounterValue(prober.ProbesSent, "fast", addr)
	slow := getCounterValue(prober.ProbesSent, "slow", addr)
	// Vacuous-pass guard: both loops must actually have probed.
	if fast <= 3 || slow <= 3 {
		t.Fatalf("both targets must have probed: fast=%v slow=%v (cpu load?)", fast, slow)
	}
	if fast < 1.5*slow {
		t.Errorf("per-target interval override not applied: fast sent %v, slow sent %v (want fast >= 1.5*slow)", fast, slow)
	}
}

// serverSeriesExists reports whether a metric family currently has a series
// whose label set EQUALS labels. reload_test.go's metricSeriesExists matches
// only the 3-label client shape {source,target,address} and compares label
// cardinality, so it can never match a 2-label server family like
// link_server_probes_received_total{source,client} — it would return false
// vacuously. This helper takes an explicit label map instead. Like that
// helper it uses Gather(), not WithLabelValues, which would re-create a
// deleted series at zero and make a "was it deleted?" assertion impossible
// to fail.
func serverSeriesExists(t *testing.T, family string, labels map[string]string) bool {
	t.Helper()
	fams, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, f := range fams {
		if f.GetName() != family {
			continue
		}
		for _, m := range f.GetMetric() {
			if len(m.GetLabel()) != len(labels) {
				continue
			}
			match := true
			for _, lp := range m.GetLabel() {
				if labels[lp.GetName()] != lp.GetValue() {
					match = false
					break
				}
			}
			if match {
				return true
			}
		}
	}
	return false
}

// TestServer_DynamicClientEviction (R2): under MaxClientSeries pressure the
// server sweeps clients idle for DynClientTTL, freeing a slot AND deleting
// the evicted client's metric series. This pins both halves of the fix:
//   - blackout lift: a source dropped with client_overflow while all slots
//     were held by fresh clients is admitted again once those clients age out;
//   - lifetime cardinality: the evicted client's series is DELETED, not left
//     registered forever at its last value (a vec keeps a series per label set
//     for the life of the process).
func TestServer_DynamicClientEviction(t *testing.T) {
	prober.InitMetrics()
	oldCap, oldTTL := prober.MaxClientSeries, prober.DynClientTTL
	// 500ms rather than a tight 100ms: the blackout phase only needs the three
	// probes to land within the TTL (microseconds on loopback), while a long TTL
	// keeps the post-sleep eviction assertion robust against scheduler stalls.
	prober.MaxClientSeries, prober.DynClientTTL = 2, 500*time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	defer func() {
		cancel()
		<-done // join before restoring the shared vars
		prober.MaxClientSeries, prober.DynClientTTL = oldCap, oldTTL
	}()

	pc := listenUDP(t, ctx)
	allowed := mustAllow("127.0.0.0/8") // CIDR entry -> clients take the dynamic path
	go func() {
		prober.ServePacketConn(ctx, pc, testSource, allowed, "")
		close(done)
	}()
	addr := pc.LocalAddr().String()

	// Dial all three first so the window between the last admitted probe and
	// the overflow probe stays far below DynClientTTL.
	c2 := dialFrom(t, addr, net.IPv4(127, 0, 0, 2))
	defer c2.Close()
	c3 := dialFrom(t, addr, net.IPv4(127, 0, 0, 3))
	defer c3.Close()
	c4 := dialFrom(t, addr, net.IPv4(127, 0, 0, 4))
	defer c4.Close()

	// Two clients fill the MaxClientSeries=2 dynamic slots.
	if !echoOnce(t, c2) {
		t.Fatal("first CIDR client (127.0.0.2) must be echoed")
	}
	if !echoOnce(t, c3) {
		t.Fatal("second CIDR client (127.0.0.3) must be echoed")
	}
	if !serverSeriesExists(t, "link_server_probes_received_total", map[string]string{"source": testSource, "client": "127.0.0.2"}) {
		t.Fatal("admitted dynamic client 127.0.0.2 must have a metric series")
	}

	// A third distinct source with all slots held by fresh clients: blacked
	// out with client_overflow rather than admitted.
	beforeOverflow := getCounterValue(prober.ServerProbesDropped, "client_overflow")
	if echoOnce(t, c4) {
		t.Fatal("source beyond MaxClientSeries with no idle slot must be dropped")
	}
	if got := getCounterValue(prober.ServerProbesDropped, "client_overflow") - beforeOverflow; got < 1 {
		t.Errorf("expected a client_overflow drop, got +%v", got)
	}

	// Past DynClientTTL the sweep frees the stale slot, so the source that
	// was just blacked out is admitted again (the R2 blackout-lift fix).
	time.Sleep(800 * time.Millisecond)
	if !echoOnce(t, c4) {
		t.Fatal("source must be echoed once DynClientTTL frees a slot")
	}
	if got := getCounterValue(prober.ServerProbesReceived, "127.0.0.4"); got < 1 {
		t.Errorf("evicted-then-admitted client must be counted, got %v", got)
	}

	// The sweep must also DELETE the evicted client's series: the vec keeps a
	// series per label set for the process lifetime, so dropping only the map
	// entry would leave lifetime cardinality growing unbounded. The control
	// assertion above (series present while admitted) proves this is not vacuous.
	if serverSeriesExists(t, "link_server_probes_received_total", map[string]string{"source": testSource, "client": "127.0.0.2"}) {
		t.Error("evicted client's link_server_probes_received_total series is still registered — series deletion is broken")
	}
}

// TestServer_DynamicClientSeriesExpiresBelowCap (B1): the idle sweep must
// also run below MaxClientSeries pressure. It used to run only when the
// dynamic map was full, so a prefix-matched client that probed once and
// went away kept exporting its series forever — link_server_clock_skew
// stayed frozen at its last value and its alert could never resolve.
// The sweep is time-gated to once per second, so the second client's probe
// (after both DynClientTTL and the gate have elapsed) is what triggers it.
func TestServer_DynamicClientSeriesExpiresBelowCap(t *testing.T) {
	prober.InitMetrics()
	oldTTL := prober.DynClientTTL
	// 200ms: far below the 1s sweep gate, so the eviction assertion can only
	// pass if a resolve below the cap actually sweeps.
	prober.DynClientTTL = 200 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	defer func() {
		cancel()
		<-done // join before restoring the shared var
		prober.DynClientTTL = oldTTL
	}()

	pc := listenUDP(t, ctx)
	allowed := mustAllow("127.0.0.0/8") // CIDR entry -> clients take the dynamic path
	go func() {
		prober.ServePacketConn(ctx, pc, testSource, allowed, "")
		close(done)
	}()
	addr := pc.LocalAddr().String()

	c2 := dialFrom(t, addr, net.IPv4(127, 0, 0, 2))
	defer c2.Close()
	if !echoOnce(t, c2) {
		t.Fatal("first CIDR client must be echoed")
	}
	// Both per-client families must exist while admitted — the control that
	// makes the deletion assertion below non-vacuous.
	for _, family := range []string{"link_server_probes_received_total", "link_server_clock_skew_seconds"} {
		if !serverSeriesExists(t, family, map[string]string{"source": testSource, "client": "127.0.0.2"}) {
			t.Fatalf("%s series must exist for the admitted dynamic client", family)
		}
	}

	// Wait past BOTH DynClientTTL and the once-per-second sweep gate, with
	// no MaxClientSeries pressure (cap is the default 1024): exactly the
	// state the cap-only sweep missed.
	time.Sleep(1200 * time.Millisecond)

	c3 := dialFrom(t, addr, net.IPv4(127, 0, 0, 3))
	defer c3.Close()
	if !echoOnce(t, c3) {
		t.Fatal("a second CIDR client must be echoed below the cap")
	}

	// c3's echo proves its resolve() ran, so the sweep had its chance.
	for _, family := range []string{"link_server_probes_received_total", "link_server_clock_skew_seconds"} {
		if serverSeriesExists(t, family, map[string]string{"source": testSource, "client": "127.0.0.2"}) {
			t.Errorf("%s series must be deleted once the client is idle past DynClientTTL, even below MaxClientSeries", family)
		}
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

// writeFailConn reads real datagrams but fails every WriteTo: the "server
// received a valid probe but could not echo it" case. It must be counted in
// link_server_echo_errors_total, because the client counts the missing echo as
// LOSS — without this counter an operator subtracts nothing and blames the
// network for a local socket fault.
type writeFailConn struct {
	net.PacketConn
	writes atomic.Int64
}

func (c *writeFailConn) WriteTo([]byte, net.Addr) (int, error) {
	c.writes.Add(1)
	return 0, errors.New("injected write failure")
}

// TestServer_EchoWriteErrorsCounted pins both halves of that contract: the
// probe is still counted as RECEIVED (it did arrive) and the failed echo is
// counted separately, with nothing delivered back.
func TestServer_EchoWriteErrorsCounted(t *testing.T) {
	prober.InitMetrics()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pc := &writeFailConn{PacketConn: listenUDP(t, ctx)}
	done := make(chan error, 1)
	go func() { done <- prober.ServePacketConn(ctx, pc, testSource, testAllow, "") }()

	conn, probe := dialProbe(t, pc.LocalAddr().String())
	defer conn.Close()

	before := getCounterValue(prober.ServerEchoErrors)
	conn.Write(probe)
	conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	if n, _ := conn.Read(make([]byte, 1500)); n != 0 {
		t.Errorf("a failed echo must not deliver bytes back, got %d", n)
	}

	deadline := time.Now().Add(2 * time.Second)
	for getCounterValue(prober.ServerEchoErrors) == before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := getCounterValue(prober.ServerEchoErrors) - before; got < 1 {
		t.Errorf("a probe the server could not echo must be counted in link_server_echo_errors_total, got %v", got)
	}
	if pc.writes.Load() < 1 {
		t.Error("the server never attempted the echo write")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("ServePacketConn returned %v, want nil on cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ServePacketConn did not return after cancel")
	}
}

// TestServer_ExactClientSeriesNeverEvicted: exact-allowlist handles are
// pre-resolved and must never be swept. Deleting a live client's series resets
// its counters, which a Prometheus rate() reads as a restart, so the TTL
// sweeper must only ever touch the dynamic (CIDR) map. Uses a lowered
// DynClientTTL and waits past a whole dynSweepInterval (1s) so a regression
// that walked the exact map would have evicted the series by then.
func TestServer_ExactClientSeriesNeverEvicted(t *testing.T) {
	prober.InitMetrics()
	oldTTL := prober.DynClientTTL
	prober.DynClientTTL = 50 * time.Millisecond
	defer func() { prober.DynClientTTL = oldTTL }()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	// Join the server BEFORE restoring the var above (defer order).
	defer func() {
		cancel()
		<-done
	}()

	pc := listenUDP(t, ctx)
	allowed := mustAllow("127.0.0.1") // exact entry -> pre-resolved handle
	go func() {
		prober.ServePacketConn(ctx, pc, testSource, allowed, "")
		close(done)
	}()

	conn, probe := dialProbe(t, pc.LocalAddr().String())
	defer conn.Close()

	conn.Write(probe)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, _ := conn.Read(make([]byte, 1500)); n != prober.PayloadSize {
		t.Fatal("exact-allowlist client must be echoed")
	}
	before := getCounterValue(prober.ServerProbesReceived, "127.0.0.1")

	// Past the lowered TTL and past a full sweeper tick.
	time.Sleep(1300 * time.Millisecond)

	// Non-mutating check FIRST: reading through WithLabelValues would re-create
	// a series the sweeper had evicted, making the regression invisible.
	if !serverSeriesExists(t, "link_server_probes_received_total",
		map[string]string{"source": testSource, "client": "127.0.0.1"}) {
		t.Error("an exact-IP client's series must never be evicted by the TTL sweeper")
	}

	// The counter must CONTINUE from where it was, not restart: a reset would
	// show up as 1 (or as the series having been re-created at 0 by the read
	// above). Metrics are process-global, so `before` counts every earlier test
	// that probed 127.0.0.1 too.
	conn.Write(probe)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, _ := conn.Read(make([]byte, 1500)); n != prober.PayloadSize {
		t.Fatal("exact-allowlist client must still be echoed after the TTL")
	}
	if got := getCounterValue(prober.ServerProbesReceived, "127.0.0.1"); got < before+1 {
		t.Errorf("exact-IP counters must not reset: got %v, want >= %v (evicted and re-created?)", got, before+1)
	}
}

// TestServer_HMACSizeWindowAndDropReasons: under HMAC the accepted frame window
// is measured from PayloadSizeWithHMAC (32), not PayloadSize (24) — otherwise
// -payload probes to an authenticated server would be blackholed — and one
// byte past the payload cap is dropped. Every drop reason is named in
// link_server_probes_dropped_total's Help, the README and the shipped alert,
// so the counters themselves are pinned here: a mislabelled drop is what turns
// "secret/NTP misconfig" into "the network is broken".
func TestServer_HMACSizeWindowAndDropReasons(t *testing.T) {
	prober.InitMetrics()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const secret = "size-window-secret"
	pc := listenUDP(t, ctx)
	allowed := mustAllow("127.0.0.1")
	done := make(chan struct{})
	go func() {
		prober.ServePacketConn(ctx, pc, testSource, allowed, secret)
		close(done)
	}()
	t.Cleanup(func() { <-done })
	addr := pc.LocalAddr().String()

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	now := func() uint64 { return uint64(time.Now().UnixNano()) }

	// send writes one frame, waits up to 400ms for an echo, and reports the
	// echo size (0 when nothing came back).
	send := func(frame []byte) int {
		t.Helper()
		conn.Write(frame)
		conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
		n, _ := conn.Read(make([]byte, 2000))
		return n
	}
	// expectDrop asserts the reason counter grows by one for that frame. The
	// baseline is read BEFORE the write: reading it afterwards races the
	// server's read loop and makes the wait vacuous.
	expectDrop := func(reason string, frame []byte) {
		t.Helper()
		before := getCounterValue(prober.ServerProbesDropped, reason)
		if n := send(frame); n != 0 {
			t.Errorf("%s frame must not be echoed, got %d bytes back", reason, n)
		}
		deadline := time.Now().Add(2 * time.Second)
		for getCounterValue(prober.ServerProbesDropped, reason) < before+1 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		if got := getCounterValue(prober.ServerProbesDropped, reason); got < before+1 {
			t.Errorf("expected a %q drop, counter stayed at %v", reason, got-before)
		}
	}

	// Bounded header+payload frame: accepted, and echoed at its full size.
	const payload = 64
	withPayload := append(buildHMACFrame(secret, 1, now()), make([]byte, payload)...)
	if n := send(withPayload); n != prober.PayloadSizeWithHMAC+payload {
		t.Errorf("a header+payload frame at an HMAC server must be echoed: got %d bytes, want %d", n, prober.PayloadSizeWithHMAC+payload)
	}

	// One byte over the payload cap.
	expectDrop("size", append(buildHMACFrame(secret, 2, now()), make([]byte, prober.MaxPayloadBytes+1)...))
	// Shorter than the HMAC header: a size drop, never read as a 24-byte frame.
	expectDrop("size", make([]byte, prober.PayloadSize))

	// Wrong magic.
	badMagic := buildHMACFrame(secret, 3, now())
	badMagic[0] ^= 0xFF
	expectDrop("magic", badMagic)

	// Bad tag.
	badTag := buildHMACFrame(secret, 4, now())
	badTag[31] ^= 0xFF
	expectDrop("hmac", badTag)
}
