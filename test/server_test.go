package prober_test

import (
	"context"
	"net"
	"testing"
	"time"

	"link_ping_prometheus/internal/prober"
)

// testAllow is the fail-closed client allowlist used by server tests:
// all dial from the loopback IP, so it is the sole permitted prober.
var testAllow = map[string]struct{}{net.IPv4(127, 0, 0, 1).String(): {}}

// startServer starts ServePacketConn on an ephemeral loopback port with
// the standard test allowlist, returning the port address. The socket is
// closed on ctx cancel.
func startServer(t *testing.T, ctx context.Context) string {
	t.Helper()
	pc := listenUDP(t, ctx)
	go prober.ServePacketConn(ctx, pc, testSource, testAllow)
	return pc.LocalAddr().String()
}

// startServerDone is startServer with a channel that is closed when
// ServePacketConn returns, for tests that assert shutdown behavior.
func startServerDone(t *testing.T, ctx context.Context) (string, <-chan struct{}) {
	t.Helper()
	pc := listenUDP(t, ctx)
	done := make(chan struct{})
	go func() {
		prober.ServePacketConn(ctx, pc, testSource, testAllow)
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
	if endRecv > startRecv {
		t.Errorf("Garbage data counted as valid response? %v -> %v", startRecv, endRecv)
	}
}

func TestServer_EnforceSizeAndHeader(t *testing.T) {
	prober.InitMetrics()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr := startServer(t, ctx)

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	reply := make([]byte, 24)

	// 34-byte datagram with a valid magic prefix is not a probe: no echo.
	oversized := make([]byte, 34)
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
	for i := 0; i < 3; i++ {
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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
		done <- prober.ServePacketConn(ctx, pc, testSource, testAllow)
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := prober.RunServer(ctx, "127.0.0.1:0", testSource, nil); err == nil {
		t.Error("RunServer with empty allowlist must fail closed")
	}
}
