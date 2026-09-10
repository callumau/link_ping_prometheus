package prober

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// Client-side HMAC coverage. Config.EchoSecret appeared in no test, so a
// regression in the 32-byte frame layout, the truncated-tag computation,
// or the payload offset under HMAC (PayloadSizeWithHMAC) would have
// shipped unseen. These tests run a real ServePacketConn with a secret
// and a real client with EchoSecret set.

// hmacCounter reads any counter series by its full label set. The shared
// wbCounter helper assumes the client {source,target,address} shape; the
// server vecs use {source,client} / {source,reason}.
func hmacCounter(vec *prometheus.CounterVec, labels ...string) float64 {
	var m dto.Metric
	if err := vec.WithLabelValues(labels...).Write(&m); err != nil {
		return 0
	}
	return m.GetCounter().GetValue()
}

// hmacEchoServer starts a production ServePacketConn echo responder with
// echoSecret on an ephemeral loopback port, closed when ctx ends. The
// allowlist is fail-closed to 127.0.0.1 so only the local probe client is
// admitted.
func hmacEchoServer(t *testing.T, ctx context.Context, source, secret string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	allowed, err := ParseAllowlist("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		ServePacketConn(ctx, pc, source, allowed, secret)
	}()
	go func() {
		<-ctx.Done()
		pc.Close()
	}()
	t.Cleanup(func() {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("HMAC echo server did not stop after ctx cancel")
		}
	})
	return pc.LocalAddr().String()
}

// runProbeTargetFor drives one target's probe loop for d, then cancels and
// joins it so counters are stable when the caller reads them.
func runProbeTargetFor(t *testing.T, tg Target, cfg Config, d time.Duration) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		probeTarget(ctx, tg, cfg)
		close(done)
	}()
	// pi-lens-ignore: go-time-sleep-test
	time.Sleep(d)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("probe loop did not stop after cancel")
	}
}

// TestClientHMAC_HealthyEcho: a client whose EchoSecret matches the
// server's must send 32-byte authenticated frames the server accepts and
// echoes — RTT samples appear, nothing times out, and the server counts
// the probes. This is the only test that proves the client frame is 32
// bytes with a valid truncated tag.
// pi-lens-ignore: go-test-functions
func TestClientHMAC_HealthyEcho(t *testing.T) {
	InitMetrics()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const src, secret = "test", "hmac-healthy-secret"
	addr := hmacEchoServer(t, ctx, src, secret)

	const name = "hmac_healthy"
	startRecv := hmacCounter(ServerProbesReceived, src, "127.0.0.1")

	cfg := Config{
		Source:       src,
		BaseInterval: 30 * time.Millisecond,
		BaseTimeout:  300 * time.Millisecond,
		EchoSecret:   secret,
	}
	runProbeTargetFor(t, Target{Name: name, Address: addr}, cfg, 600*time.Millisecond)

	if rtt := wbHistCount(src, name, addr); rtt <= 0 {
		t.Fatalf("a valid HMAC handshake must produce RTT samples, got %v", rtt)
	}
	if tout := wbCounter(ProbesTimedOut, src, name, addr); tout != 0 {
		t.Errorf("all authenticated probes must be echoed, got timed_out=%v", tout)
	}
	if got := hmacCounter(ServerProbesReceived, src, "127.0.0.1") - startRecv; got <= 0 {
		t.Errorf("server must count authenticated probes from the client, got %v", got)
	}
}

// TestClientHMAC_WrongSecretRejected: when the client secret differs from
// the server's, every frame fails tag validation. The server must drop
// them (hmac drop reason) and the client must see pure loss — a bad tag
// must never be accepted as a valid echo.
// pi-lens-ignore: go-test-functions
func TestClientHMAC_WrongSecretRejected(t *testing.T) {
	InitMetrics()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const src = "test"
	addr := hmacEchoServer(t, ctx, src, "server-secret")
	startDrops := hmacCounter(ServerProbesDropped, src, "hmac")

	const name = "hmac_wrong_secret"
	cfg := Config{
		Source:       src,
		BaseInterval: 30 * time.Millisecond,
		BaseTimeout:  300 * time.Millisecond,
		EchoSecret:   "different-client-secret",
	}
	runProbeTargetFor(t, Target{Name: name, Address: addr}, cfg, 800*time.Millisecond)

	if rtt := wbHistCount(src, name, addr); rtt != 0 {
		t.Errorf("a bad HMAC tag must never be accepted, got %v RTT samples", rtt)
	}
	if tout := wbCounter(ProbesTimedOut, src, name, addr); tout <= 0 {
		t.Errorf("wrong-secret probes must time out (the server drops them), got %v", tout)
	}
	if got := hmacCounter(ServerProbesDropped, src, "hmac") - startDrops; got <= 0 {
		t.Errorf("the server must record hmac drops for wrong-secret frames, got %v", got)
	}
}

// TestClientHMAC_WithPayload: HMAC and -payload together must still
// round-trip intact. The echoed payload starts at offset
// PayloadSizeWithHMAC (32), not PayloadSize (24); if the reader compared
// from the wrong offset it would flag every valid echo as corrupted and
// observe no RTT. Pins that offset for the first time.
// pi-lens-ignore: go-test-functions
func TestClientHMAC_WithPayload(t *testing.T) {
	InitMetrics()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const src, secret = "test", "hmac-payload-secret"
	addr := hmacEchoServer(t, ctx, src, secret)

	const name = "hmac_payload"
	cfg := Config{
		Source:       src,
		BaseInterval: 30 * time.Millisecond,
		BaseTimeout:  300 * time.Millisecond,
		EchoSecret:   secret,
		Payload:      64,
	}
	runProbeTargetFor(t, Target{Name: name, Address: addr}, cfg, 600*time.Millisecond)

	if rtt := wbHistCount(src, name, addr); rtt <= 0 {
		t.Fatalf("HMAC+payload echoes must produce RTT samples, got %v", rtt)
	}
	if tout := wbCounter(ProbesTimedOut, src, name, addr); tout != 0 {
		t.Errorf("HMAC+payload probes must all be echoed, got timed_out=%v", tout)
	}
	if corrupted := wbCounter(CorruptedProbes, src, name, addr); corrupted != 0 {
		t.Errorf("a valid HMAC+payload echo must not be flagged corrupted (plOff=PayloadSizeWithHMAC), got %v", corrupted)
	}
}
