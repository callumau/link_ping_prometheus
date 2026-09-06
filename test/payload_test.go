package prober_test

import (
	"context"
	"testing"
	"time"

	"link_ping_prometheus/internal/prober"
)

// payloadPattern regenerates the deterministic payload pattern
// independently of the code under test (mirrors the xorshift64* in
// prober.fillPayload) so corruption detection is validated against its
// own spec.
func payloadPattern(buf []byte, seq, ts uint64) {
	x := seq*0x9E3779B97F4A7C15 ^ ts
	for i := range buf {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		buf[i] = byte(x >> 24)
	}
}

// TestPayload_HealthyEcho: with -payload enabled, pattern-filled probes
// echo intact, RTT is observed, corrupted stays 0, and the extended
// balance invariant holds: sent = rtt + timed_out + corrupted + inflight.
// pi-lens-ignore: go-test-functions
func TestPayload_HealthyEcho(t *testing.T) {
	prober.InitMetrics()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Echo-all: the whole datagram (header + pattern payload) returns.
	addr := udpEcho(t, ctx, func(buf []byte, w func([]byte)) { w(buf) })

	const targetName = "payload_ok"
	cfg := cfgWith(true, 50*time.Millisecond, time.Second, prober.Target{Name: targetName, Address: addr})
	cfg.Source = testSource
	cfg.Payload = 64

	done := make(chan struct{})
	go func() {
		defer close(done)
		// pi-lens-ignore: go-context-background-handler
		_ = prober.RunClient(ctx, cfg)
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("RunClient did not stop after cancel")
		}
	}()

	deadline := time.Now().Add(3 * time.Second)
	var rttCount float64
	for time.Now().Before(deadline) {
		rttCount = getHistogramCount(prober.RTTSeconds, targetName, addr)
		if rttCount >= 5 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if rttCount < 5 {
		t.Fatalf("expected >=5 RTT samples with payload probes, got %v", rttCount)
	}
	if n := getCounterValue(prober.CorruptedProbes, targetName, addr); n != 0 {
		t.Errorf("intact echoes must not count as corrupted, got %v", n)
	}
	sent := getCounterValue(prober.ProbesSent, targetName, addr)
	timedOut := getCounterValue(prober.ProbesTimedOut, targetName, addr)
	corrupted := getCounterValue(prober.CorruptedProbes, targetName, addr)
	residual := sent - rttCount - timedOut - corrupted
	if residual < 0 || residual > 5 {
		t.Errorf("balance with payload mode: sent %v = rtt %v + timeout %v + corrupted %v leaves residual %v (allowed 0..5 abandoned at cancel)", sent, rttCount, timedOut, corrupted, residual)
	}
}

// TestPayload_CorruptionCountedSeparately: a response whose payload
// bytes were altered in flight counts in link_probes_corrupted_total —
// NOT in RTT and NOT as loss — while the link stays up (the round trip
// demonstrably completed).
// pi-lens-ignore: go-test-functions
func TestPayload_CorruptionCountedSeparately(t *testing.T) {
	prober.InitMetrics()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Echo server that flips one payload byte on every frame it can
	// corrupt: every echo comes back corrupted in this test.
	addr := udpEcho(t, ctx, func(buf []byte, w func([]byte)) {
		if len(buf) > 32 {
			buf[30] ^= 0xFF
		}
		w(buf)
	})

	const targetName = "payload_corrupt"
	cfg := cfgWith(true, 50*time.Millisecond, time.Second)
	cfg.Source = testSource
	cfg.Targets = []prober.Target{{Name: targetName, Address: addr}}
	cfg.Payload = 64

	startRTT := getHistogramCount(prober.RTTSeconds, targetName, addr)
	startCorrupted := getCounterValue(prober.CorruptedProbes, targetName, addr)

	done := make(chan struct{})
	go func() {
		defer close(done)
		// pi-lens-ignore: go-context-background-handler
		_ = prober.RunClient(ctx, cfg)
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("RunClient did not stop after cancel")
		}
	}()

	deadline := time.Now().Add(3 * time.Second)
	var corrupted float64
	for time.Now().Before(deadline) {
		corrupted = getCounterValue(prober.CorruptedProbes, targetName, addr) - startCorrupted
		if corrupted >= 5 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if corrupted < 5 {
		t.Fatalf("expected >=5 corrupted echoes, got %v", corrupted)
	}

	rtt := getHistogramCount(prober.RTTSeconds, targetName, addr) - startRTT
	if rtt != 0 {
		t.Errorf("corrupted echoes must not be observed as RTT samples, got %v", rtt)
	}
	if up := getGaugeValue(prober.LinkUp, targetName, addr); up != 1 {
		t.Errorf("a completing-but-corrupted round trip must keep link_up=1, got %v", up)
	}
}
