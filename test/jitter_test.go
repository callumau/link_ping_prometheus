package prober_test

import (
	"context"
	"math"
	"sync/atomic"
	"testing"
	"time"

	"tcp_ping_prometheus/internal/prober"
)

// TestJitterGauge_ConstantRTTStaysZero: on a link with constant RTT the
// consecutive-sample deltas are ~0, so the RFC 3550 estimate must stay
// near zero — a negative control for the jitter gauge.
func TestJitterGauge_ConstantRTTStaysZero(t *testing.T) {
	prober.InitMetrics()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := udpEcho(t, ctx, echoAll)

	cfg := cfgWith(false, 100*time.Millisecond, 500*time.Millisecond, prober.Target{Name: "jitter_const", Address: addr})
	go prober.RunClient(ctx, cfg)
	time.Sleep(1500 * time.Millisecond)
	cancel()

	j := getGaugeValue(prober.JitterSeconds, "jitter_const", addr)
	if j > 0.001 {
		t.Errorf("constant-RTT jitter should be ~0, got %v s", j)
	}
}

// TestJitterGauge_ConvergesAndResetsOnGap: with RTT alternating between
// ~0ms and ~40ms, the RFC 3550 estimate converges toward 40ms. After a
// single dropped echo (one probe times out), the estimate must reset to
// 0 and rebuild slowly — the post-outage recovery must not spike.
func TestJitterGauge_ConvergesAndResetsOnGap(t *testing.T) {
	prober.InitMetrics()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Serial handler: every received probe sleeps 40ms (even count) or
	// 0ms (odd count) before echoing. When dropNow is set, exactly one
	// probe is dropped to create the sequence-number gap.
	var count atomic.Int64
	var dropNow atomic.Bool
	addr := udpEcho(t, ctx, func(buf []byte, w func([]byte)) {
		if len(buf) != prober.PayloadSize || string(buf[0:8]) != prober.MagicBytes {
			return
		}
		n := count.Add(1)
		if dropNow.Load() && n%2 == 0 {
			return
		}
		if n%2 == 0 {
			time.Sleep(40 * time.Millisecond)
		}
		w(buf)
	})

	cfg := cfgWith(false, 100*time.Millisecond, 200*time.Millisecond, prober.Target{Name: "jitter_var", Address: addr})
	go prober.RunClient(ctx, cfg)

	// Phase 1: converged estimate tracks the ~40ms RTT swing.
	time.Sleep(1500 * time.Millisecond)
	j := getGaugeValue(prober.JitterSeconds, "jitter_var", addr)
	if j < 0.015 || j > 0.05 {
		t.Errorf("jitter on 40ms-swing link should be ~0.04 s, got %v", j)
	}

	// Phase 2: drop one probe, then wait for it to time out and for the
	// next echo to land — the first sample after the gap resets J to 0.
	dropNow.Store(true)
	deadline := time.Now().Add(5 * time.Second)
	for getCounterValue(prober.ProbesTimedOut, "jitter_var", addr) < 1 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if getCounterValue(prober.ProbesTimedOut, "jitter_var", addr) < 1 {
		t.Fatal("dropped probe never timed out")
	}
	prev := getHistogramCount(prober.RTTSeconds, "jitter_var", addr)
	for getHistogramCount(prober.RTTSeconds, "jitter_var", addr) == prev && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	j = getGaugeValue(prober.JitterSeconds, "jitter_var", addr)
	if j > 0.002 {
		t.Errorf("jitter must reset to 0 on sequence gap, got %v", j)
	}

	// Phase 3: estimate rebuilds slowly from 0 — no spike.
	time.Sleep(300 * time.Millisecond)
	j = getGaugeValue(prober.JitterSeconds, "jitter_var", addr)
	if j > 0.015 {
		t.Errorf("jitter must rebuild from 0 after gap, got %v (want < 0.015)", j)
	}
	if math.IsNaN(j) || j < 0 {
		t.Errorf("jitter must be non-negative, got %v", j)
	}

	cancel()
}
