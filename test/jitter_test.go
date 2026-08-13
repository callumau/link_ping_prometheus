package prober_test

import (
	"context"
	"math"
	"sync/atomic"
	"testing"
	"time"

	"link_ping_prometheus/internal/prober"
)

// TestJitterGauge_MultiInflightKeepsTracking: with more than one probe
// in flight (interval < RTO — the state adaptive backoff produces on a
// degraded link), echoes arrive in bursts and several can land in the
// same drain tick. The RFC 3550 estimate must keep tracking the RTT
// swing; it must not collapse to 0 just because a drain processed
// several responses at once.
func TestJitterGauge_MultiInflightKeepsTracking(t *testing.T) {
	prober.InitMetrics()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Batch echo server: probes are gathered and flushed together every
	// ~150ms, with the flush delay alternating 100ms/200ms per batch.
	// Each flush delivers several echoes back-to-back (multiple
	// responses per client drain) and consecutive batches have RTTs that
	// differ by ~100ms — the condition that exposed the collapse.
	var frames [][]byte
	var flushAt time.Time
	longDelay := false
	addr := udpEcho(t, ctx, func(buf []byte, w func([]byte)) {
		if len(buf) != prober.PayloadSize || string(buf[0:8]) != prober.MagicBytes {
			return
		}
		frames = append(frames, append([]byte(nil), buf...))
		if flushAt.IsZero() {
			flushAt = time.Now().Add(150 * time.Millisecond)
		}
		if !time.Now().Before(flushAt) {
			batch := frames
			frames = nil
			flushAt = time.Time{}
			delay := 100 * time.Millisecond
			if longDelay {
				delay = 200 * time.Millisecond
			}
			longDelay = !longDelay
			time.Sleep(delay)
			for _, f := range batch {
				w(f)
			}
		}
	})

	// Interval 50ms with a ~250-350ms RTT keeps ~5-7 probes in flight;
	// the 2s timeout never fires, so every probe resolves as an echo.
	cfg := cfgWith(false, 50*time.Millisecond, 2*time.Second, prober.Target{Name: "jitter_multi", Address: addr})
	go prober.RunClient(ctx, cfg)

	// The estimate must climb past 1ms once the first RTT swing is
	// observed; it must never blow past the ~250ms worst-case delta.
	var maxSeen float64
	seen := false
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if j := getGaugeValue(prober.JitterSeconds, "jitter_multi", addr); j > maxSeen {
			maxSeen = j
		}
		if j := getGaugeValue(prober.JitterSeconds, "jitter_multi", addr); j > 0.001 {
			seen = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !seen {
		t.Errorf("jitter collapsed to 0 with multiple probes in flight (max seen %.4fs); RTTs differing by ~100ms must feed the RFC 3550 estimate", maxSeen)
	}
	if j := getGaugeValue(prober.JitterSeconds, "jitter_multi", addr); j > 0.3 {
		t.Errorf("jitter %.4fs exceeds the ~250ms worst-case RTT delta; estimate diverged", j)
	}

	cancel()
}

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
