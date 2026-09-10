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

	// Guard against a vacuous pass: with no echo ever matched the gauge sits
	// at its 0 default and the assertion below cannot fail. Fewer than a
	// handful of consecutive samples makes the check meaningless too.
	if n := getHistogramCount(prober.RTTSeconds, "jitter_const", addr); n < 5 {
		t.Fatalf("only %v echoes matched — jitter==0 would be vacuous (cpu load?)", n)
	}

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
	// 0ms (odd count) before echoing. dropNow arms a ONE-SHOT drop:
	// CompareAndSwap consumes it on the next even count, so exactly one
	// sequence gap occurs. A permanently-armed drop (the old Load()
	// check) drops every even probe forever, pinning the estimate at 0 and
	// making the "rebuilds slowly — no spike" assertion unfalsifiable.
	var count atomic.Int64
	var dropNow atomic.Bool
	addr := udpEcho(t, ctx, func(buf []byte, w func([]byte)) {
		if len(buf) != prober.PayloadSize || string(buf[0:8]) != prober.MagicBytes {
			return
		}
		n := count.Add(1)
		if n%2 == 0 && dropNow.CompareAndSwap(true, false) {
			return // the single dropped probe
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

	// Phase 2: arm the one-shot drop, then catch the reset. The first
	// response AFTER the gap sets J to 0 for one inter-probe window
	// (~interval) before the following sample rebuilds it, so poll faster
	// than the interval to observe that window.
	dropNow.Store(true)
	deadline := time.Now().Add(5 * time.Second)
	resetSeen := false
	for time.Now().Before(deadline) {
		if getGaugeValue(prober.JitterSeconds, "jitter_var", addr) <= 0.001 {
			resetSeen = true
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if !resetSeen {
		t.Fatalf("jitter never reset to 0 after the sequence gap (cpu load?)")
	}
	// Anchor the rebuild count at the reset sample (the histogram Observe
	// runs in the same block as the jitter Set, so the reset sample is
	// already counted here).
	base := getHistogramCount(prober.RTTSeconds, "jitter_var", addr)
	// The gap must be real: the one-shot dropped probe has to time out.
	for getCounterValue(prober.ProbesTimedOut, "jitter_var", addr) < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if getCounterValue(prober.ProbesTimedOut, "jitter_var", addr) < 1 {
		t.Fatal("one-shot dropped probe never timed out — no sequence gap was created")
	}

	// Phase 3: the estimate REBUILDS from the post-gap reset — strictly
	// positive again, and inside the RFC 3550 band for the observed
	// consecutive sample count (J_N = 40ms·(1−(15/16)^N)). A regression
	// that pins J at 0 after a gap fails the > 0 check; one that re-seeds
	// it with a stale delta fails the analytic ceiling.
	const rebuildSamples = 8
	p3deadline := time.Now().Add(5 * time.Second)
	n := 0
	for time.Now().Before(p3deadline) {
		if n = int(getHistogramCount(prober.RTTSeconds, "jitter_var", addr) - base); n >= rebuildSamples {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if n < rebuildSamples {
		t.Fatalf("only %d samples after the gap in 5s — cpu load?", n)
	}
	j = getGaugeValue(prober.JitterSeconds, "jitter_var", addr)
	if math.IsNaN(j) || j <= 0 {
		t.Errorf("jitter must rebuild to a positive value after a sequence gap, got %v", j)
	}
	analytic := 40 * time.Millisecond.Seconds() * (1 - math.Pow(15.0/16.0, float64(n)))
	if j > analytic+0.004 {
		t.Errorf("jitter %v above the RFC 3550 rebuild band %v for N=%d — the estimate must climb slowly from the post-gap reset", j, analytic+0.004, n)
	}

	cancel()
}
