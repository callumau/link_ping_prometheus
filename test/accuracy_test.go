package prober_test

// Accuracy-focused integration tests: they pin the monitoring-visible
// numbers (loss ratio, balance invariant, RTT histogram placement,
// documented jitter ceiling) against deliberately shaped echo servers.
// Complements client_test.go's accuracy suite, which covers loss ratio
// and mean-RTT point estimates; these tests add invariant-level checks
// those suites do not make.

import (
	"context"
	"math"
	"testing"
	"time"

	"link_ping_prometheus/internal/prober"
)

// TestBalanceInvariant_ExactAccountingUnderLoss: while probes are being
// dropped at a known rate, every probe must resolve into exactly one of
// {echo counted, timeout} — sent minus resolved probes may only differ
// by the handful abandoned at cancel (never flushed by design, see
// TestGracefulShutdown_NoPhantomTimeouts), and the in-flight gauge must
// drain to zero once probing stops. A drift here silently undercounts
// real loss forever.
func TestBalanceInvariant_ExactAccountingUnderLoss(t *testing.T) {
	prober.InitMetrics()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	count := 0
	addr := validatedEcho(t, ctx, func(buf []byte, w func([]byte)) {
		count++
		if count%4 == 0 {
			return // known 25% drop fraction
		}
		w(buf)
	})

	targetName, cfg := namedCfg("balance_loss_test", addr, 50*time.Millisecond, 200*time.Millisecond)

	startSent := getCounterValue(prober.ProbesSent, targetName, addr)
	startTimeout := getCounterValue(prober.ProbesTimedOut, targetName, addr)
	startRecv := getHistogramCount(prober.RTTSeconds, targetName, addr)

	runClientSettle(ctx, cancel, cfg, 1200*time.Millisecond)
	time.Sleep(300 * time.Millisecond) // let the final sweeps resolve

	sent := getCounterValue(prober.ProbesSent, targetName, addr) - startSent
	timedOut := getCounterValue(prober.ProbesTimedOut, targetName, addr) - startTimeout
	recvd := getHistogramCount(prober.RTTSeconds, targetName, addr) - startRecv

	if sent < 8 {
		t.Fatalf("too few probes sent (%v) to judge loss accounting — cpu load?", sent)
	}

	// Known drop fraction: every 4th probe is skipped by the echo server.
	expectedDrops := math.Round(sent / 4)
	if math.Abs(timedOut-expectedDrops) > 2 {
		t.Errorf("timeouts %v should match the 1-in-4 drop fraction (~%v)", timedOut, expectedDrops)
	}

	// Balance invariant: unresolved probes are only the ones abandoned
	// mid-flight at cancel (bounded by interval vs timeout window).
	if unresolved := sent - recvd - timedOut; math.Abs(unresolved) > 3 {
		t.Errorf("balance violated: sent %v = recv %v + timeout %v leaves %v unaccounted", sent, recvd, timedOut, unresolved)
	}
	if inflight := getGaugeValue(prober.ProbesInflight, targetName, addr); inflight != 0 {
		t.Errorf("in-flight must drain to 0 after settle, got %v", inflight)
	}
}

// TestRTTBuckets_LandInFiniteBucketsUnderKnownLatency: with an 80ms
// injected delay, the histogram mean must track it AND the samples must
// land inside the finite bucket range (nothing relegated to +Inf only),
// concentrated in the [50ms, 250ms] edges. If bucket edges ever stop
// covering real link latencies, quantile recording degrades silently
// while means still look plausible.
func TestRTTBuckets_LandInFiniteBucketsUnderKnownLatency(t *testing.T) {
	prober.InitMetrics()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	delay := 80 * time.Millisecond
	addr := validatedEcho(t, ctx, func(buf []byte, w func([]byte)) {
		time.Sleep(delay)
		w(buf)
	})

	targetName, cfg := namedCfg("bucket_test", addr, 100*time.Millisecond, 500*time.Millisecond)
	runClientFor(ctx, cfg, 1300*time.Millisecond)
	cancel()
	time.Sleep(200 * time.Millisecond)

	h := histogramMetric(prober.RTTSeconds, targetName, addr)
	if h == nil {
		t.Fatal("no histogram series for bucket test")
	}
	total := float64(h.GetSampleCount())
	if total < 5 {
		t.Fatalf("only %v samples collected — cpu load?", total)
	}

	mean := h.GetSampleSum() / total
	if mean < delay.Seconds()-0.015 || mean > delay.Seconds()+0.03 {
		t.Errorf("mean RTT %vs drifted from injected delay %vs", mean, delay.Seconds())
	}

	// Cumulative bucket counts: nothing beyond the largest finite edge.
	var below50, below250, belowMax float64
	for _, b := range h.GetBucket() {
		switch ub := b.GetUpperBound(); {
		case ub == 0.05:
			below50 = float64(b.GetCumulativeCount())
		case ub == 0.25:
			below250 = float64(b.GetCumulativeCount())
		case ub == 2.5:
			belowMax = float64(b.GetCumulativeCount())
		}
	}
	if belowMax != total {
		t.Errorf("%v of %v samples landed beyond the largest finite bucket (+Inf-only): bucket edges do not cover measured latencies", total-belowMax, total)
	}
	inRange := below250 - below50
	if inRange < 0.9*total {
		t.Errorf("only %v/%v samples in the [50ms,250ms] edges for an 80ms link", inRange, total)
	}
}

// TestJitterGauge_ReorderResetsEstimate_DocumentedCeiling: AGENTS.md
// documents a known ceiling — packet reordering within the pending
// window resets the RFC 3550 estimate to 0 (non-consecutive sequence),
// understating jitter on reorder-prone links. This test PINS that
// documented behavior so any future fix is a conscious change, not an
// accident: with pairwise-reversed delivery and a constant 40ms RTT
// swing, an implementation that stopped resetting would climb toward
// ~40ms; the current one must stay near 0.
func TestJitterGauge_ReorderResetsEstimate_DocumentedCeiling(t *testing.T) {
	prober.InitMetrics()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var pair [][]byte
	n := 0
	addr := validatedEcho(t, ctx, func(buf []byte, w func([]byte)) {
		pair = append(pair, append([]byte(nil), buf...))
		n++
		if n%2 == 0 {
			time.Sleep(40 * time.Millisecond)
			// Deliver the pair reversed: seq k+1 before seq k.
			w(pair[1])
			w(pair[0])
			pair = pair[:0]
		}
	})

	targetName, cfg := namedCfg("reorder_jitter_test", addr, 50*time.Millisecond, 300*time.Millisecond)
	runClientFor(ctx, cfg, 1500*time.Millisecond)
	cancel()
	time.Sleep(200 * time.Millisecond)

	// Guard against passing vacuously: echoes must actually be matched.
	if c := getHistogramCount(prober.RTTSeconds, targetName, addr); c < 5 {
		t.Fatalf("only %v reordered echoes matched — test setup broken (cpu load?)", c)
	}
	if j := getGaugeValue(prober.JitterSeconds, targetName, addr); j > 0.005 {
		t.Errorf("jitter %v s under continuous reordering exceeds the documented reset-to-0 ceiling (~40ms swings would show as ~0.04)", j)
	}
}

// TestNonAdaptive_SlowLinkReadsAsTimeoutsNotSilence: with a fixed
// timeout below true RTT, every probe must resolve as a counted timeout
// (visible, balanced loss) rather than vanishing silently — and link_up
// must fall to 0, since sustained misses mean the health signal is
// honest even when the operator misconfigured the fixed timeout.
func TestNonAdaptive_SlowLinkReadsAsTimeoutsNotSilence(t *testing.T) {
	prober.InitMetrics()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr := validatedEcho(t, ctx, func(buf []byte, w func([]byte)) {
		time.Sleep(150 * time.Millisecond) // well past the 100ms fixed timeout
		w(buf)
	})

	targetName, cfg := namedCfg("slow_fixed_test", addr, 100*time.Millisecond, 100*time.Millisecond)

	startSent := getCounterValue(prober.ProbesSent, targetName, addr)
	startTimeout := getCounterValue(prober.ProbesTimedOut, targetName, addr)
	startRecv := getHistogramCount(prober.RTTSeconds, targetName, addr)

	runClientSettle(ctx, cancel, cfg, 900*time.Millisecond)
	time.Sleep(300 * time.Millisecond)

	sent := getCounterValue(prober.ProbesSent, targetName, addr) - startSent
	timedOut := getCounterValue(prober.ProbesTimedOut, targetName, addr) - startTimeout
	recvd := getHistogramCount(prober.RTTSeconds, targetName, addr) - startRecv

	if sent < 4 {
		t.Fatalf("only %v probes sent — cpu load?", sent)
	}
	if recvd != 0 {
		t.Errorf("responses arriving past the fixed deadline must not be counted as RTT samples, got %v", recvd)
	}
	if timedOut < sent-3 {
		t.Errorf("probes exceeding the fixed timeout must resolve as visible timeouts: sent %v, timed out %v", sent, timedOut)
	}
	if inflight := getGaugeValue(prober.ProbesInflight, targetName, addr); inflight != 0 {
		t.Errorf("in-flight must drain to 0, got %v", inflight)
	}
	if up := getGaugeValue(prober.LinkUp, targetName, addr); up != 0 {
		t.Errorf("link_up must read 0 when every probe times out, got %v", up)
	}
}
