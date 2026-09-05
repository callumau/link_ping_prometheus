package prober_test

// Precision tests: exact, adversarial assertions on the monitoring-visible
// numbers. Unlike the tolerance-based suites, each test here pins a
// mathematically derivable value (RFC 3550 convergence, bucket lower bounds,
// counter equalities) so a plausible regression — wrong send-time baseline,
// fixed RTO floor, link_up keyed on loss ratio, fabricated counters — fails
// loudly instead of drifting inside a tolerance window.

import (
	"context"
	"math"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"link_ping_prometheus/internal/prober"
)

// TestPrecision_AdaptiveRTOFloor_ExactHeadroom: on a stable ~180ms link the
// dynamic RTO floor (max(200ms, 2*SRTT)) must hold the timeout at ~2× the
// measured RTT, and the link must produce ZERO false timeouts. A regression
// to a fixed 200ms floor reads ~0.2s on the RTO gauge (fails the lower
// bound), and any floor arithmetic error shows up as spurious
// link_probes_timed_out_total — the exact class of loss inflation the
// dynamic floor exists to prevent.
func TestPrecision_AdaptiveRTOFloor_ExactHeadroom(t *testing.T) {
	prober.InitMetrics()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	delay := 180 * time.Millisecond
	addr := validatedEcho(t, ctx, func(buf []byte, w func([]byte)) {
		time.Sleep(delay)
		w(buf)
	})

	targetName, cfgBase := namedCfg("precision_floor", addr, 250*time.Millisecond, 500*time.Millisecond)
	cfg := cfgBase
	cfg.Adaptive = true

	startTimeout := getCounterValue(prober.ProbesTimedOut, targetName, addr)
	runClientFor(ctx, cfg, 3500*time.Millisecond)
	cancel()
	time.Sleep(200 * time.Millisecond)

	if got := getCounterValue(prober.ProbesTimedOut, targetName, addr) - startTimeout; got != 0 {
		t.Errorf("adaptive RTO on a stable %v link must produce ZERO false timeouts, got %v", delay, got)
	}

	mean := getHistogramMean(prober.RTTSeconds, targetName, addr)
	if mean < delay.Seconds() || mean > delay.Seconds()+0.015 {
		t.Fatalf("mean RTT %v out of [%v, %v] — test shape broken (cpu load?)", mean, delay.Seconds(), delay.Seconds()+0.015)
	}
	rto := getGaugeValue(prober.RTOEstimate, targetName, addr)
	// Floor: 2*SRTT. Upper: SRTT + max(G, 4*RTTVAR) ≈ SRTT + G once RTTVAR
	// decays, but tolerate early-sample variance.
	if rto < 2*mean-0.01 {
		t.Errorf("RTO %v must hold the dynamic floor ≥ 2*SRTT ≈ %v (a fixed 200ms floor reads ~0.2 here)", rto, 2*mean)
	}
	if rto > 2*mean+0.1 {
		t.Errorf("RTO %v wildly above 2*SRTT+%v — RTO computation diverged", rto, 2*mean)
	}
}

// TestPrecision_BucketPlacement_CannotUndercountRTT: the echo server sleeps
// D before replying, so EVERY RTT sample is ≥ D by construction — the
// histogram's cumulative counts at every edge below D must be EXACTLY 0.
// Any sample there means RTT was measured from the wrong baseline (tick
// time, server clock, etc.) and undercounts real latency while the mean
// still looks plausible. Two targets pin this at two delays in one run.
func TestPrecision_BucketPlacement_CannotUndercountRTT(t *testing.T) {
	prober.InitMetrics()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mkEcho := func(delay time.Duration) func([]byte, func([]byte)) {
		return func(buf []byte, w func([]byte)) {
			time.Sleep(delay)
			w(buf)
		}
	}

	addrA := validatedEcho(t, ctx, mkEcho(80*time.Millisecond))
	addrB := validatedEcho(t, ctx, mkEcho(120*time.Millisecond))

	// Interval must exceed the largest delay: the echo responder handles
	// probes serially, so interval < delay makes the server queue echoes
	// and RTT grows without bound (423ms mean observed at 60ms/80ms).
	cfg := cfgWith(false, 150*time.Millisecond, time.Second,
		prober.Target{Name: "precision_bkt_80", Address: addrA},
		prober.Target{Name: "precision_bkt_120", Address: addrB})
	runClientFor(ctx, cfg, 4500*time.Millisecond)
	cancel()
	time.Sleep(200 * time.Millisecond)

	cases := []struct {
		name    string
		addr    string
		delay   time.Duration
		maxMean time.Duration
	}{
		{"precision_bkt_80", addrA, 80 * time.Millisecond, 95 * time.Millisecond},
		{"precision_bkt_120", addrB, 120 * time.Millisecond, 135 * time.Millisecond},
	}
	for _, tc := range cases {
		h := histogramMetric(prober.RTTSeconds, tc.name, tc.addr)
		if h == nil {
			t.Fatalf("%s: no histogram series", tc.name)
		}
		total := float64(h.GetSampleCount())
		if total < 20 {
			t.Fatalf("%s: only %v samples — cpu load?", tc.name, total)
		}
		for _, b := range h.GetBucket() {
			if b.GetUpperBound() < tc.delay.Seconds() && b.GetCumulativeCount() != 0 {
				t.Errorf("%s: %v samples at/below the %v edge but the link RTT can never go below %v — RTT baseline is wrong",
					tc.name, b.GetCumulativeCount(), b.GetUpperBound(), tc.delay)
			}
		}
		mean := h.GetSampleSum() / total
		if mean < tc.delay.Seconds() || mean > tc.maxMean.Seconds() {
			t.Errorf("%s: mean RTT %v out of [%v, %v]", tc.name, mean, tc.delay.Seconds(), tc.maxMean.Seconds())
		}
	}
}

// TestPrecision_HealthyLink_NoFabricatedLoss_ServerCrossCheck: on an
// echo-everything loopback link, loss must be EXACTLY zero and the server's
// received counter must equal the client's sent counter exactly (every
// written datagram arrives). The only permitted residual in
// sent − rtt_count − timed_out is probes abandoned in flight at cancel —
// bounded by RTO/interval — and inflight must drain to 0. Disproves
// fabricated counters, wrong denominators, and client/server drift.
func TestPrecision_HealthyLink_NoFabricatedLoss_ServerCrossCheck(t *testing.T) {
	prober.InitMetrics()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Cross-check against the REAL prober echo server: only
	// ServePacketConn increments link_server_probes_received_total — a
	// hand-rolled test responder never would.
	pc := listenUDP(t, ctx)
	allowed := map[string]struct{}{"127.0.0.1": {}}
	go prober.ServePacketConn(ctx, pc, testSource, allowed, "")
	addr := pc.LocalAddr().String()
	clientIP := "127.0.0.1" // server metric labels the bare IP, not IP:port

	targetName, cfg := namedCfg("precision_healthy", addr, 100*time.Millisecond, 400*time.Millisecond)

	startSent := getCounterValue(prober.ProbesSent, targetName, addr)
	startServerRecv := getCounterValue(prober.ServerProbesReceived, clientIP)

	runClientSettle(ctx, cancel, cfg, 2*time.Second)
	time.Sleep(300 * time.Millisecond)

	sent := getCounterValue(prober.ProbesSent, targetName, addr) - startSent
	timedOut := getCounterValue(prober.ProbesTimedOut, targetName, addr)
	recvd := getHistogramCount(prober.RTTSeconds, targetName, addr)
	serverRecv := getCounterValue(prober.ServerProbesReceived, clientIP) - startServerRecv

	if sent < 10 {
		t.Fatalf("only %v probes sent — cpu load?", sent)
	}
	if timedOut != 0 {
		t.Errorf("healthy loopback link must read EXACTLY 0 timeouts, got %v — fabricated loss", timedOut)
	}
	if serverRecv != sent {
		t.Errorf("server received %v but client sent %v — every written datagram must reach an echo-all loopback server", serverRecv, sent)
	}
	residual := sent - recvd - timedOut
	if residual < 0 || residual > 5 { // abandoned in flight at cancel ≤ RTO/interval + 1
		t.Errorf("balance: sent %v = rtt %v + timeout %v leaves residual %v (allowed 0..5 abandoned at cancel)", sent, recvd, timedOut, residual)
	}
	if inflight := getGaugeValue(prober.ProbesInflight, targetName, addr); inflight != 0 {
		t.Errorf("inflight must drain to 0 after settle, got %v", inflight)
	}
}

// TestPrecision_LinkUpImmuneToSustainedNonconsecutiveLoss: a 33% loss rate
// (every 3rd probe dropped, never consecutively) must keep link_up == 1 for
// the entire run. Disproves any regression that keys link state off the loss
// ratio or single misses instead of LinkUpMissThreshold consecutive misses.
func TestPrecision_LinkUpImmuneToSustainedNonconsecutiveLoss(t *testing.T) {
	prober.InitMetrics()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	count := 0
	addr := validatedEcho(t, ctx, func(buf []byte, w func([]byte)) {
		count++
		if count%3 == 0 {
			return
		}
		w(buf)
	})

	targetName, cfg := namedCfg("precision_linkup_loss", addr, 50*time.Millisecond, 200*time.Millisecond)

	down := false
	done := make(chan struct{})
	go func() {
		go prober.RunClient(ctx, cfg)
		// Monitor only after the first echo lands: link_up starts at 0 by
		// design until the first echo, and that startup window is not a
		// flap.
		for getHistogramCount(prober.RTTSeconds, targetName, addr) == 0 {
			time.Sleep(20 * time.Millisecond)
		}
		deadline := time.Now().Add(2500 * time.Millisecond)
		for time.Now().Before(deadline) {
			if getGaugeValue(prober.LinkUp, targetName, addr) != 1 {
				down = true
			}
			time.Sleep(40 * time.Millisecond)
		}
		close(done)
	}()
	<-done
	cancel()
	time.Sleep(200 * time.Millisecond)

	if timedOut := getCounterValue(prober.ProbesTimedOut, targetName, addr); timedOut < 5 {
		t.Fatalf("only %v timeouts — the 33%% drop shape did not take effect (vacuous pass)", timedOut)
	}
	if getHistogramCount(prober.RTTSeconds, targetName, addr) < 20 {
		t.Fatal("too few echoes matched — test setup broken (cpu load?)")
	}
	if down {
		t.Error("link_up read 0 under sustained 33% non-consecutive loss — link state must track consecutive misses, not loss ratio")
	}
	if up := getGaugeValue(prober.LinkUp, targetName, addr); up != 1 {
		t.Errorf("link_up must stay 1 at end of run, got %v", up)
	}
}

// TestPrecision_Jitter_AnalyticConvergence: with RTT alternating 0ms/40ms,
// every consecutive delta |D| is ~40ms, so RFC 3550 (J += (|D|−J)/16) gives
// the closed form J_N = 40ms·(1−(15/16)^N) after N consecutive samples.
// After polling to a known sample count N, J must sit inside the analytic
// band [40ms·(1−0.9375^N)−3ms, 45ms] — a tighter, formula-derived check
// than any fixed tolerance, disproving wrong gain, wrong delta sign, or
// sampling from the wrong pair.
func TestPrecision_Jitter_AnalyticConvergence(t *testing.T) {
	prober.InitMetrics()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var count atomic.Int64
	addr := validatedEcho(t, ctx, func(buf []byte, w func([]byte)) {
		if count.Add(1)%2 == 0 {
			time.Sleep(40 * time.Millisecond)
		}
		w(buf)
	})

	targetName, cfg := namedCfg("precision_jitter", addr, 100*time.Millisecond, 200*time.Millisecond)
	go prober.RunClient(ctx, cfg)

	// Poll until N consecutive samples so the analytic bound is known.
	const minSamples = 30
	deadline := time.Now().Add(10 * time.Second)
	var n int
	for time.Now().Before(deadline) {
		if n = int(getHistogramCount(prober.RTTSeconds, targetName, addr)); n >= minSamples {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if n < minSamples {
		t.Fatalf("only %v samples in 10s — cpu load?", n)
	}

	analytic := 40*time.Millisecond.Seconds() * (1 - math.Pow(15.0/16.0, float64(n)))
	j := getGaugeValue(prober.JitterSeconds, targetName, addr)
	lower := analytic - 0.003 // scheduling noise on the ~0ms leg
	upper := 0.045           // converged J approaches max |D| ≈ 40ms + noise
	if j < lower || j > upper {
		t.Errorf("jitter %v outside RFC 3550 analytic band [%v, %v] for N=%v (fixed point is 40ms)", j, lower, upper, n)
	}
	cancel()
}

// TestPrecision_RTTBucketList_PinnedExact: the histogram bucket list is
// user-facing (README documents it; Grafana quantiles depend on it) and has
// drifted out of sync with docs before. Pin the exact list, its ordering,
// and its ceiling against DefaultMaxRTO: any bucket edit must be a
// conscious, test-visible change.
func TestPrecision_RTTBucketList_PinnedExact(t *testing.T) {
	want := []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 3.0}
	if !reflect.DeepEqual(prober.RTTBuckets, want) {
		t.Errorf("RTTBuckets drifted: got %v, want %v (update README bucket list in the same commit)", prober.RTTBuckets, want)
	}
	for i := 1; i < len(prober.RTTBuckets); i++ {
		if prober.RTTBuckets[i] <= prober.RTTBuckets[i-1] {
			t.Errorf("bucket edges must strictly increase: %v then %v", prober.RTTBuckets[i-1], prober.RTTBuckets[i])
		}
	}
	if max := prober.RTTBuckets[len(prober.RTTBuckets)-1]; max != prober.DefaultMaxRTO.Seconds() {
		t.Errorf("largest bucket edge %v must equal DefaultMaxRTO (%v): samples beyond the RTO cap are impossible, extra edges are dead weight", max, prober.DefaultMaxRTO.Seconds())
	}
}
