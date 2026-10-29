package prober_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"link_ping_prometheus/internal/prober"
)

// mtuCfg builds a fast-sweep client config for MTU tests: 300ms sweep
// probe deadlines keep the binary search bounded even on failure paths.
func mtuCfg(addr string, status *prober.StatusRegistry) prober.Config {
	return prober.Config{
		Source:       testSource,
		Targets:      []prober.Target{{Name: "mtu_target", Address: addr}},
		BaseInterval: 50 * time.Millisecond,
		BaseTimeout:  300 * time.Millisecond,
		Adaptive:     true,
		MTUSweep:     20 * time.Millisecond,
		Status:       status,
	}
}

// mainBalanceGap reads the main probe counters once and returns
// sent − (rtt_count + timed_out + inflight). These are separate atomics, so
// a counter transition landing mid-read can leave a ±1 residue; callers
// retry a few times. MTU-sweep probes must never enter these counters, so
// while a sweep has run the gap is exactly 0.
func mainBalanceGap(name, addr string) float64 {
	sent := getCounterValue(prober.ProbesSent, name, addr)
	rtt := getHistogramCount(prober.RTTSeconds, name, addr)
	timedOut := getCounterValue(prober.ProbesTimedOut, name, addr)
	inflight := getGaugeValue(prober.ProbesInflight, name, addr)
	return sent - rtt - timedOut - inflight
}

// TestMTUSweep_FullSizeSurvives: on an echo-everything path the sweep
// proves the maximum frame on the first probe; path_mtu_bytes converges
// to header+MaxPayloadBytes and surfaces in /status. MTU counters move
// independently of the main loss counters (deliberately outside the
// sent/rtt/timed_out/corrupted balance).
// pi-lens-ignore: go-test-functions
func TestMTUSweep_FullSizeSurvives(t *testing.T) {
	prober.InitMetrics()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr := udpEcho(t, ctx, func(buf []byte, w func([]byte)) { w(buf) })
	reg := prober.NewStatusRegistry()
	cfg := mtuCfg(addr, reg)

	runClientAsync(t, ctx, cancel, cfg)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if getGaugeValue(prober.PathMTUBytes, "mtu_target", addr) == float64(prober.PayloadSize+prober.MaxPayloadBytes) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := getGaugeValue(prober.PathMTUBytes, "mtu_target", addr); got != float64(prober.PayloadSize+prober.MaxPayloadBytes) {
		t.Fatalf("path_mtu_bytes must converge to header+MaxPayloadBytes=%d, got %v", prober.PayloadSize+prober.MaxPayloadBytes, got)
	}
	if n := getCounterValue(prober.MTUProbesSent, "mtu_target", addr); n < 1 {
		t.Errorf("expected at least 1 MTU probe sent, got %v", n)
	}
	if n := getCounterValue(prober.MTUProbesLost, "mtu_target", addr); n != 0 {
		t.Errorf("healthy full-size path must have 0 lost MTU probes, got %v", n)
	}

	// A sweep has run (MTUProbesSent > 0 above), so the MAIN balance must
	// still hold exactly: sent == rtt_count + timed_out + inflight. A
	// regression that routed DF-sweep probes through link_probes_sent_total
	// would inflate sent — the loss denominator — without a matching rtt or
	// timeout sample and break this immediately. The read is retried because
	// the four counters are separate atomics (a transition landing mid-read
	// leaves a ±1 residue); a real regression is persistent, not transient.
	balDeadline := time.Now().Add(2 * time.Second)
	balanced := false
	for time.Now().Before(balDeadline) {
		if mainBalanceGap("mtu_target", addr) == 0 {
			balanced = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !balanced {
		t.Errorf("main balance broken while MTU sweeps run: sent-(rtt+timed_out+inflight) = %v (MTU probes must stay out of the loss counters)", mainBalanceGap("mtu_target", addr))
	}

	// /status carries the same value (snapshot refreshes on the main
	// loop tick, so poll briefly rather than reading immediately).
	deadline = time.Now().Add(2 * time.Second)
	pathMTU := 0
	for time.Now().Before(deadline) {
		for _, s := range reg.Snapshot() {
			if s.Name == "mtu_target" {
				pathMTU = s.PathMTUBytes
			}
		}
		if pathMTU == prober.PayloadSize+prober.MaxPayloadBytes {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if pathMTU != prober.PayloadSize+prober.MaxPayloadBytes {
		t.Errorf("/status path_mtu_bytes must mirror the gauge, got %d", pathMTU)
	}

	// MTU probes never enter the main loss machinery: on an echo-all
	// server the main counters show no fabricated loss.
	if n := getCounterValue(prober.ProbesTimedOut, "mtu_target", addr); n != 0 {
		t.Errorf("main loss must be untouched by MTU sweeps, got %v", n)
	}
}

// TestMTUSweep_FindsLimit: a server that silently drops frames larger
// than a bound (MTU-restricted path) makes the sweep settle on the
// largest surviving size — lost probes counted separately, link_up
// unaffected (small probes keep flowing).
// pi-lens-ignore: go-test-functions
func TestMTUSweep_FindsLimit(t *testing.T) {
	prober.InitMetrics()

	const maxPayload = 600
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr := udpEcho(t, ctx, func(buf []byte, w func([]byte)) {
		if len(buf) <= prober.PayloadSize+maxPayload {
			w(buf)
		}
	})
	reg := prober.NewStatusRegistry()
	cfg := mtuCfg(addr, reg)

	runClientAsync(t, ctx, cancel, cfg)
	want := prober.PayloadSize + maxPayload
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if getGaugeValue(prober.PathMTUBytes, "mtu_target", addr) == float64(want) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got := getGaugeValue(prober.PathMTUBytes, "mtu_target", addr); got != float64(want) {
		t.Fatalf("path_mtu_bytes must converge to header+%d=%d, got %v", maxPayload, want, got)
	}
	if n := getCounterValue(prober.MTUProbesLost, "mtu_target", addr); n < 1 {
		t.Errorf("oversized sweep probes must be counted lost, got %v", n)
	}
	if up := getGaugeValue(prober.LinkUp, "mtu_target", addr); up != 1 {
		t.Errorf("MTU sweeps must not disturb link_up, got %v", up)
	}
}

// TestMTUSweep_SingleLossDoesNotFlapGauge pins the retry-once flap
// protection at a LIVE link: a size with no echo is retried once before the
// search steps down, so one dropped DF probe cannot converge path_mtu_bytes
// below the real MTU and make it flap between sweeps (e.g. 1424 → 1248 at
// 1% loss). The server drops exactly one full-size probe (the first
// attempt) and echoes the retry and everything else, so the gauge must
// converge to and stay at the real MTU, lost must count that single dropped
// ATTEMPT (a probe rate, not a distinct-size rate), and the retry's extra
// attempt must appear in sent.
// pi-lens-ignore: go-test-functions
func TestMTUSweep_SingleLossDoesNotFlapGauge(t *testing.T) {
	prober.InitMetrics()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var fullSeen atomic.Int64
	addr := udpEcho(t, ctx, func(buf []byte, w func([]byte)) {
		if len(buf) == prober.PayloadSize+prober.MaxPayloadBytes && fullSeen.Add(1) == 1 {
			return // drop exactly the first full-size DF probe
		}
		w(buf)
	})
	reg := prober.NewStatusRegistry()
	cfg := mtuCfg(addr, reg)

	runClientAsync(t, ctx, cancel, cfg)
	want := float64(prober.PayloadSize + prober.MaxPayloadBytes)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if getGaugeValue(prober.PathMTUBytes, "mtu_target", addr) == want {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := getGaugeValue(prober.PathMTUBytes, "mtu_target", addr); got != want {
		t.Fatalf("gauge must converge to the real MTU despite one dropped probe: want %v, got %v (retry-once broken?)", want, got)
	}
	if n := getCounterValue(prober.MTUProbesSent, "mtu_target", addr); n < 2 {
		t.Fatalf("the dropped size must be retried: sent %v probes, want >= 2", n)
	}
	// A probe RATE, not an exact count: the sweep fires every 20ms while these
	// assertions run, so an extra attempt (a retry racing the next sweep, a
	// probe still inside its deadline) is normal under CPU load. What must hold
	// is that the one dropped attempt was counted and that succeeding sweeps do
	// not keep adding losses.
	if n := getCounterValue(prober.MTUProbesLost, "mtu_target", addr); n < 1 {
		t.Errorf("the dropped attempt must count lost, got %v", n)
	}
	// The flap this guards against happens between sweeps, so keep sampling
	// across several more sweeps: the gauge must stay at the real MTU.
	for range 20 {
		if got := getGaugeValue(prober.PathMTUBytes, "mtu_target", addr); got != want {
			t.Fatalf("gauge flapped after the transient loss: want %v, got %v", want, got)
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Bounded, not exact: ±1 of slack absorbs a retry that landed while the
	// sampling loop above ran (repo convention — assertions that encode an
	// exact scheduling order are flaky on a loaded box). A real regression
	// (every sweep losing its full-size probe) would grow without bound.
	if n := getCounterValue(prober.MTUProbesLost, "mtu_target", addr); n > 2 {
		t.Errorf("succeeding sweeps must not add lost attempts, got %v (want <= 2)", n)
	}
	// MTU probes stay outside the main loss balance even with a retry.
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if mainBalanceGap("mtu_target", addr) == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if gap := mainBalanceGap("mtu_target", addr); gap != 0 {
		t.Errorf("main balance broken while MTU sweeps run: gap %v", gap)
	}
}

// TestMTUSweep_DeadLinkKeepsLastValue: when even the header-only DF
// probe dies (link down / DF-blocked path), the sweep aborts early and
// never fabricates a path MTU — the gauge keeps its last known value.
// pi-lens-ignore: go-test-functions
func TestMTUSweep_DeadLinkKeepsLastValue(t *testing.T) {
	prober.InitMetrics()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Echo server that stops responding entirely: dead link.
	addr := udpEcho(t, ctx, func(buf []byte, w func([]byte)) {
		// w intentionally never called — link behaves as down.
	})
	reg := prober.NewStatusRegistry()
	cfg := mtuCfg(addr, reg)
	// Give the first sweep room to finish before the next one starts: the
	// three dead-link probes each cost one 300ms timeout, so a 1s sweep
	// interval leaves a comfortable window to observe the exact 3/3 counts
	// without the second sweep polluting them.
	cfg.MTUSweep = time.Second

	runClientAsync(t, ctx, cancel, cfg)
	// First sweep fires immediately: the full-size probe is retried once
	// (2 attempts), then the header-only abort probe runs (1 attempt). All
	// vanish, so ~3 sent and ~3 lost. The counts are asserted as RANGES, not
	// as the exact pair: each dead-link probe costs a full 300ms deadline, so
	// whether the sampler catches the first sweep before the next 1s sweep
	// starts depends on scheduling, and encoding that order is what made this
	// test flaky (repo convention: ±1 under CPU load). What must hold is the
	// 3-probe abort sequence, that no probe on a dead link reads as surviving,
	// and that the gauge stays unknown.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if getCounterValue(prober.MTUProbesLost, "mtu_target", addr) >= 3 &&
			getCounterValue(prober.MTUProbesSent, "mtu_target", addr) >= 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if n := getCounterValue(prober.MTUProbesSent, "mtu_target", addr); n < 3 || n > 5 {
		t.Fatalf("expected the 3-probe dead-link abort sequence (2 full-size attempts + 1 header-only), got %v sent (want 3..5)", n)
	}
	if n := getCounterValue(prober.MTUProbesLost, "mtu_target", addr); n < 3 {
		t.Errorf("every dead-link DF probe must count lost, got %v", n)
	}
	// The gauge must stay unknown across several more samples: a dead link
	// must never fabricate a path MTU.
	for range 10 {
		if got := getGaugeValue(prober.PathMTUBytes, "mtu_target", addr); got != 0 {
			t.Errorf("no surviving probe must leave path_mtu_bytes unknown (0), got %v", got)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestMTUSweep_DeadlineFollowsAdaptiveRTO: on a link whose RTT exceeds the
// configured -timeout, the main loop adapts its RTO upward; the DF sweep must
// wait at least as long as the main loop does. With a static -timeout deadline
// every DF probe times out, path_mtu_bytes stays 0 for the process lifetime,
// and MtuSweepUnresolved mis-reports the path as DF-blocked — on exactly the
// long-haul link class the dynamic RTO floor exists for.
func TestMTUSweep_DeadlineFollowsAdaptiveRTO(t *testing.T) {
	prober.InitMetrics()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 250ms per frame: above the 100ms configured timeout, below the RTO the
	// adaptive loop settles on (its floor is 2*SRTT = 500ms).
	const delay = 250 * time.Millisecond
	addr := udpEcho(t, ctx, func(buf []byte, w func([]byte)) {
		time.Sleep(delay)
		w(buf)
	})

	reg := prober.NewStatusRegistry()
	cfg := prober.Config{
		Source: testSource,
		Targets: []prober.Target{
			{Name: "mtu_adaptive", Address: addr},
		},
		// Interval > delay: the echo responder handles frames serially, so a
		// shorter interval would queue probes and inflate every RTT.
		BaseInterval: 400 * time.Millisecond,
		BaseTimeout:  100 * time.Millisecond,
		Adaptive:     true,
		MTUSweep:     200 * time.Millisecond,
		Status:       reg,
	}
	runClientAsync(t, ctx, cancel, cfg)

	want := float64(prober.PayloadSize + prober.MaxPayloadBytes)
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if getGaugeValue(prober.PathMTUBytes, "mtu_adaptive", addr) == want {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got := getGaugeValue(prober.PathMTUBytes, "mtu_adaptive", addr); got != want {
		rto := getGaugeValue(prober.RTOEstimate, "mtu_adaptive", addr)
		t.Fatalf("path_mtu_bytes must converge once the adaptive RTO (%vs) exceeds the RTT: want %v, got %v — a static -timeout deadline leaves the sweep unable to probe", rto, want, got)
	}
	// Setup guard: the applied RTO really did rise above -timeout, which is
	// what the sweep had to follow for this case to be meaningful.
	if rto := getGaugeValue(prober.RTOEstimate, "mtu_adaptive", addr); rto <= cfg.BaseTimeout.Seconds() {
		t.Fatalf("test setup: applied RTO %vs must exceed -timeout %v", rto, cfg.BaseTimeout.Seconds())
	}
}
