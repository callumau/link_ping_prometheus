package prober_test

import (
	"context"
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

	// First sweep fires immediately: probes sent, none survive. Wait on
	// lost (not sent) so the two early-abort probes have both timed out.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if getCounterValue(prober.MTUProbesLost, "mtu_target", addr) >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if n := getCounterValue(prober.MTUProbesSent, "mtu_target", addr); n < 2 {
		t.Fatalf("expected >=2 MTU probes attempted, got %v", n)
	}
	if n := getCounterValue(prober.MTUProbesLost, "mtu_target", addr); n < 2 {
		t.Errorf("failed DF probes must count lost, got %v", n)
	}
	if got := getGaugeValue(prober.PathMTUBytes, "mtu_target", addr); got != 0 {
		t.Errorf("no surviving probe must leave path_mtu_bytes unknown (0), got %v", got)
	}
}
