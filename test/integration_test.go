package prober_test

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"link_ping_prometheus/internal/prober"
)

// TestMultiTargetProbing runs ten targets at once and asserts every one
// sent probes and received RTT samples. Ten concurrent targets IS the
// scale claim; the former TestStress_ManyTargets only repeated it with a
// weaker "sent >= 5" assertion.
func TestMultiTargetProbing(t *testing.T) {
	prober.InitMetrics()

	ctx := t.Context()
	const count = 10

	targets := make([]prober.Target, 0, count)
	for i := range count {
		targets = append(targets, prober.Target{
			Name:    fmt.Sprintf("target_%d", i),
			Address: startEchoServer(ctx, t),
		})
	}

	cfg := cfgWith(false, 50*time.Millisecond, 500*time.Millisecond, targets...)
	go prober.RunClient(ctx, cfg)

	// pi-lens-ignore: go-time-sleep-test
	time.Sleep(time.Second)

	for _, tg := range targets {
		// ~20 probes are expected in 1s at a 50ms interval; requiring 5
		// keeps the old stress test's floor (a regression that stalls most
		// targets cannot pass on one lucky send) while the RTT assertion
		// proves the echoes actually returned.
		if sent := getCounterValue(prober.ProbesSent, tg.Name, tg.Address); sent < 5 {
			t.Errorf("target %s sent %v probes, want >= 5 (cpu load?)", tg.Name, sent)
		}
		verifyHistogramCount(t, prober.RTTSeconds, tg.Name, tg.Address)
	}
}

// TestServerDropout: a remote that stops echoing must show up as real
// timeouts — UDP has no retransmission to hide it. The echo responder
// stays up and stops replying, which is the one behaviour the outage
// tests (a dead peer) do not cover.
func TestServerDropout(t *testing.T) {
	prober.InitMetrics()

	ctx := t.Context()
	var echoOn atomic.Bool
	echoOn.Store(true)
	addr := validatedEcho(t, ctx, func(buf []byte, w func([]byte)) {
		if echoOn.Load() {
			w(buf)
		}
	})

	targetName := "dropout_test"
	cfg := cfgWith(false, 50*time.Millisecond, 300*time.Millisecond, prober.Target{Name: targetName, Address: addr})

	initialTimeouts := getCounterValue(prober.ProbesTimedOut, targetName, addr)

	go prober.RunClient(ctx, cfg)

	// Let the link establish, then stop echoing.
	// pi-lens-ignore: go-time-sleep-test
	time.Sleep(200 * time.Millisecond)
	echoOn.Store(false)
	// Probes now go unanswered and must time out after the 300ms RTO.
	// pi-lens-ignore: go-time-sleep-test
	time.Sleep(500 * time.Millisecond)

	finalTimeouts := getCounterValue(prober.ProbesTimedOut, targetName, addr)
	if diff := finalTimeouts - initialTimeouts; diff == 0 {
		t.Errorf("expected timeouts to increase after dropout, got 0 increase")
	}
}
