package prober_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"link_ping_prometheus/internal/prober"
)

// The AdaptiveStats unit tests (SRTT/RTTVAR/RTO math, backoff clamping,
// dynamic floor) live in internal/prober/adaptive_test.go, in-package,
// where they read the unexported fields directly.

func TestAdaptive_RespondsToJitter(t *testing.T) {
	prober.InitMetrics()

	// UDP echo server whose per-probe delay changes mid-test. The client
	// must observe real RTT samples (AdaptiveStats.Update) and raise its
	// RTO when the link latency jumps. (The previous TCP listener never
	// received the UDP probes — every probe timed out and the RTO only
	// grew via backoff, so the test passed without testing adaptation.)
	var delay atomic.Int64
	delay.Store(int64(10 * time.Millisecond))

	// pi-lens-ignore: go-context-background-handler
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr := validatedEcho(t, ctx, func(buf []byte, w func([]byte)) {
		// pi-lens-ignore: go-time-sleep-test
		time.Sleep(time.Duration(delay.Load()))
		w(buf)
	})

	// Interval 200ms > max delay 150ms so the serial echo handler never
	// queues up; every probe is echoed within the client's RTO.
	cfg := cfgWith(true, 200*time.Millisecond, 500*time.Millisecond, prober.Target{Name: "adaptive_jitter", Address: addr})
	go prober.RunClient(ctx, cfg)

	// Low-latency phase: RTO settles on the 200ms floor. If the probes
	// were not being echoed (the old broken state), the RTO would instead
	// have backed off to 2s+ here — the assertion below catches that.
	// pi-lens-ignore: go-time-sleep-test
	time.Sleep(1500 * time.Millisecond)
	rtoLow := getGaugeValue(prober.RTOEstimate, "adaptive_jitter", addr)

	// Link jumps to 150ms: the dynamic floor (2*SRTT) must lift the RTO
	// to ~300ms plus the RTTVAR term.
	delay.Store(int64(150 * time.Millisecond))
	// pi-lens-ignore: go-time-sleep-test
	time.Sleep(3 * time.Second)
	rtoHigh := getGaugeValue(prober.RTOEstimate, "adaptive_jitter", addr)

	t.Logf("RTO Low: %v, RTO High: %v", rtoLow, rtoHigh)

	if rtoLow >= 1.0 {
		t.Errorf("RTO Low %v indicates probes are not being echoed (backoff instead of adaptation); expected ~200ms floor", rtoLow)
	}
	if rtoHigh <= rtoLow {
		t.Errorf("RTO should adapt up with latency: high latency %v should > low latency %v", rtoHigh, rtoLow)
	}
	if rtoHigh < 0.25 {
		t.Errorf("RTO High %v is too low for a 150ms link (floor is 2*SRTT ≈ 300ms)", rtoHigh)
	}
}
