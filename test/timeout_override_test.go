package prober_test

import (
	"context"
	"testing"
	"time"

	"link_ping_prometheus/internal/prober"
)

// TestPerTargetTimeoutDrivesProbeDeadline pins that a target's Timeout
// override — not just the global BaseTimeout — governs the runtime probe
// deadline. Two targets run under the same global 1s timeout: target A
// overrides it to 100ms and its echo replies only after 700ms, so every
// probe must read as loss with no RTT sample; target B keeps the 1s timeout
// against an immediate echo and must stay lossless with samples
// accumulating. The two echoes live on separate servers so A's slow handler
// cannot delay B's replies (udpEcho handlers run serially).
//
// The slow echo must sleep LONGER than the 500ms probe interval, not merely
// longer than the 100ms timeout: runEchoLoop drains buffered responses
// before the per-tick timeout sweep, so a reply landing inside the interval
// is accepted as an RTT sample even when it outran the timeout. Only a reply
// arriving after the tick that already timed the probe out is discarded.
// Tightening this delay back below the interval would silently re-break the
// test (A would post RTT samples and no timeouts).
func TestPerTargetTimeoutDrivesProbeDeadline(t *testing.T) {
	prober.InitMetrics()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	slowAddr := validatedEcho(t, ctx, func(buf []byte, w func([]byte)) {
		// > probe interval, so the probe is timed out at the 500ms tick
		// before this reply lands (see the test docstring).
		// pi-lens-ignore: go-time-sleep-test
		time.Sleep(700 * time.Millisecond)
		w(buf)
	})
	fastAddr := startEchoServer(ctx, t)

	const nameSlow, nameFast = "slow_timeout", "fast_timeout"

	cfg := cfgWith(false, 500*time.Millisecond, time.Second,
		prober.Target{Name: nameSlow, Address: slowAddr, Timeout: 100 * time.Millisecond},
		prober.Target{Name: nameFast, Address: fastAddr, Timeout: time.Second},
	)
	runClientSettle(ctx, cancel, cfg, 2500*time.Millisecond)

	slowRTT := getHistogramCount(prober.RTTSeconds, nameSlow, slowAddr)
	slowTimedOut := getCounterValue(prober.ProbesTimedOut, nameSlow, slowAddr)
	fastRTT := getHistogramCount(prober.RTTSeconds, nameFast, fastAddr)
	fastTimedOut := getCounterValue(prober.ProbesTimedOut, nameFast, fastAddr)

	if slowTimedOut == 0 {
		t.Errorf("target with Timeout=100ms against a 700ms echo must record timeouts, got %v", slowTimedOut)
	}
	if slowRTT != 0 {
		t.Errorf("target with Timeout=100ms against a 700ms echo must record no RTT samples, got %v", slowRTT)
	}
	if fastTimedOut != 0 {
		t.Errorf("target with Timeout=1s against an immediate echo must not time out, got %v", fastTimedOut)
	}
	if fastRTT <= 2 {
		t.Errorf("target with Timeout=1s against an immediate echo must record >2 RTT samples, got %v", fastRTT)
	}
}
