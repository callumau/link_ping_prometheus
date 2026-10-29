package prober

import (
	"math"
	"testing"
	"time"
)

// TestRTTSeconds_Positive: the normal path — both instants carry the
// monotonic reading, so the RTT is their difference and no QPC source is
// available (unix) or needed.
// pi-lens-ignore: go-test-functions
func TestRTTSeconds_Positive(t *testing.T) {
	sentAt := time.Now()
	recvAt := sentAt.Add(37 * time.Millisecond)

	got, ok := rttSeconds(sentAt, recvAt, 0, 0)
	if !ok {
		t.Fatal("a forward-ordered pair must yield a sample")
	}
	if math.Abs(got-0.037) > 1e-9 {
		t.Errorf("rttSeconds = %v, want 0.037", got)
	}

	// Zero delta is a real sample (sub-quantum loopback), not "unmeasurable":
	// AdaptiveStats has a haveSample flag precisely so a 0s reading is
	// smoothed rather than re-entering the first-sample branch.
	if got, ok := rttSeconds(sentAt, sentAt, 0, 0); !ok || got != 0 {
		t.Errorf("a zero delta must be a valid 0s sample, got %v ok=%v", got, ok)
	}
}

// TestRTTSeconds_NegativeIsNotASample pins the failure this replaces: the old
// UnixNano subtraction produced a NEGATIVE RTT when the wall clock stepped
// backwards between send and receive (VM snapshot restore, NTP step, manual
// `date`). Observing it decrements link_rtt_seconds_sum and drives
// AdaptiveStats negative, which collapses the RTO floor to its minimum.
func TestRTTSeconds_NegativeIsNotASample(t *testing.T) {
	sentAt := time.Now()
	recvAt := sentAt.Add(-5 * time.Millisecond) // clock stepped back while in flight

	got, ok := rttSeconds(sentAt, recvAt, 0, 0)
	if ok {
		t.Fatalf("a receive instant before the send instant must not yield a sample, got %v", got)
	}
	if got != 0 {
		t.Errorf("the rejected sample must be 0 (never negative), got %v", got)
	}
}

// TestRTTSeconds_QPCPreferred: when both sides carry a QueryPerformanceCounter
// reading it wins over the wall clock — Go's time.Now() is interrupt-time
// quantized on Windows, so a sub-quantum link computes as exactly 0ns there and
// SRTT sticks at 0. The wall-clock delta here is deliberately bogus so the
// preference is observable.
func TestRTTSeconds_QPCPreferred(t *testing.T) {
	sentAt := time.Now()
	recvAt := sentAt.Add(100 * time.Millisecond)
	// qpcSeconds is only meaningful on Windows (0 elsewhere, by design, see
	// rtt_other.go); assert the PREFERENCE rather than a platform-specific
	// value so this test pins the same rule on both.
	got, ok := rttSeconds(sentAt, recvAt, 1, 2)
	if !ok {
		t.Fatal("a qpc pair must be accepted")
	}
	if want := qpcSeconds(1); got != want {
		t.Errorf("qpc pair must win over the (bogus) wall-clock delta 100ms: got %v, want %v", got, want)
	}

	// A counter pair that runs BACKWARDS must fall back to the wall clock
	// rather than underflow uint64 into a multi-decade RTT.
	got, ok = rttSeconds(sentAt, recvAt, 2, 1)
	if !ok {
		t.Fatal("wall clock must still be usable when the qpc pair is rejected")
	}
	if math.Abs(got-0.100) > 1e-9 {
		t.Errorf("a backwards qpc pair must fall back to the wall clock (0.1), got %v", got)
	}
}

// TestProbeExpired: the sweep predicate. Normal expiry, the strictly-greater
// boundary (the documented loss deadline is the first tick AFTER the RTO), and
// — the fix — a FUTURE send instant. A future sentAt is what a backwards clock
// step leaves in the pending map; the old `nowNS-st.sentNS > timeout` test never
// matched it, so those entries accumulated until maxPendingWindow throttled
// every send (nothing probed while link_up stayed 1).
// pi-lens-ignore: go-test-functions
func TestProbeExpired(t *testing.T) {
	now := time.Now()
	timeout := 300 * time.Millisecond

	cases := []struct {
		name   string
		sentAt time.Time
		want   bool
	}{
		{"in flight, well inside the timeout", now.Add(-50 * time.Millisecond), false},
		{"exactly at the timeout", now.Add(-timeout), false},
		{"one nanosecond past the timeout", now.Add(-timeout - time.Nanosecond), true},
		{"future send instant (clock stepped back)", now.Add(5 * time.Minute), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := probeExpired(now, tc.sentAt, timeout); got != tc.want {
				t.Errorf("probeExpired(now, now%+v, %v) = %v, want %v", tc.sentAt.Sub(now), timeout, got, tc.want)
			}
		})
	}
}
