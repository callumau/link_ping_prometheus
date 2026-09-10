package prober

import (
	"math"
	"testing"
	"time"
)

// In-package tests: they read the unexported srtt/rttvar/rto fields
// directly, which is why the AdaptiveStats state has no accessor API.

// pi-lens-ignore: go-test-functions
func TestAdaptiveStats_Logic(t *testing.T) {
	stats := NewAdaptiveStats(1 * time.Second)

	if stats.srtt != 0 {
		t.Errorf("Expected initial SRTT 0, got %f", stats.srtt)
	}

	rtt := 0.100
	stats.Update(rtt)
	if math.Abs(stats.srtt-0.1) > 0.0001 {
		t.Errorf("After 1st update: expected SRTT 0.1, got %f", stats.srtt)
	}
	if math.Abs(stats.rttvar-0.05) > 0.0001 {
		t.Errorf("After 1st update: expected RTTVAR 0.05, got %f", stats.rttvar)
	}
	if math.Abs(stats.rto-0.3) > 0.0001 {
		t.Errorf("After 1st update: expected RTO 0.3, got %f", stats.rto)
	}

	stats.Update(0.100)
	if math.Abs(stats.rto-0.25) > 0.0001 {
		t.Errorf("After 2nd update: expected RTO 0.25, got %f", stats.rto)
	}

	stats.Update(0.200)
	if stats.rto <= 0.25 {
		t.Errorf("Expected RTO to increase after spike, got %f", stats.rto)
	}
}

// TestAdaptiveStats_BackoffClampedAndConsecutive: RTO doubling after
// consecutive timeouts is the recovery mechanism that lets the RTO adapt
// up when no successful measurements arrive (RFC 6298). It must double
// only after the first timeout in a series and clamp at DefaultMaxRTO.
// pi-lens-ignore: go-test-functions
func TestAdaptiveStats_BackoffClampedAndConsecutive(t *testing.T) {
	stats := NewAdaptiveStats(1 * time.Second)

	// First timeout in a series must NOT double the RTO (RFC 6298:
	// doubling applies to retransmissions, not the initial timeout).
	stats.Backoff()
	if stats.rto != 1.0 {
		t.Errorf("first backoff must not double RTO, got %f", stats.rto)
	}

	// Subsequent consecutive timeouts double, but never beyond the clamp.
	stats.Backoff()
	if math.Abs(stats.rto-2.0) > 0.0001 {
		t.Errorf("expected RTO 2.0 after second consecutive timeout, got %f", stats.rto)
	}
	stats.Backoff()
	if math.Abs(stats.rto-4.0) > 0.0001 && stats.rto != DefaultMaxRTO.Seconds() {
		t.Errorf("expected RTO 4.0 clamped to DefaultMaxRTO after third consecutive timeout, got %f", stats.rto)
	}

	// Repeated backoffs must saturate at DefaultMaxRTO, not overflow.
	max := DefaultMaxRTO.Seconds()
	for range 200 {
		stats.Backoff()
	}
	if r := stats.CurrentRTO(); r != DefaultMaxRTO {
		t.Errorf("expected RTO clamped to DefaultMaxRTO %v, got %v", DefaultMaxRTO, r)
	}
	if stats.rto != max {
		t.Errorf("expected internal RTO clamped to %f, got %f", max, stats.rto)
	}

	// A successful measurement resets the consecutive-timeout counter.
	stats.Update(0.1)
	stats.Backoff()
	if stats.rto != stats.srtt+4*stats.rttvar {
		t.Errorf("after success, next backoff must not double: got %f", stats.rto)
	}
}

// TestAdaptiveStats_DynamicFloor: the RTO floor must track the smoothed
// RTT (2*SRTT, minimum 200ms) so a link whose RTT approaches a fixed
// floor does not suffer spurious timeouts. A ~150ms link gets ~300ms RTO,
// not 200ms; a quiet LAN stays at the 200ms minimum.
// pi-lens-ignore: go-test-functions
func TestAdaptiveStats_DynamicFloor(t *testing.T) {
	stats := NewAdaptiveStats(10 * time.Millisecond)
	if r := stats.CurrentRTO(); r != DefaultMinRTO {
		t.Errorf("with no measurements the floor is the 200ms minimum, got %v", r)
	}

	stats.Update(0.150)
	for range 25 {
		// pi-lens-ignore: gorm-n-plus-one
		stats.Update(0.150)
	}
	if r := stats.CurrentRTO(); r < 300*time.Millisecond {
		t.Errorf("150ms link must floor RTO at 2*SRTT=300ms, got %v", r)
	}
	if r := stats.CurrentRTO(); r > 450*time.Millisecond {
		t.Errorf("150ms link RTO must stay near the floor, got %v", r)
	}

	stats.Update(0.010)
	for range 25 {
		// pi-lens-ignore: gorm-n-plus-one
		stats.Update(0.010)
	}
	if r := stats.CurrentRTO(); r != DefaultMinRTO {
		t.Errorf("10ms link must fall back to the 200ms minimum, got %v", r)
	}
}

// TestAdaptiveStats_ConvergenceTracksTrueMeanAndFloorHoldsEveryStep:
// feeding a deterministic sample series with a known mean (80ms ±10ms
// alternating), SRTT must converge to the true mean and the clamped RTO
// must respect the dynamic floor max(200ms, 2*SRTT) at EVERY step — a
// floor violation would let the RTO dip below twice the measured RTT
// and fabricate timeouts on exactly the links adaptive mode exists for.
func TestAdaptiveStats_ConvergenceTracksTrueMeanAndFloorHoldsEveryStep(t *testing.T) {
	stats := NewAdaptiveStats(1 * time.Second)

	for i := range 60 {
		sample := 0.070
		if i%2 == 1 {
			sample = 0.090
		}
		stats.Update(sample)

		floor := math.Max(DefaultMinRTO.Seconds(), 2*stats.srtt)
		if r := stats.CurrentRTO().Seconds(); r < floor-1e-9 {
			t.Fatalf("step %d: RTO %v below dynamic floor %v", i, stats.CurrentRTO(), floor)
		}
		if r := stats.CurrentRTO().Seconds(); r > DefaultMaxRTO.Seconds()+1e-9 {
			t.Fatalf("step %d: RTO %v above DefaultMaxRTO", i, stats.CurrentRTO())
		}
	}

	const trueMean = 0.080
	if math.Abs(stats.srtt-trueMean) > 0.003 {
		t.Errorf("SRTT %v failed to converge to true mean %v after 60 samples", stats.srtt, trueMean)
	}
}

// pi-lens-ignore: go-test-functions
func TestAdaptiveStats_RTOFloorAndGranularity(t *testing.T) {
	// Hard floor: even a tiny base timeout must clamp to 200ms.
	stats := NewAdaptiveStats(10 * time.Millisecond)
	if r := stats.CurrentRTO(); r != DefaultMinRTO {
		t.Errorf("expected RTO floored at %v, got %v", DefaultMinRTO, r)
	}

	// RFC 6298: RTO = SRTT + max(G, 4*RTTVAR). On a zero-jitter link
	// RTTVAR decays below G/4, so the clock granularity term takes over.
	stats.Update(0.050)
	for range 25 {
		// pi-lens-ignore: gorm-n-plus-one
		stats.Update(0.050)
	}
	wantG := 0.050 + DefaultClockGranularity.Seconds()
	if math.Abs(stats.rto-wantG) > 0.0005 {
		t.Errorf("expected RTO = SRTT + max(G, 4*RTTVAR) ≈ %f, got %f", wantG, stats.rto)
	}

	// RTTVAR term dominates when jitter is large: 4*RTTVAR > G.
	stats.Update(0.200)
	expect := stats.srtt + 4*stats.rttvar
	if stats.rto < expect-0.0001 {
		t.Errorf("RTO must include 4*RTTVAR term, got %f < %f", stats.rto, expect)
	}
}

// TestAdaptiveStats_ZeroRTTSampleUsesSmoothing: a legitimate 0s RTT
// sample (sub-nanosecond loopback) is a real measurement, not "no sample
// yet". The old srtt==0 sentinel made the first-sample branch re-run
// forever after a 0s reading, so every later estimate was computed with
// the first-sample formula against a bogus baseline. Pinned via
// haveSample.
// pi-lens-ignore: go-test-functions
func TestAdaptiveStats_ZeroRTTSampleUsesSmoothing(t *testing.T) {
	stats := NewAdaptiveStats(time.Second)
	stats.Update(0) // first real sample is 0s
	if !stats.haveSample {
		t.Fatal("a 0s RTT sample must count as a real measurement")
	}
	stats.Update(0)     // must smooth, not re-run the first-sample branch
	stats.Update(0.100) // EWMA from srtt=rttvar=0

	// SRTT = (1-1/8)*0 + (1/8)*0.1 = 0.0125; RTTVAR = (1/4)*|0-0.1| = 0.025.
	if math.Abs(stats.srtt-0.0125) > 1e-9 {
		t.Errorf("0s samples must not re-enter the first-sample branch; SRTT=%f want 0.0125", stats.srtt)
	}
	if math.Abs(stats.rttvar-0.025) > 1e-9 {
		t.Errorf("0s samples must not re-enter the first-sample branch; RTTVAR=%f want 0.025", stats.rttvar)
	}
}

// pi-lens-ignore: go-test-functions
func TestAdaptiveStats_SRTTAccessor(t *testing.T) {
	// SRTT is 0 before the first measurement, then follows the EWMA.
	stats := NewAdaptiveStats(time.Second)
	if s := stats.SRTT(); s != 0 {
		t.Errorf("expected SRTT=0 before first Update, got %v", s)
	}
	stats.Update(0.100)
	if s := stats.SRTT(); s != 100*time.Millisecond {
		t.Errorf("expected SRTT=100ms after first Update, got %v", s)
	}
	stats.Update(0.200)
	// First: SRTT=0.100. Second: SRTT = 0.875*0.100 + 0.125*0.200 = 0.1125.
	// Float64→ns truncation needs a 1µs tolerance, not an exact match.
	if s := stats.SRTT(); math.Abs(s.Seconds()-0.1125) > 1e-6 {
		t.Errorf("expected SRTT=112.5ms after EWMA update, got %v", s)
	}
}

// TestAdaptiveStats_BackoffDoublesTheEffectiveFloor pins the fix for a link
// whose SRTT is far below DefaultMinRTO: Backoff must double the EFFECTIVE
// timeout (the floored one the loop actually applies), not the raw RFC value.
// With a sub-millisecond SRTT the floor owns the timeout, so doubling only
// a.rto leaves the applied value at DefaultMinRTO forever and a latency step
// to 350ms would take ~9 timeout batches to be covered instead of 2.
func TestAdaptiveStats_BackoffDoublesTheEffectiveFloor(t *testing.T) {
	stats := NewAdaptiveStats(1 * time.Millisecond)
	stats.Update(0.0005) // 0.5ms RTT: floor = DefaultMinRTO (200ms)

	if got := stats.CurrentRTO(); got != DefaultMinRTO {
		t.Fatalf("precondition: applied timeout must be the floor %v, got %v", DefaultMinRTO, got)
	}

	// First timeout in a series never doubles (RFC 6298), second one does.
	stats.Backoff()
	if got := stats.CurrentRTO(); got != DefaultMinRTO {
		t.Fatalf("first backoff must not raise the floored timeout, got %v", got)
	}
	stats.Backoff()
	if got, want := stats.CurrentRTO(), 2*DefaultMinRTO; got != want {
		t.Errorf("second backoff must double the EFFECTIVE timeout to %v (raw-rto doubling would leave it at %v), got %v",
			want, DefaultMinRTO, got)
	}
}
