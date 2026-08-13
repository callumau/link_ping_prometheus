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
	for i := 0; i < 200; i++ {
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
	for i := 0; i < 25; i++ {
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
	for i := 0; i < 25; i++ {
		// pi-lens-ignore: gorm-n-plus-one
		stats.Update(0.010)
	}
	if r := stats.CurrentRTO(); r != DefaultMinRTO {
		t.Errorf("10ms link must fall back to the 200ms minimum, got %v", r)
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
	for i := 0; i < 25; i++ {
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
