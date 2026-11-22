package prober

import (
	"math"
	"time"
)

// AdaptiveStats implements RFC 6298-style RTO estimation for probe RTTs.
type AdaptiveStats struct {
	srtt                float64
	rttvar              float64
	rto                 float64
	consecutiveTimeouts int
	// seed is the configured -timeout; DefaultMaxRTO caps backoff growth, never the seed itself.
	seed time.Duration
	// haveSample distinguishes "no RTT yet" from a legitimate 0s loopback RTT.
	haveSample bool
}

// NewAdaptiveStats returns an AdaptiveStats with RTO initialised to
// baseTimeout. SRTT and RTTVAR start at zero and are populated on the
// first Update call.
func NewAdaptiveStats(baseTimeout time.Duration) *AdaptiveStats {
	return &AdaptiveStats{
		srtt:   0.0,
		rttvar: 0.0,
		rto:    baseTimeout.Seconds(),
		seed:   baseTimeout,
	}
}

// Update incorporates a new RTT measurement using RFC 6298 smoothing:
//   - First measurement sets SRTT = R, RTTVAR = R/2.
//   - Subsequent measurements apply exponential weighted moving average
//     with gain DefaultAlpha (1/8) for SRTT and DefaultBeta (1/4) for RTTVAR.
//   - RTO = SRTT + max(G, 4 × RTTVAR), where G is the clock granularity
//     of the RTT measurement (RFC 6298 section 2.4).
func (a *AdaptiveStats) Update(rttSeconds float64) {
	a.consecutiveTimeouts = 0
	if !a.haveSample {
		a.srtt = rttSeconds
		a.rttvar = rttSeconds / 2
		a.haveSample = true
	} else {
		a.rttvar = (1-DefaultBeta)*a.rttvar + DefaultBeta*math.Abs(a.srtt-rttSeconds)
		a.srtt = (1-DefaultAlpha)*a.srtt + DefaultAlpha*rttSeconds
	}
	a.rto = a.srtt + math.Max(DefaultClockGranularity.Seconds(), 4*a.rttvar)
}

// Backoff doubles the effective RTO on consecutive timeouts (from the 2nd
// timeout onward), clamped to maxRTO().
func (a *AdaptiveStats) Backoff() {
	a.consecutiveTimeouts++
	if a.consecutiveTimeouts > 1 {
		// Double the effective timeout (including the 2*SRTT floor) so a
		// step increase in link RTT climbs above the real RTT in minimal steps.
		floor := math.Max(DefaultMinRTO.Seconds(), 2*a.srtt)
		a.rto = math.Min(math.Max(a.rto, floor)*2, a.maxRTO())
	}
}

// maxRTO returns the backoff ceiling: max(DefaultMaxRTO, configured -timeout).
func (a *AdaptiveStats) maxRTO() float64 {
	if seed := a.seed.Seconds(); seed > DefaultMaxRTO.Seconds() {
		return seed
	}
	return DefaultMaxRTO.Seconds()
}

// maxAppliedRTOSec caps the applied RTO at 24h to keep Duration conversion within int64.
const maxAppliedRTOSec = 24 * 60 * 60

// CurrentRTO returns the effective RTO: max(DefaultMinRTO, 2*SRTT, min(rto, maxRTO)).
// The 2*SRTT floor is uncapped by DefaultMaxRTO so high-RTT links (SRTT > 1.5s)
// are not falsely timed out.
func (a *AdaptiveStats) CurrentRTO() time.Duration {
	floor := math.Max(DefaultMinRTO.Seconds(), 2*a.srtt)
	val := math.Max(math.Min(a.rto, a.maxRTO()), floor)
	if val > maxAppliedRTOSec {
		val = maxAppliedRTOSec
	}
	return time.Duration(val * float64(time.Second))
}

// SRTT returns the smoothed RTT estimate (RFC 6298) for export as the
// link_rtt_srtt_seconds gauge. Zero before the first measurement.
func (a *AdaptiveStats) SRTT() time.Duration {
	return time.Duration(a.srtt * float64(time.Second))
}
