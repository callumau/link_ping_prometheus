package prober

import (
	"math"
	"time"
)

// AdaptiveStats implements RFC 6298-style RTO estimation for TCP probes.
//
// Fields are unexported; use the accessor methods SRTT, RTTVar, and RTO
// to read the current state.
type AdaptiveStats struct {
	srtt                float64
	rttvar              float64
	rto                 float64
	consecutiveTimeouts int
}

// NewAdaptiveStats returns an AdaptiveStats with RTO initialised to
// baseTimeout. SRTT and RTTVAR start at zero and are populated on the
// first Update call.
func NewAdaptiveStats(baseTimeout time.Duration) *AdaptiveStats {
	return &AdaptiveStats{
		srtt:   0.0,
		rttvar: 0.0,
		rto:    baseTimeout.Seconds(),
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
	if a.srtt == 0 {
		a.srtt = rttSeconds
		a.rttvar = rttSeconds / 2
	} else {
		a.rttvar = (1-DefaultBeta)*a.rttvar + DefaultBeta*math.Abs(a.srtt-rttSeconds)
		a.srtt = (1-DefaultAlpha)*a.srtt + DefaultAlpha*rttSeconds
	}
	a.rto = a.srtt + math.Max(DefaultClockGranularity.Seconds(), 4*a.rttvar)
}

// SRTT returns the smoothed round-trip time in seconds.
func (a *AdaptiveStats) SRTT() float64 { return a.srtt }

// RTTVar returns the round-trip time variation in seconds.
func (a *AdaptiveStats) RTTVar() float64 { return a.rttvar }

// RTO returns the current retransmission timeout in seconds (before clamping).
func (a *AdaptiveStats) RTO() float64 { return a.rto }

// Backoff doubles the RTO, clamped to DefaultMaxRTO. Called after
// consecutive timeouts. RFC 6298 applies doubling to retransmitted
// segments so the RTO can adapt up even while no successful measurements
// are arriving (e.g. a latency jump above the current RTO); without it a
// degraded link would never recover from a too-small timeout. The first
// timeout in a series does not double; every subsequent consecutive
// timeout doubles, so a sustained outage can never push RTO beyond the
// clamp.
func (a *AdaptiveStats) Backoff() {
	a.consecutiveTimeouts++
	if a.consecutiveTimeouts > 1 {
		a.rto = math.Min(a.rto*2, DefaultMaxRTO.Seconds())
	}
}

// CurrentRTO returns the clamped RTO as a time.Duration. The floor is
// dynamic: max(DefaultMinRTO, 2*SRTT). A fixed floor like 200ms is too
// tight on links whose RTT approaches it (e.g. ~185ms links), causing
// spurious timeouts and loss inflation; flooring at twice the smoothed
// RTT guarantees the timeout always has real headroom over the measured
// RTT while the 200ms minimum still guards LAN links against jitter.
func (a *AdaptiveStats) CurrentRTO() time.Duration {
	floor := math.Max(DefaultMinRTO.Seconds(), 2*a.srtt)
	val := math.Max(math.Min(a.rto, DefaultMaxRTO.Seconds()), floor)
	return time.Duration(val * float64(time.Second))
}
