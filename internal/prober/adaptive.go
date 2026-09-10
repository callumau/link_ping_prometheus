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
	// haveSample distinguishes "no RTT measurement yet" from a real 0s
	// sample. The old srtt==0 sentinel made a legitimate sub-nanosecond
	// loopback RTT re-enter the first-sample branch on every Update,
	// pinning SRTT/RTTVAR to the first-sample formula forever.
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
		// Double the EFFECTIVE timeout, not the raw a.rto. The loop applies
		// CurrentRTO(), whose dynamic floor max(DefaultMinRTO, 2*SRTT) can
		// sit above a.rto on a low-SRTT link; doubling only a.rto would
		// leave the floor in charge, so the applied timeout would barely
		// move (a 350ms step would need ~9 timeout batches instead of 2)
		// and a degraded link could never climb back above its real RTT.
		floor := math.Max(DefaultMinRTO.Seconds(), 2*a.srtt)
		a.rto = math.Min(math.Max(a.rto, floor)*2, DefaultMaxRTO.Seconds())
	}
}

// CurrentRTO returns the RTO as a time.Duration. The floor is dynamic:
// max(DefaultMinRTO, 2*SRTT). A fixed floor like 200ms is too tight on links
// whose RTT approaches it (e.g. ~185ms links), causing spurious timeouts and
// loss inflation; flooring at twice the smoothed RTT guarantees the timeout
// always has real headroom over the measured RTT while the 200ms minimum still
// guards LAN links against jitter.
//
// DefaultMaxRTO caps the BACKOFF value, not the floor: on a link whose SRTT
// exceeds 1.5s the applied timeout is 2*SRTT and therefore above 3s. Capping
// the floor would reintroduce exactly the spurious timeouts it exists to
// prevent (a 2s-RTT satellite link), so the floor wins by design —
// link_rto_seconds documents it and RTT samples above the 3s bucket edge land
// in +Inf on such links.
func (a *AdaptiveStats) CurrentRTO() time.Duration {
	floor := math.Max(DefaultMinRTO.Seconds(), 2*a.srtt)
	val := math.Max(math.Min(a.rto, DefaultMaxRTO.Seconds()), floor)
	return time.Duration(val * float64(time.Second))
}

// SRTT returns the smoothed RTT estimate (RFC 6298) for export as the
// link_rtt_srtt_seconds gauge. Zero before the first measurement.
func (a *AdaptiveStats) SRTT() time.Duration {
	return time.Duration(a.srtt * float64(time.Second))
}
