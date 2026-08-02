package prober

import "time"

// lossWindow matches the RTT summary's 10-minute MaxAge so the loss
// gauge and the RTT percentiles describe the same window.
const lossWindow = 10 * time.Minute

// lossEvent records a probe outcome (sent or timed out) at a point in
// time. Entries older than lossWindow are dropped on read.
type lossEvent struct {
	at       time.Time
	sent     int
	timeouts int
}

// lossTracker computes the packet loss percentage over a sliding
// 10-minute window from event deltas, so the gauge is independent of
// counter resets and connection drops. Used from the single probe
// goroutine of one target; not safe for concurrent use.
type lossTracker struct {
	events   []lossEvent
	sent     int
	timeouts int
}

func newLossTracker() *lossTracker {
	return &lossTracker{events: make([]lossEvent, 0, 256)}
}

// addSent records n probes written to the wire.
func (l *lossTracker) addSent(at time.Time, n int) {
	l.events = append(l.events, lossEvent{at: at, sent: n})
	l.sent += n
}

// addTimeout records n probes that timed out.
func (l *lossTracker) addTimeout(at time.Time, n int) {
	l.events = append(l.events, lossEvent{at: at, timeouts: n})
	l.timeouts += n
}

// lossPercent purges events older than the window and returns the
// percentage of timed-out probes in the remaining window. Returns 0
// when no probes were sent in the window.
func (l *lossTracker) lossPercent(at time.Time) float64 {
	cutoff := at.Add(-lossWindow)
	i := 0
	for i < len(l.events) && l.events[i].at.Before(cutoff) {
		l.sent -= l.events[i].sent
		l.timeouts -= l.events[i].timeouts
		i++
	}
	if i > 0 {
		l.events = append(l.events[:0], l.events[i:]...)
	}
	if l.sent == 0 {
		return 0
	}
	return float64(l.timeouts) / float64(l.sent) * 100
}
