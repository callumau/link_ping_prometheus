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

// lossTracker computes the link loss ratio over a sliding 10-minute
// window from event deltas, so the gauge is independent of counter
// resets and connection drops. Failed connection attempts are recorded
// as both sent and timed out, pinning the ratio to 1.0 during a full
// outage. Used from the single probe goroutine of one target; not safe
// for concurrent use.
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

// lossRatio purges events older than the window and returns the
// ratio of lost probe attempts in the remaining window (0.0-1.0).
// Returns 0 when no probe attempts were made in the window.
func (l *lossTracker) lossRatio(at time.Time) float64 {
	cutoff := at.Add(-lossWindow)
	i := 0
	// Purge events at least one window old (inclusive of the cutoff:
	// an event exactly `lossWindow` old must not be counted).
	for i < len(l.events) && !l.events[i].at.After(cutoff) {
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
	return float64(l.timeouts) / float64(l.sent)
}
