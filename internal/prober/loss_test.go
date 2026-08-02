package prober

import (
	"math"
	"testing"
	"time"
)

// TestLossTracker_Unit exercises the sliding-window ratio math with
// fully injected timestamps — deterministic, no sleeps.
func TestLossTracker_Unit(t *testing.T) {
	base := time.Now()

	// Empty tracker: 0.
	l := newLossTracker()
	if got := l.lossRatio(base); got != 0 {
		t.Errorf("empty tracker: expected 0, got %v", got)
	}

	// Sent only: 0 loss.
	l.addSent(base, 3)
	if got := l.lossRatio(base); got != 0 {
		t.Errorf("sent-only: expected 0, got %v", got)
	}

	// One timeout among three sent: 1/3.
	l.addTimeout(base, 1)
	if got := l.lossRatio(base); math.Abs(got-1.0/3.0) > 1e-9 {
		t.Errorf("mixed: expected 1/3, got %v", got)
	}

	// Full-outage pinning: failed dials record sent+timeout together.
	l2 := newLossTracker()
	t0 := base.Add(time.Hour)
	l2.addSent(t0, 1)
	l2.addTimeout(t0, 1)
	if got := l2.lossRatio(t0); got != 1.0 {
		t.Errorf("outage pinning: expected 1.0, got %v", got)
	}

	// Window purge: events older than the window are dropped entirely.
	l3 := newLossTracker()
	l3.addSent(base, 1)
	l3.addTimeout(base, 1)
	if got := l3.lossRatio(base); got != 1.0 {
		t.Fatalf("pre-purge: expected 1.0, got %v", got)
	}
	if got := l3.lossRatio(base.Add(lossWindow)); got != 0 {
		t.Errorf("post-purge: expected 0, got %v", got)
	}
	if l3.sent != 0 || l3.timeouts != 0 {
		t.Errorf("purge must remove event deltas: sent=%d timeouts=%d", l3.sent, l3.timeouts)
	}

	// Partial purge keeps newer events.
	l4 := newLossTracker()
	l4.addSent(base, 1)
	l4.addTimeout(base, 1)
	l4.addSent(base.Add(time.Minute), 1)
	if got := l4.lossRatio(base.Add(lossWindow)); got != 0 {
		t.Errorf("partial purge: expected 0 (only fresh sent remains), got %v", got)
	}
	if l4.sent != 1 || l4.timeouts != 0 {
		t.Errorf("partial purge kept wrong deltas: sent=%d timeouts=%d", l4.sent, l4.timeouts)
	}

	// Boundary: an event exactly one window old at query time must be
	// purged; anything younger survives.
	l5 := newLossTracker()
	cut := base.Add(lossWindow)
	l5.addSent(cut, 2)
	l5.addTimeout(cut, 1)
	if got := l5.lossRatio(cut); got != 0.5 {
		t.Errorf("fresh event: expected 0.5, got %v", got)
	}
	if got := l5.lossRatio(cut.Add(time.Nanosecond)); got != 0.5 {
		t.Errorf("1ns-old event: expected 0.5, got %v", got)
	}
	if got := l5.lossRatio(cut.Add(lossWindow - time.Nanosecond)); got != 0.5 {
		t.Errorf("window-1ns-old event: expected 0.5, got %v", got)
	}
	if got := l5.lossRatio(cut.Add(lossWindow)); got != 0 {
		t.Errorf("exactly-window-old event must be purged: expected 0, got %v", got)
	}
}
