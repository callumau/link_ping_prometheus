package prober

import (
	"math"
	"testing"
	"time"
)

func pow2(e float64) float64 { return math.Pow(2, e) }

// TestBackoff_Unit verifies exponential growth bounds, the cap, jitter
// distribution, and reset semantics.
func TestBackoff_Unit(t *testing.T) {
	base := 100 * time.Millisecond
	max := 10 * time.Second

	b := newBackoff(base, max)

	// Every delay must lie in [0, cap] and the cap must grow
	// exponentially until it hits max, where it stays.
	for i := 0; i < 60; i++ {
		d := b.next()
		capf := float64(base) * pow2(float64(i))
		if capf > float64(max) {
			capf = float64(max)
		}
		if d < 0 || d > time.Duration(capf) {
			t.Fatalf("attempt %d: delay %v outside [0, %v]", i, d, time.Duration(capf))
		}
	}

	// Exponential growth: attempt k+1's cap is double attempt k's until
	// the max kicks in.
	b2 := newBackoff(base, max)
	for i := 1; i < 8; i++ {
		cap := time.Duration(float64(base) * pow2(float64(i)))
		if got := b2.next(); got > cap {
			t.Errorf("attempt %d: delay %v exceeds cap %v", i, got, cap)
		}
	}

	// reset() restarts the schedule at the base cap.
	b3 := newBackoff(base, max)
	b3.attempt = 30
	b3.reset()
	if b3.attempt != 0 {
		t.Errorf("reset must zero the attempt counter, got %d", b3.attempt)
	}

	// Jitter must actually vary: many draws with a constant small cap
	// produce more than one distinct value.
	b4 := newBackoff(1*time.Millisecond, 1*time.Millisecond)
	seen := map[time.Duration]bool{}
	for i := 0; i < 50; i++ {
		seen[b4.next()] = true
	}
	if len(seen) < 2 {
		t.Errorf("full jitter should produce varied delays, got %d distinct", len(seen))
	}
}
