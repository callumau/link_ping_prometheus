package prober

import (
	"math"
	"math/rand/v2"
	"time"
)

const (
	// DefaultBackoffBase is the initial reconnection delay.
	DefaultBackoffBase = 100 * time.Millisecond
	// DefaultBackoffMax caps the delay between reconnection attempts.
	DefaultBackoffMax = 10 * time.Second
)

// backoff implements exponential backoff with full jitter for
// reconnection attempts: each next() returns a random delay drawn
// uniformly from [0, min(max, base * 2^attempt)]. Attempts reset via
// reset() once a connection is established. Not safe for concurrent
// use; each probe target owns one instance.
type backoff struct {
	base    time.Duration
	max     time.Duration
	attempt int
}

func newBackoff(base, max time.Duration) *backoff {
	return &backoff{base: base, max: max}
}

// next returns the delay for the next reconnection attempt and
// advances the attempt counter. The random component (full jitter)
// prevents retry storms: colliding probers retry at scattered times
// instead of hammering in lockstep.
func (b *backoff) next() time.Duration {
	cap := float64(b.base) * math.Pow(2, float64(b.attempt))
	if cap > float64(b.max) {
		cap = float64(b.max)
	}
	b.attempt++
	if b.attempt > 40 {
		// Guard against attempt overflow; the cap is already at max.
		b.attempt = 40
	}
	return time.Duration(rand.Float64() * cap)
}

// reset restarts the backoff schedule after a successful connection.
func (b *backoff) reset() {
	b.attempt = 0
}
