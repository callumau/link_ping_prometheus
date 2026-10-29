package prober

import (
	"testing"
	"time"
)

// checkPendingWindow must not compute maxPendingWindow*interval: that product
// overflows int64 once interval passes ~106 days (1000 x 292 years of
// nanoseconds), turning the bound into a wrapped nonsense value that rejected
// configurations it never reasoned about. The comparison is now a division,
// which is exactly equivalent for every value a Duration can hold.
func TestCheckPendingWindow(t *testing.T) {
	cases := []struct {
		name     string
		interval time.Duration
		timeout  time.Duration
		wantErr  bool
	}{
		{"typical 500ms interval, 1s timeout", 500 * time.Millisecond, time.Second, false},
		{"200ms interval, 3s adaptive ceiling", 200 * time.Millisecond, 3 * time.Second, false},
		{"window at exactly 1000x is accepted", 3 * time.Hour, 3000 * time.Hour, false},
		{"window one nanosecond past 1000x is rejected", 3 * time.Hour, 3000*time.Hour + time.Nanosecond, true},
		{"1ms interval with a 1m timeout is rejected", time.Millisecond, time.Minute, true},
		// 1000*8760h overflows int64; the old multiply form rejected this
		// (tiny-window) pair outright.
		{"absurd 8760h interval with a 24h timeout", 8760 * time.Hour, 24 * time.Hour, false},
		// Values either side of the ~106-day overflow threshold, both with a
		// window far inside the cap.
		{"2600h interval, just past the overflow threshold", 2600 * time.Hour, time.Second, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkPendingWindow(tc.interval, tc.timeout)
			if tc.wantErr && err == nil {
				t.Fatalf("interval %v with timeout %v must be rejected", tc.interval, tc.timeout)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("interval %v with timeout %v must be accepted, got %v", tc.interval, tc.timeout, err)
			}
		})
	}

	// Degenerate inputs keep failing open (they are rejected earlier by
	// Config.Validate, which owns the positivity rules).
	for _, tc := range []struct{ interval, timeout time.Duration }{
		{0, time.Second},
		{-time.Second, time.Second},
		{time.Second, 0},
	} {
		if err := checkPendingWindow(tc.interval, tc.timeout); err != nil {
			t.Errorf("interval %v timeout %v must pass the window check, got %v", tc.interval, tc.timeout, err)
		}
	}
}
