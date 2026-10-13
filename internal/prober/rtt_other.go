//go:build !windows

package prober

// qpcNow is the Windows-only high-resolution RTT clock (see
// rtt_windows.go); on unix the wall clock's nanosecond resolution is the
// measurement basis and no second source is needed.
func qpcNow() (uint64, bool) {
	return 0, false
}

// qpcSeconds is unreachable on unix (qpcNow always reports
// unavailable); returning 0 keeps a hypothetically mismatched pair from
// fabricating an RTT on the wall clock's nanosecond resolution.
func qpcSeconds(delta uint64) float64 {
	return 0
}
