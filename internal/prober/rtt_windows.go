//go:build windows

package prober

import (
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// rttClock provides the high-resolution source the RTT computation uses
// on Windows. Go's time.Now() on Windows derives from the interrupt time
// (observed on windows-latest: two successive calls inside one scheduler
// tick return IDENTICAL UnixNano values), so a sub-quantum link's RTT
// computes as 0 ns exactly - SRTT sticks to 0, RTO sits at its floor,
// and reported RTT/jitter for fast links are quantization noise. The
// kernel's QueryPerformanceCounter has ~100ns granularity, is
// monotonic, and is the canonical Windows measurement clock; both
// readings (worst case) still cost far less than the send path's other
// work. x/sys/windows does not bind these two syscalls, so the lazy
// system-dll pattern binds them directly.
type rttClock struct {
	once sync.Once
	freq float64
}

var (
	modqpc                        = windows.NewLazySystemDLL("kernel32.dll")
	procQueryPerformanceCounter   = modqpc.NewProc("QueryPerformanceCounter")
	procQueryPerformanceFrequency = modqpc.NewProc("QueryPerformanceFrequency")
)

var qpc rttClock

// qpcNow returns (counter, true) when the high-resolution clock is
// available, else (0, false); callers fall back to the wall clock.
func qpcNow() (uint64, bool) {
	qpc.once.Do(func() {
		var f int64
		r1, _, _ := procQueryPerformanceFrequency.Call(uintptr(unsafe.Pointer(&f)))
		if r1 == 0 || f <= 0 {
			return
		}
		qpc.freq = float64(f)
	})
	if qpc.freq == 0 {
		return 0, false
	}
	var v int64
	r1, _, _ := procQueryPerformanceCounter.Call(uintptr(unsafe.Pointer(&v)))
	if r1 == 0 {
		return 0, false
	}
	return uint64(v), true
}

// qpcSeconds converts a counter delta to seconds using the cached
// frequency (both values originate from qpcNow()).
func qpcSeconds(delta uint64) float64 {
	return float64(delta) / qpc.freq
}
