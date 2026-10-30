package main

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"runtime/debug"
	"time"
)

// minScavengeUnreleased is the amount of idle heap the runtime must still be
// holding beyond what it already returned to the OS before a scavenge is worth
// its stop-the-world-adjacent cost. An already-lean process must pay nothing.
// It is a byte count, not a duration.
const minScavengeUnreleased = 4 << 20

// minScavengeInterval is the smallest accepted -mem-scavenge interval. Every
// tick is a stop-the-world runtime.ReadMemStats plus, above the releasable
// threshold, a debug.FreeOSMemory, in a process whose whole job is measuring
// RTT — a 1ms interval turns the latency it exports into GC pauses. Rejected at
// the flag boundary rather than clamped inside startHeapScavenger, so the
// scavenger loop stays a pure primitive its own test drives directly.
const minScavengeInterval = 100 * time.Millisecond

// releasableHeap returns the idle heap bytes a scavenge could actually return
// to the OS, i.e. HeapIdle minus what has already been released. Deliberately
// NOT Sys-HeapReleased: Sys covers the whole process and stays far above any
// sane threshold for as long as the agent runs, which made the "skip an
// already-lean process" guard a no-op that scavenged on every tick. Clamped at
// 0: HeapReleased can transiently exceed HeapIdle, and an unsigned subtraction
// would otherwise wrap to an enormous value and force a scavenge every tick.
func releasableHeap(m runtime.MemStats) uint64 {
	if m.HeapIdle <= m.HeapReleased {
		return 0
	}
	return m.HeapIdle - m.HeapReleased
}

// shouldScavenge reports whether the process holds at least minUnreleased
// unreleased idle heap bytes.
func shouldScavenge(m runtime.MemStats, minUnreleased uint64) bool {
	return releasableHeap(m) >= minUnreleased
}

// validateScavengeInterval enforces the -mem-scavenge floor (see
// minScavengeInterval). 0 keeps meaning "disabled"; only a nonzero interval
// below the floor is refused.
func validateScavengeInterval(every time.Duration) error {
	if every <= 0 || every >= minScavengeInterval {
		return nil
	}
	return fmt.Errorf("-mem-scavenge %v is too small: each scavenge is a stop-the-world runtime.ReadMemStats (plus debug.FreeOSMemory above the releasable threshold), so an interval this small would distort the RTT/loss this agent exists to measure; use 0 to disable or a value >= %v", every, minScavengeInterval)
}

// startHeapScavenger returns the unused heap high-water mark to the OS on a
// fixed interval. The runtime scavenges in proportion to the allocation rate,
// so a scrape-driven high-water mark survives indefinitely while the agent is
// idle — visible on Windows as steady commit/RSS growth. every <= 0 disables
// it. The goroutine exits with ctx so it stops on shutdown in every mode.
func startHeapScavenger(ctx context.Context, every time.Duration, minUnreleased uint64, logger *slog.Logger) {
	if every <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(every)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			var before runtime.MemStats
			runtime.ReadMemStats(&before)
			if !shouldScavenge(before, minUnreleased) {
				continue
			}
			debug.FreeOSMemory()
			var after runtime.MemStats
			runtime.ReadMemStats(&after)
			logger.Debug("heap scavenge",
				"releasable_before_mb", releasableHeap(before)>>20,
				"idle_before_mb", before.HeapIdle>>20, "released_before_mb", before.HeapReleased>>20,
				"idle_after_mb", after.HeapIdle>>20, "released_after_mb", after.HeapReleased>>20)
		}
	}()
}
