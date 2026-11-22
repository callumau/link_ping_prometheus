package service

import (
	"context"
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
			if logger.Enabled(ctx, slog.LevelDebug) {
				var after runtime.MemStats
				runtime.ReadMemStats(&after)
				logger.Debug("heap scavenge",
					"releasable_before_mb", releasableHeap(before)>>20,
					"idle_before_mb", before.HeapIdle>>20, "released_before_mb", before.HeapReleased>>20,
					"idle_after_mb", after.HeapIdle>>20, "released_after_mb", after.HeapReleased>>20)
			}
		}
	}()
}
