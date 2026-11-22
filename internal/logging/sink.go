package logging

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// EventlogSink is the OS lifecycle-event logger the program and the
// sink watcher write to: the Windows event log under the service
// (svc/eventlog), nil elsewhere, where the fallthrough is stderr.
type EventlogSink interface {
	Info(msg string)
	Error(msg string)
}

// CountedWriter wraps the log sink and records whether any write has
// failed since the last check. Runtime log-sink failures (disk full, log
// directory removed or ACL'd away) are otherwise completely invisible:
// slog's handler discards write errors, the file stops growing, and —
// under the service, where stdout is dead — nothing anywhere records why.
type CountedWriter struct {
	mu    sync.Mutex
	w     io.Writer
	fails int
}

// NewCountedWriter returns a CountedWriter wrapping w.
func NewCountedWriter(w io.Writer) *CountedWriter {
	return &CountedWriter{w: w}
}

// Write forwards p to the underlying writer and tracks consecutive write failures.
func (c *CountedWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.mu.Lock()
	if err != nil {
		c.fails++
	} else {
		c.fails = 0
	}
	c.mu.Unlock()
	return n, err
}

// DrainFailures returns the number of write failures since the previous
// call and clears the streak, so each alert covers exactly one window.
func (c *CountedWriter) DrainFailures() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := c.fails
	c.fails = 0
	return n
}

// SinkCheckInterval is how often the sink watcher looks for log write
// failures. Long enough to stay noise-free; short enough that a fleet
// operator loses at most this window of context when the sink dies.
const SinkCheckInterval = 30 * time.Second

// WatchSink reports accumulated sink write failures on every tick,
// best-effort: to the service event log when one is available (the only
// channel that survives a dead log file under the SCM), to stderr
// otherwise (live console). slog itself cannot be the channel — it writes
// to the very sink that just failed.
func WatchSink(ctx context.Context, sysLog EventlogSink, sink *CountedWriter, every time.Duration) {
	if sink == nil || every <= 0 {
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
			if n := sink.DrainFailures(); n > 0 {
				msg := fmt.Sprintf("log sink write failures: %d writes failed since the last check; the log file may be full, missing, or access-denied", n)
				if sysLog != nil {
					sysLog.Error(msg)
					continue
				}
				fmt.Fprintln(os.Stderr, msg)
			}
		}
	}()
}

// HardenSink enforces the 0600 log invariant regardless of file
// provenance. Logs carry peer IPs and internal topology, so they are never
// world-readable, but os.OpenFile applies its mode only at creation: a file
// placed at the configured path by someone else keeps its wider mode while
// the agent appends topology into it. The Rotator used for rotation
// re-runs this same chain on every rotation (see rotator.go), so a rotated
// artifact cannot be opened by name behind the check. A symlinked path is
// refused outright: it can redirect topology-bearing log lines into a file
// owned by another local user. Fail-closed: the caller exits on error, like
// the allowlist refusal.
//
// Windows: os.OpenFile's 0600 mode, os.Stat (always 0666) and f.Chmod (an
// attribute toggle) are all meaningless for a DACL, so the POSIX enforcement
// below cannot restrict one there — Windows delegates to restrictLogDACL
// (acl_windows.go), which replaces the file's DACL with a protected set
// granting full access only to SYSTEM, Administrators and the account this
// process runs as. The installer's ACL'd log DIRECTORY remains
// defense-in-depth.
func HardenSink(path string) (repaired bool, err error) {
	f, _, repaired, err := OpenFile(path)
	if err != nil {
		return false, err
	}
	if err := f.Close(); err != nil {
		return repaired, err
	}
	return repaired, nil
}
