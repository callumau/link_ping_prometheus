package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"time"
)

// eventlogSink is the OS lifecycle-event logger the program and the
// sink watcher write to: the Windows event log under the service
// (svc/eventlog), nil elsewhere, where the fallthrough is stderr.
type eventlogSink interface {
	Info(msg string)
	Error(msg string)
}

// countedWriter wraps the log sink and records whether any write has
// failed since the last check. Runtime log-sink failures (disk full, log
// directory removed or ACL'd away) are otherwise completely invisible:
// slog's handler discards write errors, the file stops growing, and —
// under the service, where stdout is dead — nothing anywhere records why.
type countedWriter struct {
	mu    sync.Mutex
	w     io.Writer
	fails int
}

func newCountedWriter(w io.Writer) *countedWriter {
	return &countedWriter{w: w}
}

func (c *countedWriter) Write(p []byte) (int, error) {
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

// drainFailures returns the number of write failures since the previous
// call and clears the streak, so each alert covers exactly one window.
func (c *countedWriter) drainFailures() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := c.fails
	c.fails = 0
	return n
}

// sinkCheckInterval is how often the sink watcher looks for log write
// failures. Long enough to stay noise-free; short enough that a fleet
// operator loses at most this window of context when the sink dies.
const sinkCheckInterval = 30 * time.Second

// watchLogSink reports accumulated sink write failures on every tick,
// best-effort: to the service event log when one is available (the only
// channel that survives a dead log file under the SCM), to stderr
// otherwise (live console). slog itself cannot be the channel — it writes
// to the very sink that just failed.
func watchLogSink(ctx context.Context, sysLog eventlogSink, sink *countedWriter, every time.Duration) {
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
			if n := sink.drainFailures(); n > 0 {
				// pi-lens-ignore: go-no-fmt-println
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

// hardenLogSink enforces the 0600 log invariant regardless of file
// provenance. Logs carry peer IPs and internal topology, so they are never
// world-readable, but os.OpenFile applies its mode only at creation: a file
// placed at the configured path by someone else keeps its wider mode while
// the agent appends topology into it, and the lumberjack writer opens the
// existing file with no mode check and copies the live file's mode onto
// every rotated artifact — so repairing the live file at startup also
// protects future rotations. A symlinked path is refused outright: it can
// redirect topology-bearing log lines into a file owned by another local
// user. Fail-closed: the caller exits on error, like the allowlist refusal.
// Windows: os.OpenFile's 0600 mode, os.Stat (always 0666) and f.Chmod (an
// attribute toggle) are all meaningless for a DACL, so the POSIX enforcement
// below cannot restrict one there — Windows delegates to restrictLogDACL
// (logacl_windows.go), which replaces the file's DACL with a protected set
// granting full access only to SYSTEM, Administrators and the account this
// process runs as. The installer's ACL'd log DIRECTORY remains
// defense-in-depth: log rotation creates fresh files that inherit the
// directory's DACL, and restricting those on the fly would add a rotation
// path to hardenLogSink.
func hardenLogSink(path string) (repaired bool, err error) {
	fi, err := os.Lstat(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
		// Not there yet: create it at the enforced mode so the lumberjack
		// path finds an existing 0600 file (its rotation copies the current
		// file's mode onto artifacts).
		// pi-lens-ignore: go-path-traversal (operator-supplied -log-file path)
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return false, err
		}
		if runtime.GOOS == "windows" {
			// A fresh file inherits its parent directory's DACL, which may be
			// wide (a manual install pointing -log-file into a Users-writable
			// directory); restrict it now so the repair path does not have to
			// wait for the next start.
			defer f.Close()
			return restrictLogDACL(f)
		}
		return false, f.Close()
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("refusing symlinked log path %q: a symlink can redirect topology-bearing log lines into another local user's file; create the log path directly", path)
	}
	// Open the file we Lstat'ed (no O_CREATE: it exists) and repair its mode
	// on the open descriptor, not by path, so the chmod lands on what we
	// verified.
	// pi-lens-ignore: go-path-traversal (operator-supplied -log-file path)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return false, err
	}
	defer f.Close()
	got, err := f.Stat()
	if err != nil {
		return false, err
	}
	if runtime.GOOS == "windows" {
		// os.Stat always reports 0666 on Windows, so the perm-bit comparison
		// is meaningless there: restrictLogDACL reads the actual DACL of the
		// open descriptor, compares it against the restricted set it pins,
		// and only rewrites it when it differs (repaired=false for an
		// already-compliant file).
		return restrictLogDACL(f)
	}
	if got.Mode().Perm() != 0o600 {
		if err := f.Chmod(0o600); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}
