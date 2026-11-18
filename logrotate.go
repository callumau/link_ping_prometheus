package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// logRotator is the -log-file writer used when -log-file-max-mb is nonzero.
//
// It exists because a rotation must not become a provenance bypass: the
// previous rotating writer re-opened the configured path BY NAME (os.OpenFile with O_CREATE|O_APPEND and
// no O_NOFOLLOW), so a local user with write access to the log directory could
// swap a symlink in after hardenLogSink's startup check (or in the
// rename-to-create gap of a rotation) and receive the whole topology-bearing
// log stream. Every open here — initial and after each rotation — goes through
// the same verified chain (non-symlink, regular, O_NOFOLLOW|O_NONBLOCK,
// SameFile, owner, 0600/DACL), and the fresh file is created O_EXCL so a
// raced-in object is refused rather than adopted.
//
// Rotation policy deliberately mirrors the previous writer: rotate at
// -log-file-max-mb, keep -log-file-max-backups, drop artifacts older than
// -log-file-max-age. Compression stays disabled (it was disabled before).
type logRotator struct {
	mu         sync.Mutex
	path       string
	maxBytes   int64
	maxBackups int
	maxAge     time.Duration
	f          *os.File
	size       int64
	// now is a seam for tests; zero means time.Now.
	now func() time.Time
}

// newLogRotator opens (creating if needed) the log path with the verified
// chain and returns a writer that rotates it.
func newLogRotator(path string, maxMB, maxBackups, maxAgeDays int) (*logRotator, error) {
	f, size, _, err := openOrCreateLogFile(path)
	if err != nil {
		return nil, err
	}
	r := &logRotator{
		path:       path,
		maxBytes:   int64(maxMB) << 20,
		maxBackups: maxBackups,
		f:          f,
		size:       size,
	}
	if maxAgeDays > 0 {
		r.maxAge = time.Duration(maxAgeDays) * 24 * time.Hour
	}
	return r, nil
}

func (r *logRotator) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// Write appends p, rotating first when the file has reached its size bound.
// Rotation happens before the write so a single oversized record does not
// stay stranded in an over-limit file.
func (r *logRotator) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return 0, os.ErrClosed
	}
	if r.maxBytes > 0 && r.size > 0 && r.size+int64(len(p)) > r.maxBytes {
		if err := r.rotateLocked(); err != nil {
			return 0, err
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *logRotator) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}

// rotateLocked renames the live file aside and opens a fresh verified one.
// The caller holds r.mu.
func (r *logRotator) rotateLocked() error {
	clock := r.clock()
	if err := r.f.Close(); err != nil {
		return fmt.Errorf("close log file before rotation: %w", err)
	}
	r.f = nil
	r.size = 0
	backup := r.backupPath(clock)
	// pi-lens-ignore: go-path-traversal (operator-supplied -log-file path)
	if err := os.Rename(r.path, backup); err != nil {
		return fmt.Errorf("rotate log file: %w", err)
	}
	// O_EXCL: anything that appeared at the path between the rename and this
	// create (a symlink or FIFO raced in by a directory writer) fails the
	// open instead of being adopted. That is fail-closed: the sink reports a
	// write error and the watcher surfaces it.
	f, size, _, err := openOrCreateLogFile(r.path)
	if err != nil {
		return fmt.Errorf("reopen log file after rotation: %w", err)
	}
	r.f, r.size = f, size
	r.pruneLocked(clock)
	return nil
}

func (r *logRotator) backupPath(t time.Time) string {
	return fmt.Sprintf("%s.%s", r.path, t.UTC().Format("2006-01-02T15-04-05.000"))
}

// pruneLocked removes backups beyond -log-file-max-backups and older than
// -log-file-max-age. Best effort: a failed prune must not break logging.
func (r *logRotator) pruneLocked(clock time.Time) {
	dir, base := filepath.Dir(r.path), filepath.Base(r.path)+"."
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	type backup struct {
		name string
		ts   time.Time
	}
	var backups []backup
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), base) {
			continue
		}
		ts, err := time.ParseInLocation("2006-01-02T15-04-05.000", strings.TrimPrefix(e.Name(), base), time.UTC)
		if err != nil {
			continue // not one of ours
		}
		backups = append(backups, backup{name: e.Name(), ts: ts})
	}
	sort.Slice(backups, func(i, j int) bool { return backups[i].ts.After(backups[j].ts) })
	for i, b := range backups {
		tooMany := r.maxBackups > 0 && i >= r.maxBackups
		tooOld := r.maxAge > 0 && clock.Sub(b.ts) > r.maxAge
		if tooMany || tooOld {
			// pi-lens-ignore: go-ignored-call-result
			_ = os.Remove(filepath.Join(dir, b.name))
		}
	}
}

// openOrCreateLogFile opens the configured path with the verified chain,
// creating it 0600 (and DACL-restricted on Windows) when absent.
func openOrCreateLogFile(path string) (*os.File, int64, bool, error) {
	li, err := os.Lstat(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, 0, false, err
		}
		// pi-lens-ignore: go-path-traversal (operator-supplied -log-file path)
		f, err := createLogFile(path)
		if errors.Is(err, os.ErrExist) {
			// Raced with another creator: fall back to the existing-file
			// path so its type/owner/DACL checks decide, never this branch.
			return openOrCreateLogFile(path)
		}
		if err != nil {
			return nil, 0, false, err
		}
		changed := false
		if runtime.GOOS == "windows" {
			if changed, err = restrictLogDACL(f); err != nil {
				f.Close()
				return nil, 0, false, err
			}
		}
		fi, err := f.Stat()
		if err != nil {
			f.Close()
			return nil, 0, false, err
		}
		return f, fi.Size(), changed, nil
	}
	return openVerifiedLogFile(path, li)
}

// openVerifiedLogFile binds the provenance decision to the descriptor the
// caller will write through, and repairs its permissions.
func openVerifiedLogFile(path string, li os.FileInfo) (*os.File, int64, bool, error) {
	if li.Mode()&os.ModeSymlink != 0 {
		return nil, 0, false, fmt.Errorf("refusing symlinked log path %q: a symlink can redirect topology-bearing log lines into another local user's file; create the log path directly", path)
	}
	// Refuse every other non-regular object BEFORE open(2): a FIFO with no
	// reader blocks a plain open forever, so a post-open check would never
	// run.
	if !li.Mode().IsRegular() {
		return nil, 0, false, fmt.Errorf("refusing non-regular log path %q (%s): only a regular file may receive topology-bearing logs", path, li.Mode().Type())
	}
	// pi-lens-ignore: go-path-traversal (operator-supplied -log-file path)
	f, err := openLogFileForRepair(path)
	if err != nil {
		return nil, 0, false, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, false, err
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, 0, false, fmt.Errorf("refusing non-regular log path %q (%s): only a regular file may receive topology-bearing logs", path, fi.Mode().Type())
	}
	if !os.SameFile(li, fi) {
		f.Close()
		return nil, 0, false, fmt.Errorf("log path %q changed between check and open; refusing", path)
	}
	if err := checkLogFileOwner(f); err != nil {
		f.Close()
		return nil, 0, false, err
	}
	changed := false
	if runtime.GOOS == "windows" {
		if changed, err = restrictLogDACL(f); err != nil {
			f.Close()
			return nil, 0, false, err
		}
	} else if fi.Mode().Perm() != 0o600 {
		if err := f.Chmod(0o600); err != nil {
			f.Close()
			return nil, 0, false, err
		}
		changed = true
	}
	return f, fi.Size(), changed, nil
}
