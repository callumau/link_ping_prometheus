package logging

import (
	"errors"
	"fmt"
	"link_ping_prometheus/internal/filetrust"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Rotator is the -log-file writer used when -log-file-max-mb is nonzero.
//
// Every open — initial and after each rotation — goes through the same
// verified chain (non-symlink, regular, O_NOFOLLOW|O_NONBLOCK, SameFile,
// owner, 0600/DACL), and the fresh file is created O_EXCL so a raced-in
// object is refused rather than adopted.
//
// Rotation policy: rotate at maxMB, keep maxBackups, drop artifacts older
// than maxAgeDays. Compression stays disabled.
type Rotator struct {
	mu         sync.Mutex
	path       string
	maxBytes   int64
	maxBackups int
	maxAge     time.Duration
	f          *os.File
	size       int64
	closed     bool
	// now and renameFn are seams for tests; zero means time.Now / os.Rename.
	now      func() time.Time
	renameFn func(oldpath, newpath string) error
}

// NewRotator opens (creating if needed) the log path with the verified
// chain and returns a writer that rotates it.
func NewRotator(path string, maxMB, maxBackups, maxAgeDays int) (*Rotator, error) {
	r, _, err := NewRotatorChecked(path, maxMB, maxBackups, maxAgeDays)
	return r, err
}

// NewRotatorChecked opens (creating if needed) the log path with the
// verified chain, reporting whether an existing file's permissions were repaired.
func NewRotatorChecked(path string, maxMB, maxBackups, maxAgeDays int) (*Rotator, bool, error) {
	f, size, repaired, err := OpenFile(path)
	if err != nil {
		return nil, false, err
	}
	r := &Rotator{
		path:       path,
		maxBytes:   int64(maxMB) << 20,
		maxBackups: maxBackups,
		f:          f,
		size:       size,
	}
	if maxAgeDays > 0 {
		r.maxAge = time.Duration(maxAgeDays) * 24 * time.Hour
	}
	return r, repaired, nil
}

func (r *Rotator) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// Write appends p, rotating first when the file has reached its size bound.
// Rotation happens before the write so a single oversized record does not
// stay stranded in an over-limit file.
func (r *Rotator) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, os.ErrClosed
	}
	if r.f == nil {
		// Recover lazily from a previous transient rotation/reopen failure
		// instead of leaving file logging dead for the rest of the process.
		f, size, _, err := OpenFile(r.path)
		if err != nil {
			return 0, err
		}
		r.f, r.size = f, size
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

// Close closes the underlying log file. It is idempotent.
func (r *Rotator) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}

// rotateLocked renames the live file aside and opens a fresh verified one.
// The caller holds r.mu.
func (r *Rotator) rotateLocked() error {
	clock := r.clock()
	closeErr := r.f.Close()
	r.f = nil
	r.size = 0
	if closeErr != nil {
		if f, size, _, err := OpenFile(r.path); err == nil {
			r.f, r.size = f, size
		}
		return fmt.Errorf("close log file before rotation: %w", closeErr)
	}
	backup := r.uniqueBackupPath(clock)
	rename := r.renameFn
	if rename == nil {
		rename = os.Rename
	}
	if err := rename(r.path, backup); err != nil {
		// Reopen the existing verified file so logging survives a transient
		// rename failure (e.g., Windows ERROR_SHARING_VIOLATION).
		if f, size, _, rerr := OpenFile(r.path); rerr == nil {
			r.f, r.size = f, size
		}
		return fmt.Errorf("rotate log file: %w", err)
	}
	// O_EXCL: anything that appeared at the path between the rename and this
	// create (a symlink or FIFO raced in by a directory writer) fails the
	// open instead of being adopted. That is fail-closed: the sink reports a
	// write error and the watcher surfaces it.
	f, size, _, err := OpenFile(r.path)
	if err != nil {
		return fmt.Errorf("reopen log file after rotation: %w", err)
	}
	r.f, r.size = f, size
	r.pruneLocked(clock)
	return nil
}

func (r *Rotator) backupPath(t time.Time) string {
	return fmt.Sprintf("%s.%s", r.path, t.UTC().Format("2006-01-02T15-04-05.000"))
}

// uniqueBackupPath avoids overwriting an existing backup on bursty
// same-millisecond rotations or backward wall-clock steps.
func (r *Rotator) uniqueBackupPath(t time.Time) string {
	base := r.backupPath(t)
	if _, err := os.Lstat(base); errors.Is(err, os.ErrNotExist) {
		return base
	}
	for i := 1; i <= 1000; i++ {
		cand := fmt.Sprintf("%s.%d", base, i)
		if _, err := os.Lstat(cand); errors.Is(err, os.ErrNotExist) {
			return cand
		}
	}
	return base
}

func parseBackupTimestamp(suffix string) (time.Time, error) {
	if ts, err := time.ParseInLocation("2006-01-02T15-04-05.000", suffix, time.UTC); err == nil {
		return ts, nil
	}
	if dot := strings.LastIndexByte(suffix, '.'); dot > 0 {
		if n, err := strconv.Atoi(suffix[dot+1:]); err == nil && n > 0 {
			return time.ParseInLocation("2006-01-02T15-04-05.000", suffix[:dot], time.UTC)
		}
	}
	return time.Time{}, errors.New("not a backup timestamp")
}

// pruneLocked removes backups beyond maxBackups and older than maxAge.
// Best effort: a failed prune must not break logging.
func (r *Rotator) pruneLocked(clock time.Time) {
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
		ts, err := parseBackupTimestamp(strings.TrimPrefix(e.Name(), base))
		if err != nil {
			continue // not one of ours
		}
		backups = append(backups, backup{name: e.Name(), ts: ts})
	}
	sort.Slice(backups, func(i, j int) bool {
		if !backups[i].ts.Equal(backups[j].ts) {
			return backups[i].ts.After(backups[j].ts)
		}
		return backups[i].name > backups[j].name
	})
	for i, b := range backups {
		tooMany := r.maxBackups > 0 && i >= r.maxBackups
		tooOld := r.maxAge > 0 && clock.Sub(b.ts) > r.maxAge
		if tooMany || tooOld {
			_ = os.Remove(filepath.Join(dir, b.name))
		}
	}
}

// OpenFile opens the configured path with the verified chain,
// creating it 0600 (and DACL-restricted on Windows) when absent.
func OpenFile(path string) (*os.File, int64, bool, error) {
	for attempt := 0; attempt < 4; attempt++ {
		f, fi, err := filetrust.VerifyExistingRegular(path, 0, openLogFileForRepair)
		if err == nil {
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
		if !errors.Is(err, os.ErrNotExist) {
			return nil, 0, false, err
		}
		f, err = createLogFile(path)
		if errors.Is(err, os.ErrExist) {
			// Raced with another creator: retry via VerifyExistingRegular.
			continue
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
		fi, err = f.Stat()
		if err != nil {
			f.Close()
			return nil, 0, false, err
		}
		return f, fi.Size(), changed, nil
	}
	return nil, 0, false, fmt.Errorf("log file %q changed concurrently during open", path)
}
