package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newTestRotator builds a rotator with a small size bound and a monotonic
// clock so rotations in the same millisecond still get distinct backup names.
func newTestRotator(t *testing.T, dir string, maxBytes int64, maxBackups int) (*logRotator, string) {
	t.Helper()
	path := filepath.Join(dir, "agent.log")
	r, err := newLogRotator(path, 1, maxBackups, 0)
	if err != nil {
		t.Fatalf("newLogRotator: %v", err)
	}
	r.maxBytes = maxBytes
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	var n int
	r.now = func() time.Time {
		n++
		return base.Add(time.Duration(n) * time.Second)
	}
	t.Cleanup(func() { r.Close() })
	return r, path
}

func backupsFor(t *testing.T, path string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Base(path) + "."
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), base) {
			out = append(out, e.Name())
		}
	}
	return out
}

// TestLogRotatorRotatesHardensAndPrunes pins the rotation contract the audit
// found broken: rotation must not become a by-name reopen, the fresh file must
// be 0600, and backups must respect -log-file-max-backups.
func TestLogRotatorRotatesHardensAndPrunes(t *testing.T) {
	dir := t.TempDir()
	r, path := newTestRotator(t, dir, 64, 2)

	for i := 0; i < 6; i++ {
		if _, err := r.Write([]byte(strings.Repeat("x", 40) + "\n")); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if got := backupsFor(t, path); len(got) > 2 {
		t.Fatalf("maxBackups=2 kept %d backups: %v", len(got), got)
	}
	if got := backupsFor(t, path); len(got) == 0 {
		t.Fatal("expected at least one rotated backup")
	}
	if fi, err := os.Lstat(path); err != nil {
		t.Fatalf("live log missing after rotation: %v", err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Fatalf("live log mode = %04o, want 0600", fi.Mode().Perm())
	}
	for _, name := range backupsFor(t, path) {
		fi, err := os.Lstat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("backup %s: %v", name, err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("backup %s mode = %04o, want 0600", name, fi.Mode().Perm())
		}
	}
}

// TestNewLogRotatorRepairsExistingMode keeps the startup invariant: an
// operator-placed 0644 log file is repaired before anything is written.
func TestNewLogRotatorRepairsExistingMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.log")
	if err := os.WriteFile(path, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := newLogRotator(path, 10, 5, 28)
	if err != nil {
		t.Fatalf("newLogRotator: %v", err)
	}
	defer r.Close()
	if fi, err := os.Lstat(path); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %04o, want repaired 0600", fi.Mode().Perm())
	}
}

// TestLogRotatorCloseIsIdempotent covers the deferred Close in main after an
// explicit Close on a shutdown path.
func TestLogRotatorCloseIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	r, _ := newTestRotator(t, dir, 1<<20, 0)
	if err := r.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if _, err := r.Write([]byte("x")); err == nil {
		t.Fatal("write after close must fail")
	}
}

// TestLogRotatorRecoversAfterTransientRotationFailure pins that a transient
// rename failure (such as Windows ERROR_SHARING_VIOLATION from an AV scanner
// or log shipper) does not permanently close the log sink.
func TestLogRotatorRecoversAfterTransientRotationFailure(t *testing.T) {
	dir := t.TempDir()
	r, path := newTestRotator(t, dir, 16, 2)
	var failRename bool
	r.renameFn = func(oldpath, newpath string) error {
		if failRename {
			return errors.New("simulated sharing violation")
		}
		return os.Rename(oldpath, newpath)
	}

	if _, err := r.Write([]byte("0123456789abcdef\n")); err != nil {
		t.Fatalf("initial write: %v", err)
	}
	failRename = true
	if _, err := r.Write([]byte("trigger-fail\n")); err == nil {
		t.Fatal("expected rotation error when rename fails")
	}
	failRename = false
	if _, err := r.Write([]byte("recovered-line\n")); err != nil {
		t.Fatalf("write after transient rename failure failed: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read live log: %v", err)
	}
	if !strings.Contains(string(data), "recovered-line") {
		t.Fatalf("live log missing recovered line: %q", data)
	}
}

// TestLogRotatorSameMillisecondBackupsDoNotCollide pins that bursty rotations
// within the same millisecond get distinct backup names instead of overwriting.
func TestLogRotatorSameMillisecondBackupsDoNotCollide(t *testing.T) {
	dir := t.TempDir()
	r, path := newTestRotator(t, dir, 8, 10)
	fixed := time.Date(2026, 2, 3, 4, 5, 6, 789_000_000, time.UTC)
	r.now = func() time.Time { return fixed }

	for i := 0; i < 4; i++ {
		if _, err := r.Write([]byte("0123456789\n")); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if got := backupsFor(t, path); len(got) != 3 {
		t.Fatalf("expected 3 distinct same-millisecond backups, got %d (%v)", len(got), got)
	}
}

// TestLogRotatorPrunesByMaxAge pins age-based backup pruning (including
// same-millisecond deduplicated backups).
func TestLogRotatorPrunesByMaxAge(t *testing.T) {
	dir := t.TempDir()
	r, path := newTestRotator(t, dir, 8, 10)
	r.maxAge = 24 * time.Hour

	cur := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	r.now = func() time.Time { return cur }
	if _, err := r.Write([]byte("first-line\n")); err != nil {
		t.Fatal(err)
	}
	// Rotate at day 1 -> backup 1 (at cur=day 1).
	if _, err := r.Write([]byte("second-line\n")); err != nil {
		t.Fatal(err)
	}
	// Advance 3 days and rotate again -> backup 1 is now 3 days old (>24h) and must be pruned.
	cur = cur.Add(72 * time.Hour)
	if _, err := r.Write([]byte("third-line\n")); err != nil {
		t.Fatal(err)
	}
	got := backupsFor(t, path)
	if len(got) != 1 {
		t.Fatalf("expected 1 fresh backup after age prune, got %d (%v)", len(got), got)
	}
	if !strings.Contains(got[0], "2026-02-04") {
		t.Fatalf("wrong backup survived age prune: %v", got)
	}
}
