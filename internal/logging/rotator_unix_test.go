//go:build !windows

package logging

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestNewRotatorRefusesSymlink pins the core invariant: the
// rotating sink must never adopt a symlink planted at -log-file, because
// rotation must not re-open the path by name without provenance checks.
func TestNewRotatorRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	decoy := filepath.Join(dir, "decoy.log")
	if err := os.WriteFile(decoy, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "agent.log")
	if err := os.Symlink(decoy, path); err != nil {
		t.Fatal(err)
	}
	if r, err := NewRotator(path, 10, 5, 28); err == nil {
		r.Close()
		t.Fatal("a symlinked log path must be refused")
	}
	if fi, err := os.Lstat(decoy); err != nil {
		t.Fatal(err)
	} else if fi.Size() != 0 {
		t.Fatal("the decoy must not receive log records")
	}
}

// TestNewRotatorRefusesFIFO pins that a planted FIFO is refused before
// open(2): a reader-less FIFO would otherwise block the process during log
// setup with no listener bound.
func TestNewRotatorRefusesFIFO(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.log")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	if r, err := NewRotator(path, 10, 5, 28); err == nil {
		r.Close()
		t.Fatal("a FIFO log path must be refused")
	}
}

// TestRotatorNeverWritesThroughReplacedPath drives the rotate step while a
// symlink sits at the configured path: the rename moves the link aside and the
// O_EXCL create produces a fresh regular file, so the decoy stays empty.
func TestRotatorNeverWritesThroughReplacedPath(t *testing.T) {
	dir := t.TempDir()
	r, path := newTestRotator(t, dir, 8, 0)
	if _, err := r.Write([]byte("first\n")); err != nil {
		t.Fatal(err)
	}
	decoy := filepath.Join(dir, "decoy.log")
	if err := os.WriteFile(decoy, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// The attacker's swap: the verified live file is renamed away and a link
	// to the decoy takes its place.
	if err := os.Rename(path, filepath.Join(dir, "moved.log")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(decoy, path); err != nil {
		t.Fatal(err)
	}
	// The next write exceeds the bound, so the rotator rotates first.
	if _, err := r.Write([]byte("second line that overflows\n")); err != nil {
		t.Fatalf("write after swap: %v", err)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.Mode().IsRegular() {
		t.Fatalf("live log path is %s, want a fresh regular file", fi.Mode().Type())
	}
	if fi, err := os.Lstat(decoy); err != nil {
		t.Fatal(err)
	} else if fi.Size() != 0 {
		t.Fatal("the decoy must not receive log records")
	}
}

func verifyLogFileHardened(t *testing.T, path string) {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat log file %q: %v", path, err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("log file %q mode = %04o, want 0600", path, fi.Mode().Perm())
	}
}
