//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func mkfifo(path string) error { return syscall.Mkfifo(path, 0o600) }

// TestHardenLogSinkRefusesNonRegularFile pins the FIFO finding: only symlinks
// were refused, so a FIFO planted at -log-file either received the whole log
// stream (with a reader) or blocked the process in open(2) before any
// listener bound (without one). The refusal must happen before the open and
// must not hang.
func TestHardenLogSinkRefusesNonRegularFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "service.log")
	if err := mkfifo(path); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := hardenLogSink(path)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("hardenLogSink adopted a FIFO as the log sink")
		}
		if !strings.Contains(err.Error(), "non-regular") {
			t.Errorf("error should name the non-regular object, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("hardenLogSink blocked on a reader-less FIFO instead of refusing it")
	}
}

// TestHardenLogSinkRefusesSymlink keeps the existing control pinned after the
// provenance rewrite.
func TestHardenLogSinkRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.log")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "service.log")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := hardenLogSink(link); err == nil {
		t.Fatal("hardenLogSink followed a symlinked log path")
	}
}

// TestHardenLogSinkRepairsModeAndCreates is the happy path: an existing 0644
// file is repaired, a missing file is created 0600, and a second call is
// idempotent.
func TestHardenLogSinkRepairsModeAndCreates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "service.log")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	repaired, err := hardenLogSink(path)
	if err != nil {
		t.Fatalf("hardenLogSink: %v", err)
	}
	if !repaired {
		t.Error("a 0644 file must be reported as repaired")
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode after repair = %v (err %v), want 0600", fi.Mode().Perm(), err)
	}
	if repaired, err := hardenLogSink(path); err != nil || repaired {
		t.Errorf("second call must be a no-op: repaired=%v err=%v", repaired, err)
	}

	fresh := filepath.Join(dir, "new.log")
	if _, err := hardenLogSink(fresh); err != nil {
		t.Fatalf("create path: %v", err)
	}
	if fi, err := os.Stat(fresh); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("created file mode = %v (err %v), want 0600", fi.Mode().Perm(), err)
	}
}
