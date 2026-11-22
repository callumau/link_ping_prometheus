package logging

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// funcWriter adapts a function to io.Writer for sink tests.
type funcWriter func([]byte) (int, error)

func (f funcWriter) Write(p []byte) (int, error) { return f(p) }

// TestCountedWriterFailureStreak pins DrainFailures semantics: failures
// accumulate between drains, a drain clears the streak, and a
// successful write resets it.
func TestCountedWriterFailureStreak(t *testing.T) {
	var fail bool
	sink := NewCountedWriter(funcWriter(func(p []byte) (int, error) {
		if fail {
			return 0, errors.New("disk full")
		}
		return len(p), nil
	}))

	if _, err := sink.Write([]byte("ok")); err != nil {
		t.Fatalf("clean write must not error: %v", err)
	}
	if n := sink.DrainFailures(); n != 0 {
		t.Fatalf("no failures yet, drain returned %d", n)
	}

	fail = true
	for i := 0; i < 3; i++ {
		if _, err := sink.Write([]byte("x")); err == nil {
			t.Fatal("expected write error from failing sink")
		}
	}
	if n := sink.DrainFailures(); n != 3 {
		t.Fatalf("drain after 3 failed writes = %d, want 3", n)
	}
	if n := sink.DrainFailures(); n != 0 {
		t.Fatalf("second drain must be empty, got %d", n)
	}

	fail = false
	if _, err := sink.Write([]byte("ok")); err != nil {
		t.Fatalf("recovered write must not error: %v", err)
	}
	fail = true
	if _, err := sink.Write([]byte("x")); err == nil {
		t.Fatal("expected write error from failing sink")
	}
	if n := sink.DrainFailures(); n != 1 {
		t.Fatalf("success must reset the streak; drain = %d, want 1", n)
	}
}

// TestCountedWriterIsolatesFileSinkFromStdoutFailure pins that wrapping only
// the file sink stops an invalid/closed stdout handle
// under Windows SCM from triggering false log-sink failure alerts.
func TestCountedWriterIsolatesFileSinkFromStdoutFailure(t *testing.T) {
	fileSink := NewCountedWriter(funcWriter(func(p []byte) (int, error) {
		return len(p), nil
	}))
	badStdout := funcWriter(func(p []byte) (int, error) {
		return 0, errors.New("invalid handle")
	})
	mw := io.MultiWriter(fileSink, badStdout)
	if _, err := mw.Write([]byte("log line\n")); err == nil {
		t.Fatal("expected MultiWriter to surface stdout error")
	}
	if n := fileSink.DrainFailures(); n != 0 {
		t.Fatalf("healthy file sink recorded %d failures due to stdout error, want 0", n)
	}
}

// TestWatchSinkReportsToStderr pins the foreground (no service handle)
// alert path: accumulated sink failures surface on stderr even though
// slog writes into the dead sink itself.
func TestWatchSinkReportsToStderr(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = orig }()

	var fail bool
	sink := NewCountedWriter(funcWriter(func(p []byte) (int, error) {
		if fail {
			return 0, errors.New("disk full")
		}
		return len(p), nil
	}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	WatchSink(ctx, nil, sink, 20*time.Millisecond)

	fail = true
	if _, err := sink.Write([]byte("boom")); err == nil {
		t.Fatal("expected write error from failing sink")
	}

	done := make(chan string, 1)
	go func() {
		buf := make([]byte, 512)
		n, _ := r.Read(buf)
		done <- string(buf[:n])
	}()
	select {
	case got := <-done:
		if !strings.Contains(got, "log sink write failures") {
			t.Fatalf("stderr alert missing failure notice, got: %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no stderr alert within 2s")
	}
}

func TestHardenLogSink(t *testing.T) {
	t.Run("creates missing file at 0600", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "agent.log")
		if _, err := HardenSink(path); err != nil {
			t.Fatalf("HardenSink: %v", err)
		}
		if runtime.GOOS == "windows" {
			verifyLogDACLRestricted(t, path)
			return
		}
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat created file: %v", err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("created file mode = %04o, want 0600", fi.Mode().Perm())
		}
	})

	t.Run("repairs pre-existing wide mode", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "agent.log")
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatalf("seed file: %v", err)
		}
		repaired, err := HardenSink(path)
		if err != nil {
			t.Fatalf("HardenSink: %v", err)
		}
		if !repaired {
			t.Error("repaired = false, want true")
		}
		if data, err := os.ReadFile(path); err != nil || string(data) != "x" {
			t.Errorf("file content changed: %q, err %v", data, err)
		}
		if runtime.GOOS == "windows" {
			verifyLogDACLRestricted(t, path)
			return
		}
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat repaired file: %v", err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("repaired file mode = %04o, want 0600", fi.Mode().Perm())
		}
	})

	t.Run("keeps a compliant file untouched", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "agent.log")
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatalf("seed file: %v", err)
		}
		if runtime.GOOS == "windows" {
			if _, err := HardenSink(path); err != nil {
				t.Fatalf("pre-limit HardenSink: %v", err)
			}
			repaired, err := HardenSink(path)
			if err != nil {
				t.Fatalf("HardenSink: %v", err)
			}
			if repaired {
				t.Error("repaired = true for an already-restricted DACL")
				dumpLogDACLTables(t, path)
			}
			verifyLogDACLRestricted(t, path)
			return
		}
		repaired, err := HardenSink(path)
		if err != nil {
			t.Fatalf("HardenSink: %v", err)
		}
		if repaired {
			t.Error("repaired = true for an already-0600 file")
		}
	})

	t.Run("refuses symlink", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "outside.log")
		if err := os.WriteFile(target, []byte("keep"), 0o644); err != nil {
			t.Fatalf("seed target: %v", err)
		}
		path := filepath.Join(dir, "agent.log")
		if err := os.Symlink(target, path); err != nil {
			t.Skipf("symlink not supported here: %v", err)
		}
		_, err := HardenSink(path)
		if err == nil {
			t.Fatal("HardenSink accepted a symlinked log path")
		}
		if !strings.Contains(err.Error(), "symlink") {
			t.Errorf("error does not mention symlink: %v", err)
		}
		if data, err := os.ReadFile(target); err != nil || string(data) != "keep" {
			t.Errorf("linked target changed: %q, err %v", data, err)
		}
		if fi, err := os.Lstat(path); err != nil || fi.Mode()&os.ModeSymlink == 0 {
			t.Errorf("symlink replaced or missing: %v, %v", fi, err)
		}
	})
}
