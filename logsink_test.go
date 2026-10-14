package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// TestCountedWriterFailureStreak pins drainFailures semantics: failures
// accumulate between drains, a drain clears the streak, and a
// successful write resets it.
func TestCountedWriterFailureStreak(t *testing.T) {
	var fail bool
	sink := newCountedWriter(funcWriter(func(p []byte) (int, error) {
		if fail {
			return 0, errors.New("disk full")
		}
		return len(p), nil
	}))

	if _, err := sink.Write([]byte("ok")); err != nil {
		t.Fatalf("clean write must not error: %v", err)
	}
	if n := sink.drainFailures(); n != 0 {
		t.Fatalf("no failures yet, drain returned %d", n)
	}

	fail = true
	for i := 0; i < 3; i++ {
		if _, err := sink.Write([]byte("x")); err == nil {
			t.Fatal("expected write error from failing sink")
		}
	}
	if n := sink.drainFailures(); n != 3 {
		t.Fatalf("drain after 3 failed writes = %d, want 3", n)
	}
	if n := sink.drainFailures(); n != 0 {
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
	if n := sink.drainFailures(); n != 1 {
		t.Fatalf("success must reset the streak; drain = %d, want 1", n)
	}
}

// TestWatchLogSinkReportsToStderr pins the foreground (no service handle)
// alert path: accumulated sink failures surface on stderr even though
// slog writes into the dead sink itself.

// TestWatchLogSinkReportsToStderr pins the foreground (no service handle)
// alert path: accumulated sink failures surface on stderr even though
// slog writes into the dead sink itself.
func TestWatchLogSinkReportsToStderr(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = orig }()

	var fail bool
	sink := newCountedWriter(funcWriter(func(p []byte) (int, error) {
		if fail {
			return 0, errors.New("disk full")
		}
		return len(p), nil
	}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watchLogSink(ctx, nil, sink, 20*time.Millisecond)

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

// TestSvcActionSupported pins the OS gate for the -svc lifecycle actions:
// install/uninstall are Windows-only (the binary would otherwise run the
// kardianos Linux unit/init renderers, which no supported deployment
// exercises - Linux installs use the static systemd unit - and whose
// shell-containment surface supply-chain scanners flag), while the
// run/start/stop helpers stay cross-platform.
