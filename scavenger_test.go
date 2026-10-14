package main

import (
	"context"
	"log/slog"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestReleasableHeap pins the scavenge trigger's input: idle heap the runtime
// has not yet returned to the OS. The trigger used Sys-HeapReleased, which
// covers the whole process and is therefore always above the threshold, so the
// documented "skip an already-lean process" guard never fired.
// pi-lens-ignore: go-test-functions
func TestReleasableHeap(t *testing.T) {
	tests := []struct {
		name string
		m    runtime.MemStats
		want uint64
	}{
		{
			// Already-lean process: Sys is large (stacks, GC metadata, mmap'd
			// spans), but every idle span has been released - nothing to give
			// back, so nothing to scavenge.
			"all idle heap released",
			runtime.MemStats{Sys: 100 << 20, HeapIdle: 10 << 20, HeapReleased: 10 << 20},
			0,
		},
		{
			// HeapReleased can transiently exceed HeapIdle; an unsigned
			// subtraction would wrap and force a scavenge every tick. Released
			// is strictly GREATER here so the clamp is actually exercised.
			"released exceeds idle underflows to zero",
			runtime.MemStats{Sys: 4 << 20, HeapIdle: 8 << 20, HeapReleased: 12 << 20},
			0,
		},
		{
			"releasable is idle minus released",
			runtime.MemStats{Sys: 20 << 20, HeapIdle: 20 << 20, HeapReleased: 6 << 20},
			14 << 20,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := releasableHeap(tc.m); got != tc.want {
				t.Errorf("releasableHeap(%+v) = %d, want %d", tc.m, got, tc.want)
			}
		})
	}
}

// pi-lens-ignore: go-test-functions

// pi-lens-ignore: go-test-functions
func TestShouldScavenge(t *testing.T) {
	tests := []struct {
		name          string
		m             runtime.MemStats
		minUnreleased uint64
		want          bool
	}{
		// The regression: a long-running agent always holds tens of MB in Sys,
		// so keying the guard on the process total made it fire on every tick
		// of an otherwise lean process.
		{"lean process is skipped despite a large Sys", runtime.MemStats{Sys: 90 << 20, HeapIdle: 8 << 20, HeapReleased: 8 << 20}, minScavengeUnreleased, false},
		{"below threshold is skipped", runtime.MemStats{HeapIdle: 6 << 20, HeapReleased: 3 << 20}, 4 << 20, false},
		{"exactly at threshold scavenges", runtime.MemStats{HeapIdle: 8 << 20, HeapReleased: 4 << 20}, 4 << 20, true},
		{"above threshold scavenges", runtime.MemStats{HeapIdle: 12 << 20, HeapReleased: 2 << 20}, 4 << 20, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldScavenge(tc.m, tc.minUnreleased); got != tc.want {
				t.Errorf("shouldScavenge(%+v, %d) = %v, want %v", tc.m, tc.minUnreleased, got, tc.want)
			}
		})
	}
}

// chanHandler forwards log records to a channel so the scavenger test can
// observe a tick without sleeping for a real interval.

// pi-lens-ignore: go-test-functions
func TestStartHeapScavengerDisabled(t *testing.T) {
	before := runtime.NumGoroutine()
	// every <= 0 must not spawn anything at all.
	// pi-lens-ignore: go-context-background-handler
	startHeapScavenger(context.Background(), 0, minScavengeUnreleased, slog.Default())
	if after := runtime.NumGoroutine(); after > before {
		t.Errorf("every=0 must not spawn a goroutine, count went %d -> %d", before, after)
	}
}

// pi-lens-ignore: go-test-functions

// pi-lens-ignore: go-test-functions
func TestStartHeapScavengerTicksThenStopsOnCancel(t *testing.T) {
	// pi-lens-ignore: go-context-background-handler
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := make(chan string, 1)
	before := runtime.NumGoroutine()
	// minUnreleased=0 makes every tick take the scavenge path, so the log
	// line proves the ticker actually fired before we cancel it.
	startHeapScavenger(ctx, 5*time.Millisecond, 0, slog.New(chanHandler{ch: ch}))

	select {
	case msg := <-ch:
		if !strings.Contains(msg, "scavenge") {
			t.Errorf("unexpected scavenger log message %q", msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("scavenger never ticked")
	}

	cancel()
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		// pi-lens-ignore: go-time-sleep-test
		time.Sleep(2 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > before {
		t.Errorf("scavenger goroutine still running after ctx cancel: %d > %d", n, before)
	}
}

// saveFlags restores all mutated global flags after the test.
