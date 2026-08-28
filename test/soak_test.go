package prober_test

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"

	"link_ping_prometheus/internal/prober"
)

// TestSoakMemory runs the real client+server and samples the heap every
// few seconds to surface slow memory growth. It is an opt-in diagnostic:
// it skips unless SOAK_SECONDS or SOAK_TARGETS is set, so the default
// suite stays fast. Examples:
//
//	SOAK_SECONDS=600 go test -count=1 -run TestSoakMemory -v ./test/   # 10 min soak
//	SOAK_TARGETS=300 SOAK_SECONDS=60 go test -count=1 -run TestSoakMemory -v ./test/
func TestSoakMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("soak test skipped in -short mode")
	}
	if os.Getenv("SOAK_SECONDS") == "" && os.Getenv("SOAK_TARGETS") == "" {
		t.Skip("soak test is opt-in: set SOAK_SECONDS or SOAK_TARGETS")
	}
	secs := 90
	if v := os.Getenv("SOAK_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			secs = n
		}
	}
	targets := 1
	if v := os.Getenv("SOAK_TARGETS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			targets = n
		}
	}
	d := time.Duration(secs) * time.Second

	ctx, cancel := context.WithCancel(context.Background())
	// pi-lens-ignore: go-context-background-handler
	defer cancel()

	addr := startEchoServer(ctx, t)
	list := make([]prober.Target, 0, targets)
	for i := 0; i < targets; i++ {
		list = append(list, prober.Target{
			Name:    fmt.Sprintf("soak%03d", i),
			Address: addr,
		})
	}
	cfg := cfgWith(true, 50*time.Millisecond, 500*time.Millisecond, list...)

	// Force a GC before the first sample so the baseline is stable.
	runtime.GC()
	start := heapMB()

	type sample struct {
		at   time.Duration
		heap float64
		goro int
	}
	samples := []sample{{0, start, runtime.NumGoroutine()}}

	done := make(chan error, 1)
	go func() { done <- prober.RunClient(ctx, cfg) }()

	const step = 5 * time.Second
	timer := time.NewTimer(step)
	defer timer.Stop()
	for elapsed := time.Duration(0); elapsed < d; elapsed += step {
		select {
		case err := <-done:
			t.Fatalf("RunClient returned early: %v", err)
		case <-timer.C:
			runtime.GC()
			samples = append(samples, sample{elapsed + step, heapMB(), runtime.NumGoroutine()})
			timer.Reset(step)
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("RunClient did not stop after cancel")
	}

	t.Logf("soak %s with %d targets", d, targets)
	first, last := samples[0].heap, samples[len(samples)-1].heap
	t.Logf("heap baseline %.1fMB -> final %.1fMB (delta %+.1fMB over %s)",
		first, last, last-first, d)
	for _, s := range samples {
		t.Logf("  t=%s heap=%.1fMB goroutines=%d", s.at, s.heap, s.goro)
	}
	// A hard ceiling rather than a tight assertion: soak runs on CI and
	// developers' machines with very different base heaps. Anything
	// within 8MB of the start is a steady state, not a leak.
	if last > first+8 {
		t.Errorf("heap grew %.1fMB over %s (%.1f -> %.1f); investigate",
			last-first, d, first, last)
	}
	// Goroutine leak detection: each target spawns ~2 goroutines (probe loop + reader);
	// allow targets*2 + slack for the sampler and runtime.
	firstGoro := samples[0].goro
	lastGoro := samples[len(samples)-1].goro
	allowedDelta := max(targets*2+10, 20)
	if delta := lastGoro - firstGoro; delta > allowedDelta {
		t.Errorf("goroutine leak: delta %d exceeds %d (baseline %d -> final %d with %d targets)", delta, allowedDelta, firstGoro, lastGoro, targets)
	}
}

func heapMB() float64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return float64(m.HeapAlloc) / (1 << 20)
}
