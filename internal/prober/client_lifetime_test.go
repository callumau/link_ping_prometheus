package prober

import (
	"context"
	"testing"
	"time"
)

// TestRunClient_NoReloadPathWaitsForShutdown pins the steady-state wait of a
// plain client run (no -targets, so no reload path at all): RunClient must
// block until its context is cancelled.
//
// The shutdown drain is deliberately BOUNDED (stragglerStopTimeout) so a wedged
// socket op cannot hang Stop, and using that same bounded drain as the
// steady-state wait is a regression that no other test catches: RunClient
// returned after five seconds, run() treated the mode exit as terminal, shut
// the metrics server down and exited — so every deployment without -targets
// died ~5s after start while /metrics had been serving 200 and link_up was 1.
func TestRunClient_NoReloadPathWaitsForShutdown(t *testing.T) {
	InitMetrics()

	// Shorten the shutdown join bound so "past the bound" costs milliseconds
	// rather than the production 5s. Restored before any other test runs.
	old := stragglerStopTimeout
	stragglerStopTimeout = 100 * time.Millisecond
	defer func() { stragglerStopTimeout = old }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := wbRealEchoServer(t, ctx, "")

	cfg := Config{
		Source:       "test",
		BaseInterval: 20 * time.Millisecond,
		BaseTimeout:  200 * time.Millisecond,
		Adaptive:     true,
		Targets:      []Target{{Name: "lifetime", Address: addr}},
	}

	done := make(chan error, 1)
	go func() { done <- RunClient(ctx, cfg) }()

	select {
	case err := <-done:
		t.Fatalf("RunClient returned %v without cancellation: a no-reload client must wait for shutdown, not for the bounded drain", err)
	case <-time.After(600 * time.Millisecond):
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunClient returned %v on cancellation, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("RunClient did not return after cancellation")
	}
}
