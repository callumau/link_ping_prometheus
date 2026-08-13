package prober

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// TestProbeTargetRetriesOnDialFailure: a dial error (e.g. a transient DNS
// resolution failure at startup) must not kill the target's probe loop —
// it keeps retrying until the context is cancelled. Uses the dialUDP seam
// instead of an unresolvable hostname so the test is deterministic and
// has no dependency on the local resolver.
func TestProbeTargetRetriesOnDialFailure(t *testing.T) {
	InitMetrics()

	var dials atomic.Int64
	old := dialUDP
	dialUDP = func(network, address string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("dial udp: lookup test.invalid: no such host")
	}
	defer func() { dialUDP = old }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		probeTarget(ctx, Target{Name: "t", Address: "test.invalid:4000"}, Config{
			Source:       "test",
			BaseInterval: 50 * time.Millisecond,
			BaseTimeout:  100 * time.Millisecond,
		})
		close(done)
	}()

	// The retry loop pauses 1s between attempts; span a few of them.
	time.Sleep(2500 * time.Millisecond)

	if n := dials.Load(); n < 2 {
		t.Errorf("expected multiple dial attempts, got %d", n)
	}
	select {
	case <-done:
		t.Fatal("probe loop exited on dial failure; should keep retrying")
	default:
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("probe loop did not stop after cancel")
	}
}
