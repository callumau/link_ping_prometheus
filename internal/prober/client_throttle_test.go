package prober

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// invocationCounter differentiates metric label sets across go -count
// invocations (see the note in TestEchoLoop_PendingWindowThrottleSkipsSends).
var invocationCounter atomic.Int64

// White-box test for the pending-window send throttle (client.go): the
// static interval/timeout pair is validated by validatePendingWindow, but
// with -adaptive the applied timeout is the RFC 6298 RTO whose floor
// max(200ms, 2*SRTT) is unbounded above, so len(pending) can grow past
// maxPendingWindow. The loop must SKIP sends while the window is at the
// cap — no frame built, no sent/inflight movement, throttled counter
// incremented — so the pending map and its per-tick full sweep stay
// bounded.

// blackholeConn behaves like a connected UDP socket into a dead link:
// every Write succeeds, every Read blocks until Close. runEchoLoop's
// reader goroutine stays alive (no read errors) and no echo ever resolves
// a probe, so the pending window fills to the cap purely through time.
type blackholeConn struct {
	closed chan struct{}
	once   sync.Once
}

func newBlackholeConn() *blackholeConn {
	return &blackholeConn{closed: make(chan struct{})}
}

func (c *blackholeConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}

func (c *blackholeConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *blackholeConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}
func (c *blackholeConn) LocalAddr() net.Addr              { return nil }
func (c *blackholeConn) RemoteAddr() net.Addr             { return nil }
func (c *blackholeConn) SetDeadline(time.Time) error      { return nil }
func (c *blackholeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *blackholeConn) SetWriteDeadline(time.Time) error { return nil }

// TestEchoLoop_PendingWindowThrottleSkipsSends drives the adaptive RTO
// escape from maxPendingWindow: a warmed SRTT of 0.8s lifts the applied
// RTO to ~2.4s (the dynamic floor 2*SRTT=1.6s), so a 1ms interval builds
// a window far above the 1000-entry cap — a pair the STATIC validator
// would reject (2.4s > 1000*1ms fails checkPendingWindow), reached here
// only through adaptation. The test observes the loop through the metric
// handles: len(pending) maps 1:1 onto link_probes_inflight (every pending
// entry carries exactly one inflight unit), so the gauge is a direct
// window read without a hook into the local map.
func TestEchoLoop_PendingWindowThrottleSkipsSends(t *testing.T) {
	InitMetrics()
	// Per-invocation series: the loop exits via cancel, whose deferred tail
	// resolves pending inflight-only (the pinned shutdown convention — a
	// deliberate imbalance on the shared series). A second -count iteration
	// reading the SAME series would then start with that residual drift and
	// never see the balance reconcile to zero. A unique address label gives
	// every invocation a fresh, self-consistent series.
	invocation := invocationCounter.Add(1)
	addr := fmt.Sprintf("127.0.0.1:9%d", invocation)
	const src, name = "throttle-src", "throttled_target"

	stats := NewAdaptiveStats(2 * time.Second)
	stats.Update(0.8) // SRTT=0.8s, RTTVAR=0.4s → RTO = 0.8+4*0.4 = 2.4s
	if got := stats.CurrentRTO(); got != 2400*time.Millisecond {
		t.Fatalf("test setup: expected 2.4s adaptive RTO, got %v", got)
	}

	m := newTargetMetrics(src, Target{Name: name, Address: addr})
	cfg := Config{Source: src, BaseInterval: time.Millisecond, BaseTimeout: 2 * time.Second, Adaptive: true}
	conn := newBlackholeConn()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runEchoLoop(ctx, conn, cfg, stats, m, &probeLoopState{}, slog.Default()) }()

	// Phase 1: let the window fill. The inflight gauge is len(pending)
	// exactly, so it must never exceed maxPendingWindow once throttling
	// engages.
	deadline := time.Now().Add(15 * time.Second)
	var maxInflight float64
	for time.Now().Before(deadline) {
		if infl := wbGauge(ProbesInflight, src, name, addr); infl > maxInflight {
			maxInflight = infl
		}
		if wbGauge(ProbesInflight, src, name, addr) >= float64(maxPendingWindow) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if maxInflight > float64(maxPendingWindow) {
		t.Errorf("pending window exceeded maxPendingWindow: inflight=%v cap=%d", maxInflight, maxPendingWindow)
	}
	if maxInflight < float64(maxPendingWindow) {
		cancel()
		<-done
		t.Fatalf("window never reached the cap; throttle not exercised (max inflight=%v)", maxInflight)
	}

	// Phase 2: with the window at the cap and the first probes still
	// inside their 2.4s RTO, every tick must throttle instead of send.
	// Sample sent/throttled/inflight over 300ms: sent must stay frozen
	// (a skipped send is not sent), throttled must grow, inflight must
	// never cross the cap.
	frozen := false
	sampleDeadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(sampleDeadline) {
		infl := wbGauge(ProbesInflight, src, name, addr)
		if infl < float64(maxPendingWindow) {
			// A timeout sweep drained the window: sends resumed. Only
			// compare a fully pinned window.
			time.Sleep(20 * time.Millisecond)
			continue
		}
		sent0, th0 := wbCounter(ProbesSent, src, name, addr), wbCounter(ProbesThrottled, src, name, addr)
		time.Sleep(300 * time.Millisecond)
		infl = wbGauge(ProbesInflight, src, name, addr)
		sent1, th1 := wbCounter(ProbesSent, src, name, addr), wbCounter(ProbesThrottled, src, name, addr)
		if infl < float64(maxPendingWindow) {
			// Window drained mid-sample; keep sampling for a pinned one.
			continue
		}
		if infl > float64(maxPendingWindow) {
			t.Errorf("inflight exceeded the cap during throttle: %v", infl)
		}
		if sent1 != sent0 {
			t.Errorf("sent grew from %v to %v while the pending window was pinned at the cap — a throttled tick must not send", sent0, sent1)
		}
		if th1 <= th0 {
			t.Errorf("throttled counter did not advance while the window was pinned (before=%v after=%v)", th0, th1)
		}
		frozen = true
		break
	}
	if !frozen {
		t.Fatal("never observed a pinned cap window with sent frozen and throttled advancing")
	}

	// Phase 3: run to the first RTO expiry so the sweep resolves probes:
	// timed_out must drain the window (probes time out at the first tick
	// after the RTO, exactly as without throttling) and the balance
	// invariant sent = rtt + timed_out + inflight must hold throughout —
	// the throttle never touches the balance because the probe never
	// existed. Sample until a zero-drift gather appears, never asserting
	// exact zero on one snapshot (see test/reload_test.go waitForBalance).
	drainDeadline := time.Now().Add(6 * time.Second)
	drifts := []float64{}
	for time.Now().Before(drainDeadline) {
		sent := wbCounter(ProbesSent, src, name, addr)
		tout := wbCounter(ProbesTimedOut, src, name, addr)
		rtt := wbHistCount(src, name, addr)
		infl := wbGauge(ProbesInflight, src, name, addr)
		drift := sent - rtt - tout - infl
		if drift == 0 && wbCounter(ProbesTimedOut, src, name, addr) > 0 {
			break
		}
		drifts = append(drifts, drift)
		time.Sleep(20 * time.Millisecond)
	}
	if tout := wbCounter(ProbesTimedOut, src, name, addr); tout <= 0 {
		t.Errorf("timed_out must drain the window after the RTO expiry, got %v", tout)
	}
	if drift := wbCounter(ProbesSent, src, name, addr) - wbHistCount(src, name, addr) - wbCounter(ProbesTimedOut, src, name, addr) - wbGauge(ProbesInflight, src, name, addr); drift != 0 {
		t.Errorf("balance invariant never reconciled to 0 across 6s of sampling (drift sequence head: %v)", drifts)
	}
	if wbCounter(ProbesThrottled, src, name, addr) <= 0 {
		t.Errorf("throttled counter must be incremented while sends are skipped")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("runEchoLoop must exit cleanly on cancel, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runEchoLoop did not exit after cancel")
	}
	// Quiescent state: the exit tail counts nothing (shutdown = inflight-only
	// accounting; the series stops being exported) and inflight is drained.
	if infl := wbGauge(ProbesInflight, src, name, addr); infl != 0 {
		t.Errorf("inflight must drain to 0 after shutdown, got %v", infl)
	}
}
