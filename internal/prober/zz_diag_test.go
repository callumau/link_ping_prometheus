package prober

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

var _ = fmt.Sprintf
var _ = atomic.Int64{}

func TestEchoLoop_PendingWindowThrottleSkipsSendsDiag(t *testing.T) {
	start0 := time.Now()
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
		t2 := time.Now()
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
			t.Logf("window pinned: sent %v->%v th %v->%v infl=%v (t=%.3fs since start)", sent0, sent1, th0, th1, infl, t2.Sub(start0).Seconds())
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
		t.Logf("phase3: sent=%v tout=%v infl=%v rtt=%v", sent, tout, infl, rtt)
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

// TestResponseBufferCapacity pins the respCh sizing rule (audit fix): a
// static pair sizes from timeout/interval clamped 100..maxPendingWindow,
// while -adaptive pins the channel to maxPendingWindow because the
// applied RTO (floor max(200ms, 2*SRTT)) is unbounded above and can
// legitimately hold the full pending window in flight. Under-sizing a
// healthy adaptive link back-pressures the reader into the kernel and
// turns echoes into drops that get swept as fabricated loss.
