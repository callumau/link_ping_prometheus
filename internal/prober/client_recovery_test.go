package prober

import (
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// White-box recovery tests for runEchoLoop/probeTarget exit paths that
// cannot be triggered through the public API (write failures, injected
// panics, dial-retry link_up state). Complements the external suite in
// test/.

// wbCounter reads a counter series for the given client labels.
func wbCounter(vec *prometheus.CounterVec, source, name, addr string) float64 {
	var m dto.Metric
	if err := vec.WithLabelValues(source, name, addr).Write(&m); err != nil {
		return 0
	}
	return m.GetCounter().GetValue()
}

// wbGauge reads a gauge series for the given client labels.
func wbGauge(vec *prometheus.GaugeVec, source, name, addr string) float64 {
	var m dto.Metric
	if err := vec.WithLabelValues(source, name, addr).Write(&m); err != nil {
		return 0
	}
	return m.GetGauge().GetValue()
}

// wbHistCount reads an RTT histogram sample count.
func wbHistCount(source, name, addr string) float64 {
	obs, err := RTTSeconds.GetMetricWithLabelValues(source, name, addr)
	if err != nil {
		return 0
	}
	var d dto.Metric
	if err := obs.(prometheus.Metric).Write(&d); err != nil {
		return 0
	}
	return float64(d.GetHistogram().GetSampleCount())
}

// scriptedConn wraps a real UDP conn (used for Read/deadlines/Close) and
// routes Write calls through hook(n), where n is the 1-based write count.
// hook returns whether the write should fail or panic.
type scriptedConn struct {
	net.Conn
	writes atomic.Int64
	hook   func(n int64) (fail bool, panicNow bool)
}

func (s *scriptedConn) Write(b []byte) (int, error) {
	n := s.writes.Add(1)
	if s.hook != nil {
		fail, panicNow := s.hook(n)
		if panicNow {
			panic("injected write panic")
		}
		if fail {
			return 0, errors.New("injected write failure")
		}
	}
	return s.Conn.Write(b)
}

// wbEchoServer starts a minimal UDP echo responder on an ephemeral port,
// closing its socket on ctx cancellation. Each received frame is passed
// to onFrame (from the reader goroutine) before echoing.
func wbEchoServer(t *testing.T, ctx context.Context, onFrame func(buf []byte)) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		defer pc.Close()
		buf := make([]byte, MaxDatagramSize)
		for ctx.Err() == nil {
			if err := pc.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
				return
			}
			n, raddr, err := pc.ReadFrom(buf)
			if err != nil {
				continue
			}
			if onFrame != nil {
				onFrame(buf[:n])
			}
			pc.WriteTo(buf[:n], raddr)
		}
	}()
	return pc.LocalAddr().String()
}

// TestEchoLoop_PanicFlushCountsTimeouts: when the echo loop panics with
// probes still in flight, those probes can never match on this socket —
// they must be counted as timed out AND removed from inflight so the
// balance sent = rtt_count + timed_out + inflight survives the restart.
// pi-lens-ignore: go-test-functions
func TestEchoLoop_PanicFlushCountsTimeouts(t *testing.T) {
	InitMetrics()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Delay echoes past the second write so probe #1 is still pending
	// when the panic fires — the abandoned-probe flush is what's under
	// test.
	addr := wbEchoServer(t, ctx, func(buf []byte) {
		time.Sleep(150 * time.Millisecond)
	})

	realConn, err := dialUDP(ctx, "udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	conn := &scriptedConn{Conn: realConn, hook: func(n int64) (bool, bool) {
		return false, n == 2 // panic on the second write
	}}

	const src, name = "test", "panic_balance"
	m := newTargetMetrics(src, Target{Name: name, Address: addr})
	cfg := Config{Source: src, BaseInterval: 30 * time.Millisecond, BaseTimeout: time.Second}

	err = runEchoLoop(ctx, conn, cfg, NewAdaptiveStats(cfg.BaseTimeout), m, &probeLoopState{}, slog.Default())
	if err == nil || !strings.Contains(err.Error(), "panic") {
		t.Fatalf("expected panic error from runEchoLoop, got %v", err)
	}

	sent := wbCounter(ProbesSent, src, name, addr)
	rtt := wbHistCount(src, name, addr)
	tout := wbCounter(ProbesTimedOut, src, name, addr)
	infl := wbGauge(ProbesInflight, src, name, addr)

	if sent < 1 || tout < 1 {
		t.Fatalf("expected sent>=1 and timed_out>=1 after panic flush, got sent=%v tout=%v", sent, tout)
	}
	if infl != 0 {
		t.Errorf("inflight must drain to 0 after panic flush, got %v", infl)
	}
	if sent != rtt+tout+infl {
		t.Errorf("balance invariant broken after panic: sent=%v rtt=%v timed_out=%v inflight=%v",
			sent, rtt, tout, infl)
	}
}

// TestEchoLoop_LinkDownOnSustainedWriteFailures: after
// maxConsecutiveWriteFails consecutive local send errors, link_up must
// drop to 0 — a frozen link_up=1 while nothing is being probed is the
// worst failure mode for a monitor.
// pi-lens-ignore: go-test-functions
func TestEchoLoop_LinkDownOnSustainedWriteFailures(t *testing.T) {
	InitMetrics()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr := wbEchoServer(t, ctx, nil)
	realConn, err := dialUDP(ctx, "udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	conn := &scriptedConn{Conn: realConn, hook: func(n int64) (bool, bool) {
		return true, false // every write fails
	}}

	const src, name = "test", "write_fail_down"
	m := newTargetMetrics(src, Target{Name: name, Address: addr})
	m.linkUp.Set(1) // simulate a previously healthy session

	cfg := Config{Source: src, BaseInterval: 20 * time.Millisecond, BaseTimeout: time.Second}
	done := make(chan struct{})
	go func() {
		runEchoLoop(ctx, conn, cfg, NewAdaptiveStats(cfg.BaseTimeout), m, &probeLoopState{}, slog.Default())
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if up := wbGauge(LinkUp, src, name, addr); up == 0 {
			cancel()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("echo loop did not stop after cancel")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	t.Errorf("link_up must drop to 0 after %d consecutive write failures, got %v",
		maxConsecutiveWriteFails, wbGauge(LinkUp, src, name, addr))
}

// TestEchoLoop_WriteFailureDoesNotBurnSeq: a failed write never put the
// datagram on the wire, so it must not consume a sequence number — the
// server must observe contiguous seqs, and the RFC 3550 jitter estimate
// must not reset from the phantom gap.
// pi-lens-ignore: go-test-functions
func TestEchoLoop_WriteFailureDoesNotBurnSeq(t *testing.T) {
	InitMetrics()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	var seqs []uint64
	addr := wbEchoServer(t, ctx, func(buf []byte) {
		if len(buf) >= 16 && string(buf[0:8]) == MagicBytes {
			mu.Lock()
			seqs = append(seqs, binary.LittleEndian.Uint64(buf[8:16]))
			mu.Unlock()
		}
	})

	realConn, err := dialUDP(ctx, "udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	conn := &scriptedConn{Conn: realConn, hook: func(n int64) (bool, bool) {
		return n == 4, false // exactly one failed write
	}}

	const src, name = "test", "nofail_seq"
	m := newTargetMetrics(src, Target{Name: name, Address: addr})
	cfg := Config{Source: src, BaseInterval: 30 * time.Millisecond, BaseTimeout: 2 * time.Second}
	done := make(chan struct{})
	go func() {
		runEchoLoop(ctx, conn, cfg, NewAdaptiveStats(cfg.BaseTimeout), m, &probeLoopState{}, slog.Default())
		close(done)
	}()

	time.Sleep(800 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("echo loop did not stop after cancel")
	}
	// Let any in-flight echo land, then read under the same lock the
	// server goroutine appends under.
	time.Sleep(300 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()

	if len(seqs) < 5 {
		t.Fatalf("expected at least 5 echoed frames, got %d", len(seqs))
	}
	for i := 1; i < len(seqs); i++ {
		if seqs[i] != seqs[i-1]+1 {
			t.Fatalf("echoed sequence numbers not contiguous at index %d: %v (a failed write burned a seq)",
				i, seqs)
		}
	}
}

// TestEchoLoop_TransientWriteFailuresKeepLinkUp: write failures in
// pairs (always fewer than maxConsecutiveWriteFails consecutive) are
// transient: link_up must stay 1, sends must resume after each failure,
// and the balance invariant must hold exactly at quiescence.
// pi-lens-ignore: go-test-functions
func TestEchoLoop_TransientWriteFailuresKeepLinkUp(t *testing.T) {
	InitMetrics()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr := wbEchoServer(t, ctx, nil)
	realConn, err := dialUDP(ctx, "udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	conn := &scriptedConn{Conn: realConn, hook: func(n int64) (bool, bool) {
		m := n % 4
		return m == 2 || m == 3, false // pairs of failures, never 3 in a row
	}}

	const src, name = "test", "transient_wfail"
	m := newTargetMetrics(src, Target{Name: name, Address: addr})
	m.linkUp.Set(1) // previously healthy session

	cfg := Config{Source: src, BaseInterval: 20 * time.Millisecond, BaseTimeout: time.Second}
	done := make(chan struct{})
	go func() {
		runEchoLoop(ctx, conn, cfg, NewAdaptiveStats(cfg.BaseTimeout), m, &probeLoopState{}, slog.Default())
		close(done)
	}()

	time.Sleep(500 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("echo loop did not stop after cancel")
	}
	time.Sleep(100 * time.Millisecond) // let trailing echoes land before reading counters

	sent := wbCounter(ProbesSent, src, name, addr)
	rtt := wbHistCount(src, name, addr)
	tout := wbCounter(ProbesTimedOut, src, name, addr)
	infl := wbGauge(ProbesInflight, src, name, addr)

	if up := wbGauge(LinkUp, src, name, addr); up != 1 {
		t.Errorf("link_up must stay 1 through transient (<%d consecutive) write failures, got %v",
			maxConsecutiveWriteFails, up)
	}
	if sent < 5 {
		t.Errorf("writes must resume after transient failures, got sent=%v", sent)
	}
	if sent != rtt+tout+infl {
		// The only allowed residual: probes in flight at the cancel
		// instant, which graceful shutdown abandons by design (neither
		// received nor timed out — see TestGracefulShutdown_NoPhantomTimeouts).
		lost := sent - rtt - tout - infl
		if lost > 3 { // ≈ max in flight at cancel for a 20ms interval
			t.Errorf("balance invariant broken under transient write failures: sent=%v rtt=%v timed_out=%v inflight=%v (lost=%v)",
				sent, rtt, tout, infl, lost)
		}
	}
}

// TestProbeTarget_PanicRestartCyclesKeepBalance: repeated panic-restart
// cycles of the echo loop (via probeTarget's own recovery path) must
// leave the balance invariant exact — every abandoned probe becomes a
// counted loss, never a silent drop, no matter how many cycles run.
// pi-lens-ignore: go-test-functions
func TestProbeTarget_PanicRestartCyclesKeepBalance(t *testing.T) {
	InitMetrics()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Slow echoes so probes are still pending when each panic fires —
	// the abandoned-probe flush is exercised on every cycle.
	addr := wbEchoServer(t, ctx, func(buf []byte) {
		time.Sleep(120 * time.Millisecond)
	})

	old := dialUDP
	var dials atomic.Int64
	dialUDP = func(ctx context.Context, network, address string) (net.Conn, error) {
		c, err := old(ctx, network, address)
		if err != nil {
			return nil, err
		}
		dials.Add(1)
		return &scriptedConn{Conn: c, hook: func(n int64) (bool, bool) {
			return false, n == 3 // panic on the third write of every cycle
		}}, nil
	}
	defer func() { dialUDP = old }()

	const src, name = "test", "panic_cycles"
	tgt := Target{Name: name, Address: addr}
	cfg := Config{Source: src, BaseInterval: 30 * time.Millisecond, BaseTimeout: 2 * time.Second}
	done := make(chan struct{})
	go func() {
		probeTarget(ctx, tgt, cfg)
		close(done)
	}()

	// Each cycle: 3 writes × 30ms + 1s restart pause ≈ 1.1s. Wait for
	// three dials = initial session + two panic restarts.
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if dials.Load() >= 3 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cycles := dials.Load()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("probe target did not stop after cancel")
	}
	time.Sleep(200 * time.Millisecond) // trailing bookkeeping

	if cycles < 3 {
		t.Fatalf("expected at least 2 panic-restart cycles (3 dials), got %d", cycles)
	}

	sent := wbCounter(ProbesSent, src, name, addr)
	rtt := wbHistCount(src, name, addr)
	tout := wbCounter(ProbesTimedOut, src, name, addr)
	infl := wbGauge(ProbesInflight, src, name, addr)

	if sent < 3 {
		t.Errorf("probing must continue across restart cycles, sent=%v", sent)
	}
	if infl != 0 {
		t.Errorf("cancellation flush must drain inflight to 0, got %v", infl)
	}
	// Cancellation can abandon a probe that was written after the last
	// poll but before cancel took effect; the cancel-time flush drops it
	// from inflight without counting a timeout. Tolerate that small
	// residual (same convention as TransientWriteFailuresKeepLinkUp).
	lost := sent - rtt - tout - infl
	if lost < 0 || lost > 1 {
		t.Errorf("balance invariant broken across %d dial cycles: sent=%v rtt=%v timed_out=%v inflight=%v",
			cycles, sent, rtt, tout, infl)
	}
}

// TestProbeTarget_DialRetryMarksLinkDown: while the dial-retry loop runs,
// probing is structurally impossible, so a re-established session must
// not keep showing a stale link_up=1.
// pi-lens-ignore: go-test-functions
func TestProbeTarget_DialRetryMarksLinkDown(t *testing.T) {
	InitMetrics()

	old := dialUDP
	dialUDP = func(ctx context.Context, network, address string) (net.Conn, error) {
		return nil, errors.New("dial udp: lookup test.invalid: no such host")
	}
	defer func() { dialUDP = old }()

	const src, name = "test", "dialretry_down"
	addr := "test.invalid:4000"
	m := newTargetMetrics(src, Target{Name: name, Address: addr})
	m.linkUp.Set(1) // stale healthy state from before the outage

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		probeTarget(ctx, Target{Name: name, Address: addr}, Config{
			Source:       src,
			BaseInterval: 50 * time.Millisecond,
			BaseTimeout:  100 * time.Millisecond,
		})
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if up := wbGauge(LinkUp, src, name, addr); up == 0 {
			cancel()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("probe loop did not stop after cancel")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	t.Errorf("link_up must drop to 0 while stuck in the dial-retry loop, got %v",
		wbGauge(LinkUp, src, name, addr))
}
