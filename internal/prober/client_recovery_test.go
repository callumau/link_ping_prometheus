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

// wbCounterLabels reads a counter series by its full label set. Unlike
// wbCounter it handles vecs whose label cardinality differs from the
// client {source,target,address} shape (e.g. ProberInternalErrors, which
// adds a reason label).
func wbCounterLabels(vec *prometheus.CounterVec, labels ...string) float64 {
	var m dto.Metric
	if err := vec.WithLabelValues(labels...).Write(&m); err != nil {
		return 0
	}
	return m.GetCounter().GetValue()
}

// wbRealEchoServer starts a production ServePacketConn echo responder on
// an ephemeral loopback port with a fail-closed allowlist, closing it on
// ctx cancellation. Unlike wbEchoServer it validates frames exactly like
// a deployed server (allowlist, size, magic), so link-up tests observe a
// genuine end-to-end echo rather than an unconditional reflector.
func wbRealEchoServer(t *testing.T, ctx context.Context, secret string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	allowed, err := ParseAllowlist("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		<-ctx.Done()
		pc.Close()
	}()
	go func() {
		ServePacketConn(ctx, pc, "test", allowed, secret)
	}()
	return pc.LocalAddr().String()
}

// deadlineFailConn is a net.Conn whose SetReadDeadline always fails, so
// the runEchoLoop reader gives up after its 3-failure bound. Read blocks
// until Close (returning net.ErrClosed); Write succeeds, so the main
// probe loop keeps sending until it notices the reader is gone. The short
// sleep before each failure keeps the reader alive across a few 10ms
// probe intervals, leaving several probes in flight so the reader-death
// flush (abandoned probes counted as timeouts) is exercised — while still
// dying well inside probeTarget's 1s re-dial pause the test cancels in.
type deadlineFailConn struct {
	closed chan struct{}
	once   sync.Once
}

func newDeadlineFailConn() *deadlineFailConn {
	return &deadlineFailConn{closed: make(chan struct{})}
}

func (c *deadlineFailConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}

func (c *deadlineFailConn) Write(b []byte) (int, error) { return len(b), nil }

func (c *deadlineFailConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *deadlineFailConn) LocalAddr() net.Addr  { return nil }
func (c *deadlineFailConn) RemoteAddr() net.Addr { return nil }
func (c *deadlineFailConn) SetDeadline(time.Time) error {
	return nil
}
func (c *deadlineFailConn) SetReadDeadline(time.Time) error {
	// Deliberate delay: see the type comment. Keeps the reader alive long
	// enough for probes to be in flight when it dies.
	// pi-lens-ignore: go-time-sleep-test
	time.Sleep(15 * time.Millisecond)
	return errors.New("injected SetReadDeadline failure")
}
func (c *deadlineFailConn) SetWriteDeadline(time.Time) error { return nil }

// readFailConn is a net.Conn whose Read returns a persistent non-timeout
// error every time (and whose SetReadDeadline succeeds, so the reader
// actually reaches Read). The reader must exit after the bounded
// maxConsecutiveReadFails instead of spinning forever.
type readFailConn struct{}

func newReadFailConn() *readFailConn { return &readFailConn{} }

func (c *readFailConn) Read([]byte) (int, error) {
	return 0, errors.New("injected persistent UDP read error")
}
func (c *readFailConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *readFailConn) Close() error                     { return nil }
func (c *readFailConn) LocalAddr() net.Addr              { return nil }
func (c *readFailConn) RemoteAddr() net.Addr             { return nil }
func (c *readFailConn) SetDeadline(time.Time) error      { return nil }
func (c *readFailConn) SetReadDeadline(time.Time) error  { return nil }
func (c *readFailConn) SetWriteDeadline(time.Time) error { return nil }

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
			// Deliberate injection: the panic-recovery contract is what
			// this test verifies.
			// pi-lens-ignore: go-direct-panic
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

// TestProbeTarget_DialRetryMarksLinkDown drives the REAL link_up
// transition, not the startup m.linkUp.Set(0): the target first reaches
// link_up=1 through authentic end-to-end echoes, then the dialer is
// flipped to fail and the periodic reconnect bounces the loop into the
// dial-retry path, where probing is structurally impossible. It also
// asserts that link_probes_sent_total freezes while dialing fails.
//
// Falsification: remove the dial-loop m.linkUp.Set(0) in client.go and
// this test fails. Without it, the pre-outage link_up=1 would survive the
// failed reconnect indefinitely — no probes are sent while dialing, so
// consecutiveMisses never advances to drop it — and step (2) would see a
// frozen link_up=1.
// pi-lens-ignore: go-test-functions
func TestProbeTarget_DialRetryMarksLinkDown(t *testing.T) {
	InitMetrics()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr := wbRealEchoServer(t, ctx, "")

	const src, name = "test", "dialretry_down"
	// Controllable dialer seam: healthy until the link is proven up, then
	// hard-failing to force the dial-retry path mid-run.
	var failDials atomic.Bool
	old := dialUDP
	dialUDP = func(ctx context.Context, network, address string) (net.Conn, error) {
		if failDials.Load() {
			return nil, errors.New("dial udp: lookup test.invalid: no such host")
		}
		return old(ctx, network, address)
	}
	defer func() { dialUDP = old }()

	cfg := Config{
		Source:            src,
		BaseInterval:      30 * time.Millisecond,
		BaseTimeout:       500 * time.Millisecond,
		ReconnectInterval: 200 * time.Millisecond,
	}
	done := make(chan struct{})
	go func() {
		probeTarget(ctx, Target{Name: name, Address: addr}, cfg)
		close(done)
	}()

	// (1) The link must genuinely come up: a real echo produces an RTT
	// sample and sets link_up=1.
	upDeadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(upDeadline) {
		if wbHistCount(src, name, addr) > 0 && wbGauge(LinkUp, src, name, addr) == 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if rtt, up := wbHistCount(src, name, addr), wbGauge(LinkUp, src, name, addr); rtt == 0 || up != 1 {
		cancel()
		<-done
		t.Fatalf("link never came up before the outage: rtt_samples=%v link_up=%v", rtt, up)
	}

	// (2) Flip the dialer to always fail; the next 200ms reconnect cycle
	// bounces probeTarget into the dial-retry loop.
	failDials.Store(true)
	downDeadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(downDeadline) {
		if wbGauge(LinkUp, src, name, addr) == 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if up := wbGauge(LinkUp, src, name, addr); up != 0 {
		cancel()
		<-done
		t.Fatalf("link_up must drop to 0 while stuck in the dial-retry loop, got %v", up)
	}

	// (3) Probing is structurally impossible while the dialer fails: no
	// new probe may reach the wire.
	sentAtDown := wbCounter(ProbesSent, src, name, addr)
	time.Sleep(500 * time.Millisecond)
	if got := wbCounter(ProbesSent, src, name, addr); got != sentAtDown {
		t.Errorf("link_probes_sent_total grew from %v to %v while probing was structurally impossible (dial failing)",
			sentAtDown, got)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("probe loop did not stop after cancel")
	}
}

// TestProbeTarget_ReaderDeathRedials: when the reader goroutine dies
// (persistent SetReadDeadline failures), every in-flight probe is a
// guaranteed loss and every later send would go unanswered, so the loop
// must NOT exit — it must re-dial. The abandoned probes are flushed as
// timeouts (link_probes_inflight drains to 0), the reason is recorded in
// link_prober_internal_errors_total, link_up is 0, and cancellation stops
// the loop cleanly with the sent balance exact.
// pi-lens-ignore: go-test-functions
func TestProbeTarget_ReaderDeathRedials(t *testing.T) {
	InitMetrics()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var dials atomic.Int64
	old := dialUDP
	dialUDP = func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return newDeadlineFailConn(), nil
	}
	defer func() { dialUDP = old }()

	const src, name, addr = "test", "reader_dead", "127.0.0.1:4000"
	// 10ms interval: the short-lived reader (3×15ms) still sees several
	// probes in flight before it dies, so the flush is genuinely exercised.
	cfg := Config{Source: src, BaseInterval: 10 * time.Millisecond, BaseTimeout: 300 * time.Millisecond}
	done := make(chan struct{})
	go func() {
		probeTarget(ctx, Target{Name: name, Address: addr}, cfg)
		close(done)
	}()

	// A second dial proves the loop re-dialed after the bounded pause
	// instead of exiting on reader death.
	dialDeadline := time.Now().Add(1800 * time.Millisecond)
	for time.Now().Before(dialDeadline) && dials.Load() < 2 {
		time.Sleep(10 * time.Millisecond)
	}
	if dials.Load() < 2 {
		cancel()
		<-done
		t.Fatalf("reader death must trigger a re-dial, got %d dials", dials.Load())
	}
	if got := wbCounterLabels(ProberInternalErrors, src, name, addr, "reader_dead"); got < 1 {
		t.Errorf("reader death must be counted in link_prober_internal_errors_total{reason=reader_dead}, got %v", got)
	}
	select {
	case <-done:
		t.Fatal("probe loop exited on reader death; it must keep re-dialing while ctx is live")
	default:
	}

	// Cancel during the bounded dial pause (after the current cycle's
	// reader has died and flushed): no probe is in flight, so the balance
	// is exact rather than off by the cancel-time abandoned probe. The
	// reader dies ~45ms after a dial, so 250ms lands squarely in the 1s
	// pause with ample margin for a loaded CI machine.
	time.Sleep(250 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("probe loop did not stop after cancel")
	}

	sent := wbCounter(ProbesSent, src, name, addr)
	rtt := wbHistCount(src, name, addr)
	tout := wbCounter(ProbesTimedOut, src, name, addr)
	infl := wbGauge(ProbesInflight, src, name, addr)
	if tout < 1 {
		t.Errorf("the reader-death flush must count in-flight probes as timeouts, got timed_out=%v", tout)
	}
	if infl != 0 {
		t.Errorf("reader-death flush must drain inflight to 0, got %v", infl)
	}
	if up := wbGauge(LinkUp, src, name, addr); up != 0 {
		t.Errorf("link_up must be 0 while the reader is dead, got %v", up)
	}
	if sent != rtt+tout+infl {
		t.Errorf("balance invariant broken after reader death: sent=%v rtt=%v timed_out=%v inflight=%v",
			sent, rtt, tout, infl)
	}
}

// TestProbeTarget_BoundedReadErrorsRedial: a reader whose Read keeps
// returning a persistent non-timeout error must exit after the bounded
// maxConsecutiveReadFails count (no busy-spin) and the loop must re-dial.
// pi-lens-ignore: go-test-functions
func TestProbeTarget_BoundedReadErrorsRedial(t *testing.T) {
	InitMetrics()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var dials atomic.Int64
	old := dialUDP
	dialUDP = func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return newReadFailConn(), nil
	}
	defer func() { dialUDP = old }()

	const src, name, addr = "test", "read_fail", "127.0.0.1:4000"
	cfg := Config{Source: src, BaseInterval: 30 * time.Millisecond, BaseTimeout: 300 * time.Millisecond}
	done := make(chan struct{})
	go func() {
		probeTarget(ctx, Target{Name: name, Address: addr}, cfg)
		close(done)
	}()

	dialDeadline := time.Now().Add(1800 * time.Millisecond)
	for time.Now().Before(dialDeadline) && dials.Load() < 2 {
		time.Sleep(10 * time.Millisecond)
	}
	if dials.Load() < 2 {
		cancel()
		<-done
		t.Fatalf("bounded read-error exit must trigger a re-dial, got %d dials", dials.Load())
	}
	if got := wbCounterLabels(ProberInternalErrors, src, name, addr, "reader_dead"); got < 1 {
		t.Errorf("the bounded read-error exit must be counted as reader_dead, got %v", got)
	}
	select {
	case <-done:
		t.Fatal("probe loop exited on reader death; it must keep re-dialing while ctx is live")
	default:
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("probe loop did not stop after cancel")
	}
}
