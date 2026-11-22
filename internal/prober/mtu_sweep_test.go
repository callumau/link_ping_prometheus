package prober

import (
	"context"
	"encoding/binary"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// cancelOnReadConn cancels the sweep's context on the first Read and then
// reports a deadline error: the probe was written, but the read returned
// because the sweep was cancelled, not because the path dropped the probe.
type cancelOnReadConn struct {
	stubConn
	cancel context.CancelFunc
	reads  atomic.Int64
}

func (c *cancelOnReadConn) Read([]byte) (int, error) {
	c.reads.Add(1)
	c.cancel()
	return 0, os.ErrDeadlineExceeded
}

// TestMTUSweep_CancelledProbeIsNotLost pins the guard at mtu.go's waitEcho:
// a sweep cancelled by reload/shutdown must NOT count the probe in
// link_mtu_probes_lost_total. The counter feeds the lost/sent ratio operators
// alert on, so a mid-sweep teardown that fabricated a loss would page on a
// deploy. The connection cancels the context from inside Read, which is the
// same exit readEcho returns ctx.Err() on; only a probe that got no echo
// inside its full deadline may count.
func TestMTUSweep_CancelledProbeIsNotLost(t *testing.T) {
	InitMetrics()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	m := newTargetMetrics("test", Target{Name: "mtu_cancel", Address: "192.0.2.1:4000"})
	const src, name, addr = "test", "mtu_cancel", "192.0.2.1:4000"
	conn := &cancelOnReadConn{cancel: cancel}
	state := &probeLoopState{}
	cfg := Config{BaseTimeout: time.Second}

	largest, ok := sweepOnce(ctx, conn, cfg, m, state)
	if ok {
		t.Fatalf("a cancelled sweep must not report success, got largest=%d", largest)
	}
	if got := wbCounterLabels(MTUProbesSent, src, name, addr); got < 1 {
		t.Fatalf("the cancellation must happen after a probe was sent, sent=%v", got)
	}
	if got := wbCounterLabels(MTUProbesLost, src, name, addr); got != 0 {
		t.Fatalf("a cancelled sweep must not count a lost probe, lost=%v", got)
	}
	if got := conn.reads.Load(); got != 1 {
		t.Fatalf("the sweep must stop after the cancelled read, reads=%d", got)
	}
}

// mtuBlockingSendConn blocks in Write until Close is called, the way a DF send
// does when the local send buffer is saturated. It lets the test drive the
// send-side cancellation path that the read-only test above cannot reach.
type mtuBlockingSendConn struct {
	stubConn
	closed     chan struct{}
	closeOnce  sync.Once
	written    chan struct{}
	writeStart sync.Once
}

func newBlockingWriteConn() *mtuBlockingSendConn {
	return &mtuBlockingSendConn{closed: make(chan struct{}), written: make(chan struct{})}
}

func (c *mtuBlockingSendConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, os.ErrClosed
}

func (c *mtuBlockingSendConn) Write(p []byte) (int, error) {
	c.writeStart.Do(func() { close(c.written) })
	<-c.closed
	return 0, os.ErrClosed
}

func (c *mtuBlockingSendConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

// TestMTUSweep_CancelledSendIsNotLost pins the send-side twin of the guard
// above: when the sweep is cancelled while a DF write is blocked in the
// kernel, the probe must not be charged in link_mtu_probes_lost_total. The
// send used to increment the counter unconditionally and to sit in Write
// until the full probe deadline, stranding the target's tracked join.
func TestMTUSweep_CancelledSendIsNotLost(t *testing.T) {
	InitMetrics()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	m := newTargetMetrics("test", Target{Name: "mtu_send_cancel", Address: "192.0.2.2:4000"})
	const src, name, addr = "test", "mtu_send_cancel", "192.0.2.2:4000"
	conn := newBlockingWriteConn()
	state := &probeLoopState{}
	// Long enough that a wedged send would clearly outlive the test's bound.
	cfg := Config{BaseTimeout: 30 * time.Second}

	done := make(chan struct{})
	go func() {
		defer close(done)
		sweepOnce(ctx, conn, cfg, m, state)
	}()
	select {
	case <-conn.written:
	case <-time.After(2 * time.Second):
		t.Fatal("the sweep never attempted a write")
	}
	cancel()
	// Closing the socket is what a cancelled sweep does to unblock the send;
	// sweepOnce's sandboxed unit is not wired to runMTUSweep's watcher, so
	// this test closes it the same way.
	conn.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a cancelled send kept sweepOnce blocked past the join bound")
	}
	if got := wbCounterLabels(MTUProbesLost, src, name, addr); got != 0 {
		t.Fatalf("a cancelled send must not count a lost probe, lost=%v", got)
	}
}

type cancelOnFinalStepConn struct {
	stubConn
	cancel  context.CancelFunc
	header  int
	writes  int
	seqs    []uint64
	lastReq []byte
}

func (c *cancelOnFinalStepConn) Write(p []byte) (int, error) {
	c.writes++
	c.lastReq = append(c.lastReq[:0], p...)
	c.seqs = append(c.seqs, binary.LittleEndian.Uint64(p[8:16]))
	return len(p), nil
}

func (c *cancelOnFinalStepConn) Read(p []byte) (int, error) {
	// Answer the MaxPayloadBytes check? No — fail it so binary search starts,
	// answer payload=0 check, answer mid=MaxPayloadBytes/2, then cancel on
	// the very last binary-search iteration (when payload == MaxPayloadBytes-1
	// or once lo==hi is reached). Simplest: fail MaxPayloadBytes, pass 0,
	// then pass every mid EXCEPT when payload == 1, where we cancel on read!
	// Wait: with lo=1, hi=MaxPayloadBytes-1: if every mid fails, binary search
	// steps down to lo=1, hi=1 -> mid=1. Cancelling when payload==1 cancels on
	// the exact final iteration!
	payload := len(c.lastReq) - c.header
	if payload == 0 {
		return copy(p, c.lastReq), nil
	}
	if payload == 1 {
		c.cancel()
		return 0, os.ErrDeadlineExceeded
	}
	return 0, os.ErrDeadlineExceeded
}

// TestMTUSweep_CancelOnFinalStepDoesNotPublishPartialMTU pins that cancelling
// during the last binary-search iteration returns ok=false instead of publishing
// an incomplete best payload size.
func TestMTUSweep_CancelOnFinalStepDoesNotPublishPartialMTU(t *testing.T) {
	InitMetrics()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	m := newTargetMetrics("test", Target{Name: "mtu_final_cancel", Address: "192.0.2.3:4000"})
	conn := &cancelOnFinalStepConn{cancel: cancel, header: PayloadSize}
	cfg := Config{BaseTimeout: 5 * time.Millisecond}

	largest, ok := sweepOnce(ctx, conn, cfg, m, &probeLoopState{})
	if ok || largest != -1 {
		t.Fatalf("cancelled final-step sweep returned (%d, %v), want (-1, false)", largest, ok)
	}
}

// TestMTUSweep_SeqDisjointFromMainLoop pins that MTU sweep sequences sit in the
// upper half of uint64 so they never collide with runEchoLoop's 1..N sequences
// in echoDupGuard on Windows's coarse clock tick.
func TestMTUSweep_SeqDisjointFromMainLoop(t *testing.T) {
	InitMetrics()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	m := newTargetMetrics("test", Target{Name: "mtu_seq_base", Address: "192.0.2.4:4000"})
	conn := &cancelOnFinalStepConn{cancel: cancel, header: PayloadSize}
	cfg := Config{BaseTimeout: 5 * time.Millisecond}

	sweepOnce(ctx, conn, cfg, m, &probeLoopState{})
	if len(conn.seqs) == 0 {
		t.Fatal("expected at least one probe written")
	}
	for i, s := range conn.seqs {
		if s < (1 << 63) {
			t.Fatalf("MTU seq[%d] = %d overlaps low main-loop sequence space", i, s)
		}
	}
}

// TestMTUSweep_PanicIsolated verifies that a panic inside runMTUSweep is
// recovered and recorded in ProberInternalErrors instead of crashing the agent.
func TestMTUSweep_PanicIsolated(t *testing.T) {
	InitMetrics()
	origDial := dialUDP
	dialUDP = func(context.Context, string, string) (net.Conn, error) {
		panic("injected dial panic in mtu sweep")
	}
	defer func() { dialUDP = origDial }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tg := Target{Name: "mtu_panic", Address: "192.0.2.5:4000"}
	m := newTargetMetrics("test", tg)
	before := wbCounterLabels(ProberInternalErrors, "test", tg.Name, tg.Address, "panic")

	runMTUSweep(ctx, tg, Config{Source: "test", BaseTimeout: time.Second, MTUSweep: time.Minute}, m, &probeLoopState{}, slog.Default())

	after := wbCounterLabels(ProberInternalErrors, "test", tg.Name, tg.Address, "panic")
	if after != before+1 {
		t.Fatalf("internal panic counter = %v, want %v", after, before+1)
	}
}
