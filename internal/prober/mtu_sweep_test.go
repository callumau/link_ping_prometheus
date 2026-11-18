package prober

import (
	"context"
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
	cancel context.CancelFunc
	reads  atomic.Int64
}

func (c *cancelOnReadConn) Read([]byte) (int, error) {
	c.reads.Add(1)
	c.cancel()
	return 0, os.ErrDeadlineExceeded
}

func (c *cancelOnReadConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *cancelOnReadConn) Close() error                     { return nil }
func (c *cancelOnReadConn) LocalAddr() net.Addr              { return nil }
func (c *cancelOnReadConn) RemoteAddr() net.Addr             { return nil }
func (c *cancelOnReadConn) SetDeadline(time.Time) error      { return nil }
func (c *cancelOnReadConn) SetReadDeadline(time.Time) error  { return nil }
func (c *cancelOnReadConn) SetWriteDeadline(time.Time) error { return nil }

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
func (c *mtuBlockingSendConn) LocalAddr() net.Addr              { return nil }
func (c *mtuBlockingSendConn) RemoteAddr() net.Addr             { return nil }
func (c *mtuBlockingSendConn) SetDeadline(time.Time) error      { return nil }
func (c *mtuBlockingSendConn) SetReadDeadline(time.Time) error  { return nil }
func (c *mtuBlockingSendConn) SetWriteDeadline(time.Time) error { return nil }

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
