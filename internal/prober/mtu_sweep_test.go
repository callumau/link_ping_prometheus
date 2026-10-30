package prober

import (
	"context"
	"net"
	"os"
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
