package prober

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// TestIsPeerUnreachable pins the ICMP-error classification that keeps a
// legitimately DOWN peer from killing its reader goroutine. On a connected
// UDP socket ECONNREFUSED/ECONNRESET (Linux port-unreachable / Windows
// reset) and EHOSTUNREACH/ENETUNREACH (a router replied unreachable) are
// the NORMAL "far end is down" signal: the probe must simply time out with
// its reader intact. Anything else is a local socket failure and counts
// toward the reader's bounded exit (maxConsecutiveReadFails), so a mutation
// that made every error classify as peer-unreachable (or none) is caught
// here.
func TestIsPeerUnreachable(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"ECONNREFUSED is a peer failure", syscall.ECONNREFUSED, true},
		{"ECONNRESET is a peer failure", syscall.ECONNRESET, true},
		{"EHOSTUNREACH is a peer failure", syscall.EHOSTUNREACH, true},
		{"ENETUNREACH is a peer failure", syscall.ENETUNREACH, true},
		{"wrapped errno still classifies", fmt.Errorf("read: %w", syscall.ECONNREFUSED), true},
		{"read deadline is a local failure", os.ErrDeadlineExceeded, false},
		{"generic error is a local failure", errors.New("injected read failure"), false},
		{"nil is not a peer failure", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isPeerUnreachable(tc.err); got != tc.want {
				t.Errorf("isPeerUnreachable(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// refuseConn is a net.Conn whose Read always returns ECONNREFUSED — the
// ICMP-derived signal a connected UDP socket produces when the far end has
// no listener — while Write succeeds so probes keep being sent. The short
// sleep models the real socket's blocking read (and keeps the reader from
// hot-spinning); it still lets the reader survive many read errors, so a
// regression treating ECONNREFUSED as a local failure would exhaust
// maxConsecutiveReadFails and kill the reader inside the test window.
type refuseConn struct{}

func (c *refuseConn) Read([]byte) (int, error) {
	// pi-lens-ignore: go-time-sleep-test
	time.Sleep(2 * time.Millisecond)
	return 0, syscall.ECONNREFUSED
}
func (c *refuseConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *refuseConn) Close() error                     { return nil }
func (c *refuseConn) LocalAddr() net.Addr              { return nil }
func (c *refuseConn) RemoteAddr() net.Addr             { return nil }
func (c *refuseConn) SetDeadline(time.Time) error      { return nil }
func (c *refuseConn) SetReadDeadline(time.Time) error  { return nil }
func (c *refuseConn) SetWriteDeadline(time.Time) error { return nil }

// TestProbeTarget_PeerUnreachableKeepsReaderAlive drives probeTarget with a
// socket whose Read keeps reporting ECONNREFUSED: the reader must treat it
// as the normal down-peer signal and stay alive, so the loop never re-dials
// and never records a reader_dead internal error. Falsification: make
// isPeerUnreachable always return false and the reader exits after
// maxConsecutiveReadFails, incrementing reason="reader_dead" and re-dialing
// once the bounded 1s pause elapses.
// pi-lens-ignore: go-test-functions
func TestProbeTarget_PeerUnreachableKeepsReaderAlive(t *testing.T) {
	InitMetrics()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var dials atomic.Int64
	old := dialUDP
	dialUDP = func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return &refuseConn{}, nil
	}
	defer func() { dialUDP = old }()

	const src, name, addr = "test", "refuse_alive", "127.0.0.1:4000"
	cfg := Config{Source: src, BaseInterval: 20 * time.Millisecond, BaseTimeout: 100 * time.Millisecond}
	done := make(chan struct{})
	go func() {
		probeTarget(ctx, Target{Name: name, Address: addr}, cfg)
		close(done)
	}()

	// Well past the point where a non-ICMP error would have killed the
	// reader (10 read failures ≈ 20ms) AND past probeTarget's 1s re-dial
	// pause, so a regressed reader is visible both as the reader_dead
	// counter and as a second dial.
	// pi-lens-ignore: go-time-sleep-test
	time.Sleep(1200 * time.Millisecond)

	if got := wbCounterLabels(ProberInternalErrors, src, name, addr, "reader_dead"); got != 0 {
		t.Errorf("peer-unreachable reads must not be counted as reader_dead, got %v", got)
	}
	if got := dials.Load(); got != 1 {
		t.Errorf("reader must survive repeated peer-unreachable reads; got %d dials", got)
	}
	if sent := wbCounter(ProbesSent, src, name, addr); sent == 0 {
		t.Error("loop stopped sending probes; a down peer must keep being probed")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("probe loop did not stop after cancel")
	}
}
