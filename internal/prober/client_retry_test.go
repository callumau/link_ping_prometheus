package prober

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
)

// TestProbeTargetRetriesOnDialFailure: a dial error (e.g. a transient DNS
// resolution failure at startup) must not kill the target's probe loop —
// it keeps retrying until the context is cancelled. Uses the dialUDP seam
// instead of an unresolvable hostname so the test is deterministic and
// has no dependency on the local resolver.
// pi-lens-ignore: go-test-functions
func TestProbeTargetRetriesOnDialFailure(t *testing.T) {
	InitMetrics()

	var dials atomic.Int64
	old := dialUDP
	dialUDP = func(ctx context.Context, network, address string) (net.Conn, error) {
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

// failingConn is a net.Conn whose Write always fails and whose Read
// returns net.ErrClosed immediately, exercising the persistent
// send-failure path deterministically (no real socket needed).
type failingConn struct{}

func (failingConn) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (failingConn) Write([]byte) (int, error)        { return 0, errors.New("write udp: operation not permitted") }
func (failingConn) Close() error                     { return nil }
func (failingConn) LocalAddr() net.Addr              { return nil }
func (failingConn) RemoteAddr() net.Addr             { return nil }
func (failingConn) SetDeadline(time.Time) error      { return nil }
func (failingConn) SetReadDeadline(time.Time) error  { return nil }
func (failingConn) SetWriteDeadline(time.Time) error { return nil }

// TestProbeTargetCountsSendErrors: persistent UDP write failures are
// counted per attempt (never as sent) and drop link_up after the third
// consecutive failure — send errors are a local fault, not network loss.
// pi-lens-ignore: go-test-functions
func TestProbeTargetCountsSendErrors(t *testing.T) {
	InitMetrics()

	old := dialUDP
	dialUDP = func(context.Context, string, string) (net.Conn, error) {
		return failingConn{}, nil
	}
	defer func() { dialUDP = old }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		probeTarget(ctx, Target{Name: "senderr", Address: "127.0.0.1:4000"}, Config{
			Source:       "test",
			BaseInterval: 20 * time.Millisecond,
			BaseTimeout:  200 * time.Millisecond,
		})
		close(done)
	}()

	// ~10 write attempts at a 20ms interval; the third consecutive
	// failure must already have dropped link_up.
	time.Sleep(200 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("probe loop did not stop after cancel")
	}

	var m dto.Metric
	if err := SendErrors.WithLabelValues("test", "senderr", "127.0.0.1:4000").Write(&m); err != nil {
		t.Fatalf("send errors series missing: %v", err)
	}
	if n := m.GetCounter().GetValue(); n < 3 {
		t.Errorf("expected >=3 send errors counted, got %v", n)
	}

	// Nothing reached the wire, so sent and the balance series stay 0.
	if n := ProbesSent.WithLabelValues("test", "senderr", "127.0.0.1:4000"); n != nil {
		var sm dto.Metric
		if err := n.Write(&sm); err != nil {
			t.Fatal(err)
		}
		if got := sm.GetCounter().GetValue(); got != 0 {
			t.Errorf("failed sends must not count as sent, got %v", got)
		}
	}
	var gm dto.Metric
	if err := LinkUp.WithLabelValues("test", "senderr", "127.0.0.1:4000").Write(&gm); err != nil {
		t.Fatalf("link_up series missing: %v", err)
	}
	if v := gm.GetGauge().GetValue(); v != 0 {
		t.Errorf("expected link_up=0 after persistent send failures, got %v", v)
	}
}
