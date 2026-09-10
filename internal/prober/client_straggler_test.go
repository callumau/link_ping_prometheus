package prober

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// blockingWriteConn wraps a live UDP socket and blocks its FIRST Write for
// delay, so the probe loop cannot join within a lowered stragglerStopTimeout.
// started is closed when that blocking write begins, letting the test trigger
// a reload exactly while the loop is stuck: a loop still waiting on its
// interval timer returns promptly on cancel and would never become a
// straggler.
type blockingWriteConn struct {
	net.Conn
	delay   time.Duration
	started chan struct{}
	once    sync.Once
}

func (c *blockingWriteConn) Write(b []byte) (int, error) {
	c.once.Do(func() {
		close(c.started)
		// pi-lens-ignore: go-time-sleep-test
		time.Sleep(c.delay)
	})
	return c.Conn.Write(b)
}

// TestRunClient_StragglerStillWantedIsRestarted: a CHANGED target whose old
// loop misses the join bound must get its replacement loop as soon as the old
// one exits. The name is skipped while the straggler flag is set and nothing
// re-ran apply afterwards, so the target stayed unprobed — absent from /status
// and, for an interval/timeout change, still exporting its last link_up=1 —
// until an operator touched the targets file again.
func TestRunClient_StragglerStillWantedIsRestarted(t *testing.T) {
	InitMetrics()

	oldTimeout := stragglerStopTimeout
	stragglerStopTimeout = 200 * time.Millisecond
	defer func() { stragglerStopTimeout = oldTimeout }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Real echo responder: the replacement must be a genuine probe loop.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, MaxDatagramSize)
		for ctx.Err() == nil {
			if err := pc.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
				return
			}
			n, raddr, err := pc.ReadFrom(buf)
			if err != nil {
				continue
			}
			pc.WriteTo(buf[:n], raddr)
		}
	}()
	addr := pc.LocalAddr().String()

	dir := t.TempDir()
	targetsPath := filepath.Join(dir, "targets.json")
	writeTargets := func(interval string) {
		content := `[{"name":"straggler_restart","address":"` + addr + `","interval":"` + interval + `"}]`
		if err := os.WriteFile(targetsPath, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeTargets("50ms")

	started := make(chan struct{})
	var dials atomic.Int64
	oldDial := dialUDP
	dialUDP = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := oldDial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		if dials.Add(1) == 1 {
			return &blockingWriteConn{Conn: conn, delay: 600 * time.Millisecond, started: started}, nil
		}
		return conn, nil
	}
	defer func() { dialUDP = oldDial }()

	statusReg := NewStatusRegistry()
	reload := make(chan os.Signal, 1)
	cfg := Config{
		Source:       "test",
		Targets:      []Target{{Name: "straggler_restart", Address: addr, Interval: 50 * time.Millisecond}},
		BaseInterval: 50 * time.Millisecond,
		BaseTimeout:  time.Second,
		TargetsPath:  targetsPath,
		ReloadSignal: reload,
		Status:       statusReg,
	}
	done := make(chan struct{})
	go func() {
		if err := RunClient(ctx, cfg); err != nil {
			t.Errorf("RunClient: %v", err)
		}
		close(done)
	}()

	// Wait until the first loop is stuck inside its write.
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the first probe write never started (cpu load?)")
	}

	// Change the target's interval (same name and address) and reload: stop()
	// cancels, the loop is stuck in Write, the join misses the 200ms bound
	// and the name becomes a straggler.
	writeTargets("40ms")
	reload <- os.Interrupt

	// The blocked write returns after 600ms; the replacement loop must dial
	// once the old loop exits (200ms join bound + 600ms block + margin).
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && dials.Load() < 2 {
		time.Sleep(20 * time.Millisecond)
	}
	if got := dials.Load(); got < 2 {
		t.Fatalf("a still-wanted straggler must be restarted after its old loop exits: got %d dials", got)
	}

	// And it must be a real loop, not a bookkeeping artefact: /status gets a
	// fresh snapshot for the target within an interval or two (40ms each).
	statusDeadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(statusDeadline) &&
		!slices.ContainsFunc(statusReg.Snapshot(), func(s TargetStatus) bool { return s.Name == "straggler_restart" }) {
		time.Sleep(20 * time.Millisecond)
	}
	if !slices.ContainsFunc(statusReg.Snapshot(), func(s TargetStatus) bool { return s.Name == "straggler_restart" }) {
		t.Error("/status must report the restarted target: a straggler restart that is invisible in /status is still a monitoring hole")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("RunClient did not stop after cancel")
	}
}
