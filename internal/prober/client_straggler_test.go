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

	"github.com/prometheus/client_golang/prometheus"
)

// blockingWriteConn wraps a live UDP socket and blocks its FIRST Write for
// delay, so the probe loop cannot join within a lowered stragglerStopTimeout.
// started is closed when that blocking write begins, letting a test trigger a
// reload exactly while the loop is stuck: a loop still waiting on its interval
// timer returns promptly on cancel and would never become a straggler.
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

// startStragglerFixture starts a real UDP echo responder and installs a dialUDP
// seam whose FIRST connection blocks its first write for delay (closing started
// when that write begins); later dials get a normal socket. The dialUDP restore
// is registered here, so a test's own cleanup (cancel + join RunClient) runs
// first and no production goroutine is still using the seam when it is put
// back.
func startStragglerFixture(t *testing.T, ctx context.Context, delay time.Duration) (addr string, started chan struct{}, dials *atomic.Int64) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
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

	started = make(chan struct{})
	dials = &atomic.Int64{}
	old := dialUDP
	dialUDP = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := old(ctx, network, address)
		if err != nil {
			return nil, err
		}
		if dials.Add(1) == 1 {
			return &blockingWriteConn{Conn: conn, delay: delay, started: started}, nil
		}
		return conn, nil
	}
	t.Cleanup(func() { dialUDP = old })
	return pc.LocalAddr().String(), started, dials
}

// wbSeriesExists reports whether family currently has a {source,target,address}
// series. It gathers from the registry instead of resolving via
// WithLabelValues, which CREATES a deleted series at zero and would make a
// "was it purged?" assertion impossible to fail.
func wbSeriesExists(t *testing.T, family, source, name, addr string) bool {
	t.Helper()
	fams, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fams {
		if f.GetName() != family {
			continue
		}
		for _, m := range f.GetMetric() {
			got := make(map[string]string, len(m.GetLabel()))
			for _, lp := range m.GetLabel() {
				got[lp.GetName()] = lp.GetValue()
			}
			if got["source"] == source && got["target"] == name && got["address"] == addr {
				return true
			}
		}
	}
	return false
}

func statusHasName(reg *StatusRegistry, name string) bool {
	return slices.ContainsFunc(reg.Snapshot(), func(s TargetStatus) bool { return s.Name == name })
}

// TestRunClient_StragglerStillWantedIsRestarted: a CHANGED target whose old
// loop misses the join bound must get its replacement loop as soon as the old
// one exits. The name is skipped while the straggler flag is set, so without
// the release path the target stayed unprobed — absent from /status and, for
// an interval/timeout change, still exporting its last link_up=1 — until an
// operator touched the targets file again.
func TestRunClient_StragglerStillWantedIsRestarted(t *testing.T) {
	InitMetrics()

	oldTimeout := stragglerStopTimeout
	stragglerStopTimeout = 200 * time.Millisecond
	defer func() { stragglerStopTimeout = oldTimeout }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr, started, dials := startStragglerFixture(t, ctx, 600*time.Millisecond)

	targetsPath := filepath.Join(t.TempDir(), "targets.json")
	const name = "straggler_restart"
	writeInterval := func(interval string) {
		content := `[{"name":"` + name + `","address":"` + addr + `","interval":"` + interval + `"}]`
		if err := os.WriteFile(targetsPath, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeInterval("50ms")

	statusReg := NewStatusRegistry()
	reload := make(chan os.Signal, 1)
	cfg := Config{
		Source:       "test",
		Targets:      []Target{{Name: name, Address: addr, Interval: 50 * time.Millisecond}},
		BaseInterval: 50 * time.Millisecond,
		BaseTimeout:  time.Second,
		TargetsPath:  targetsPath,
		ReloadSignal: reload,
		Status:       statusReg,
	}
	stopTimeoutsBefore := wbCounterLabels(ProberInternalErrors, "test", name, addr, "stop_timeout")
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

	// Change the interval (same name and address) and reload: stop() cancels,
	// the loop is stuck in Write, the join misses the 200ms bound and the name
	// becomes a straggler.
	writeInterval("40ms")
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
	// Non-vacuous guard: the join really timed out (this counter is written
	// only on the straggler path), so the restart above came from the release
	// path and not from an ordinary in-time stop+start.
	if got := wbCounterLabels(ProberInternalErrors, "test", name, addr, "stop_timeout"); got <= stopTimeoutsBefore {
		t.Fatalf("the join never timed out (%v -> %v): this run did not exercise the straggler path", stopTimeoutsBefore, got)
	}

	// And it must be a real loop, not a bookkeeping artefact: /status gets a
	// fresh snapshot for the target within an interval or two (40ms each).
	statusDeadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(statusDeadline) && !statusHasName(statusReg, name) {
		time.Sleep(20 * time.Millisecond)
	}
	if !statusHasName(statusReg, name) {
		t.Error("/status must report the restarted target: a restart invisible there is still a monitoring hole")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("RunClient did not stop after cancel")
	}
}

// TestRunClient_StragglerRemovedBeforeExitIsPurged: a target that becomes a
// straggler (changed) and is REMOVED while its old loop is still winding down
// must still lose its series and its /status entry. Deciding "still wanted" at
// mark time made that removal a silent no-op for the rest of the process
// lifetime: a ghost /status row plus a frozen link_up series — the exact
// failure the purge path exists to prevent.
func TestRunClient_StragglerRemovedBeforeExitIsPurged(t *testing.T) {
	InitMetrics()

	oldTimeout := stragglerStopTimeout
	stragglerStopTimeout = 200 * time.Millisecond
	defer func() { stragglerStopTimeout = oldTimeout }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Long enough to fit two reloads before the stuck loop exits.
	addr, started, _ := startStragglerFixture(t, ctx, 900*time.Millisecond)

	targetsPath := filepath.Join(t.TempDir(), "targets.json")
	const name = "straggler_removed"
	writeInterval := func(interval string) {
		content := `[{"name":"` + name + `","address":"` + addr + `","interval":"` + interval + `"}]`
		if err := os.WriteFile(targetsPath, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	removeAll := func() {
		if err := os.WriteFile(targetsPath, []byte("[]"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeInterval("50ms")

	statusReg := NewStatusRegistry()
	reload := make(chan os.Signal, 1)
	cfg := Config{
		Source:       "test",
		Targets:      []Target{{Name: name, Address: addr, Interval: 50 * time.Millisecond}},
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

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the first probe write never started (cpu load?)")
	}

	// 1) A change makes the name a straggler while it is still wanted.
	writeInterval("40ms")
	reload <- os.Interrupt
	// The supervisor is inside the 200ms join wait now; let it finish marking
	// the straggler before the second reload (still long before the 900ms
	// blocked write returns).
	time.Sleep(400 * time.Millisecond)

	// 2) Remove it before the old loop exits: nothing is in `live` any more,
	// so only the straggler release path can honour the removal.
	removeAll()
	reload <- os.Interrupt

	// The stuck write returns at ~900ms, the loop exits, and the supervisor
	// resolves the straggler against the now-empty desired set.
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if !wbSeriesExists(t, "link_up", "test", name, addr) && !statusHasName(statusReg, name) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if wbSeriesExists(t, "link_up", "test", name, addr) {
		t.Error("a straggler removed before its loop exited must have its series withdrawn (frozen link_up)")
	}
	if statusHasName(statusReg, name) {
		t.Error("a straggler removed before its loop exited must lose its /status entry")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("RunClient did not stop after cancel")
	}
}
