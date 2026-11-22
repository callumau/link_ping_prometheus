package prober

import (
	"context"
	"log/slog"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

type blockingWriteCloseConn struct {
	stubConn
	closed    chan struct{}
	closeOnce sync.Once
	inWrite   chan struct{}
	writeOnce sync.Once
}

func newBlockingWriteCloseConn() *blockingWriteCloseConn {
	return &blockingWriteCloseConn{
		closed:  make(chan struct{}),
		inWrite: make(chan struct{}),
	}
}

func (c *blockingWriteCloseConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}

func (c *blockingWriteCloseConn) Write([]byte) (int, error) {
	c.writeOnce.Do(func() { close(c.inWrite) })
	<-c.closed
	return 0, os.ErrClosed
}

func (c *blockingWriteCloseConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

// stubbornWriteConn ignores Close inside Write until release is closed,
// simulating a kernel/socket stall that outlives tctx cancellation so stop()
// would wait for stragglerStopTimeout unless ctx.Done() breaks the wait.
type stubbornWriteConn struct {
	stubConn
	closed    chan struct{}
	closeOnce sync.Once
	inWrite   chan struct{}
	writeOnce sync.Once
	release   chan struct{}
}

func newStubbornWriteConn(release chan struct{}) *stubbornWriteConn {
	return &stubbornWriteConn{
		closed:  make(chan struct{}),
		inWrite: make(chan struct{}),
		release: release,
	}
}

func (c *stubbornWriteConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}

func (c *stubbornWriteConn) Write([]byte) (int, error) {
	c.writeOnce.Do(func() { close(c.inWrite) })
	<-c.release
	return 0, os.ErrClosed
}

func (c *stubbornWriteConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

type dummyReloadSignal struct{}

func (dummyReloadSignal) String() string { return "SIGHUP" }
func (dummyReloadSignal) Signal()        {}

// TestRunEchoLoop_WriteUnblocksOnCancel pins that cancelling ctx closes the
// socket immediately and unblocks a stalled conn.Write even when BaseTimeout
// is large (e.g. 1h).
func TestRunEchoLoop_WriteUnblocksOnCancel(t *testing.T) {
	InitMetrics()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	conn := newBlockingWriteCloseConn()
	m := newTargetMetrics("test", Target{Name: "write_cancel", Address: "192.0.2.10:4000"})
	cfg := Config{Source: "test", BaseInterval: 50 * time.Millisecond, BaseTimeout: time.Hour}

	done := make(chan error, 1)
	go func() {
		done <- runEchoLoop(ctx, conn, cfg, NewAdaptiveStats(cfg.BaseTimeout), m, &probeLoopState{}, slog.Default())
	}()

	select {
	case <-conn.inWrite:
	case <-time.After(2 * time.Second):
		t.Fatal("runEchoLoop never reached Write")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runEchoLoop did not unblock stalled Write on ctx cancel")
	}
}

// TestRunEchoLoop_CloseDoneBeforeReaderJoin verifies that on a non-shutdown
// exit (e.g., panic) with a full respCh, done is closed BEFORE <-readerDone so
// the reader exits immediately instead of stalling the full mtuReadArm (500ms).
func TestRunEchoLoop_CloseDoneBeforeReaderJoin(t *testing.T) {
	InitMetrics()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr := wbEchoServer(t, ctx, nil)
	realConn, err := dialUDP(ctx, "udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	conn := &scriptedConn{Conn: realConn, hook: func(n int64) (bool, bool) {
		if n == 5 {
			return false, true
		}
		return false, false
	}}

	m := newTargetMetrics("test", Target{Name: "done_order", Address: addr})
	cfg := Config{Source: "test", BaseInterval: 10 * time.Millisecond, BaseTimeout: 10 * time.Millisecond}

	start := time.Now()
	err = runEchoLoop(ctx, conn, cfg, NewAdaptiveStats(cfg.BaseTimeout), m, &probeLoopState{}, slog.Default())
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected panic error")
	}
	if elapsed >= 450*time.Millisecond {
		t.Fatalf("runEchoLoop exit took %v (>=450ms), suggesting readerDone join stalled on unclosed done channel", elapsed)
	}
}

// TestRunClient_StopRespectsContextCancel pins that RunClient shutdown does not
// wait sequentially for stragglerStopTimeout per target when the root ctx is
// cancelled mid-reload.
func TestRunClient_StopRespectsContextCancel(t *testing.T) {
	InitMetrics()
	origDial := dialUDP
	origTimeout := stragglerStopTimeout
	stragglerStopTimeout = 3 * time.Second
	defer func() {
		dialUDP = origDial
		stragglerStopTimeout = origTimeout
	}()

	release := make(chan struct{})
	defer close(release)

	var mu sync.Mutex
	var conns []*stubbornWriteConn
	dialUDP = func(context.Context, string, string) (net.Conn, error) {
		c := newStubbornWriteConn(release)
		mu.Lock()
		conns = append(conns, c)
		mu.Unlock()
		return c, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reloadCh := make(chan os.Signal, 1)
	targetsPath := writeTempTargetsFile(t, `[{"name":"a","address":"127.0.0.1:4001"},{"name":"b","address":"127.0.0.1:4002"}]`)

	cfg := Config{
		Source:       "test",
		Targets:      []Target{{Name: "a", Address: "127.0.0.1:4001"}, {Name: "b", Address: "127.0.0.1:4002"}},
		BaseInterval: 50 * time.Millisecond,
		BaseTimeout:  time.Second,
		TargetsPath:  targetsPath,
		ReloadSignal: reloadCh,
	}

	done := make(chan error, 1)
	go func() {
		done <- RunClient(ctx, cfg)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		ready := len(conns) == 2
		mu.Unlock()
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("targets did not dial")
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	c0, c1 := conns[0], conns[1]
	mu.Unlock()
	<-c0.inWrite
	<-c1.inWrite

	if err := os.WriteFile(targetsPath, []byte(`[]`), 0o600); err != nil {
		t.Fatal(err)
	}
	// Trigger reload so apply() enters stop(), then cancel root ctx shortly after;
	// stop() + drainLive() together take at most 1*stragglerStopTimeout (3s),
	// NOT 2*stragglerStopTimeout + drainLive (9s).
	start := time.Now()
	reloadCh <- dummyReloadSignal{}
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunClient stalled sequentially past single shutdown bound")
	}
	if elapsed := time.Since(start); elapsed >= 5*time.Second {
		t.Fatalf("RunClient took %v, expected < 5s", elapsed)
	}
}

func writeTempTargetsFile(t *testing.T, body string) string {
	t.Helper()
	p := t.TempDir() + "/targets.json"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
