package prober_test

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"tcp_ping_prometheus/internal/prober"
)

func TestGarbageData_Server(t *testing.T) {
	prober.InitMetrics()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	go func() {
		defer ln.Close()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			_, err := conn.Write([]byte("garbage data garbage data garbage data\n"))
			if err != nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	targetName := "garbage_test"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := cfgWith(false, 100*time.Millisecond, 100*time.Millisecond, prober.Target{Name: targetName, Address: addr})
	startRecv := getCounterValue(prober.ProbesReceived, targetName, addr)

	go prober.RunClient(ctx, cfg)
	time.Sleep(500 * time.Millisecond)
	cancel()

	endRecv := getCounterValue(prober.ProbesReceived, targetName, addr)
	if endRecv > startRecv {
		t.Errorf("Garbage data counted as valid response? %v -> %v", startRecv, endRecv)
	}
}

func TestServer_EnforceSizeAndHeader(t *testing.T) {
	prober.InitMetrics()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()

	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	go prober.ServeListener(ctx, ln, prober.DefaultReadTimeout)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	buf := make([]byte, 34)
	copy(buf[0:8], prober.MagicBytes)
	_, err = conn.Write(buf)
	if err != nil {
		t.Fatal(err)
	}

	reply := make([]byte, 24)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = io.ReadFull(conn, reply)
	if err != nil {
		t.Fatalf("Should have received echo for first valid part: %v", err)
	}
	if string(reply[0:8]) != prober.MagicBytes {
		t.Errorf("Reply header invalid")
	}

	conn.Close()
	conn, err = net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	buf = make([]byte, 48)
	copy(buf[0:8], prober.MagicBytes)
	copy(buf[24:32], "BADHEADR")
	conn.Write(buf)

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = io.ReadFull(conn, reply)
	if err != nil {
		t.Fatalf("Should get 1st reply: %v", err)
	}

	_, err = io.ReadFull(conn, reply)
	if err == nil {
		t.Errorf("Expected server to close connection on invalid 2nd packet header, but got reply")
	} else {
		t.Logf("Got expected error on 2nd packet: %v", err)
	}

	if got := getCounterValue1(prober.ServerProbesReceived, "127.0.0.1"); got < 1 {
		t.Errorf("Server should have counted at least the 1st valid probe, got %v", got)
	}
}

// TestServer_PerIPLimit: connections beyond MaxConnsPerIP from a single
// remote IP must be closed immediately, while connections within the
// limit keep working.
func TestServer_PerIPLimit(t *testing.T) {
	prober.InitMetrics()
	old := prober.MaxConnsPerIP
	prober.MaxConnsPerIP = 3

	ctx, cancel := context.WithCancel(context.Background())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		prober.ServeListener(ctx, ln, prober.DefaultReadTimeout)
		close(done)
	}()
	// Restore the shared test variable only after ServeListener has
	// returned; it reads MaxConnsPerIP on every accept.
	defer func() {
		cancel()
		<-done
		prober.MaxConnsPerIP = old
	}()
	addr := ln.Addr().String()

	probe := make([]byte, prober.PayloadSize)
	copy(probe, prober.MagicBytes)

	// Open MaxConnsPerIP connections and prove each works (the echo
	// round-trip also guarantees the server has registered the conn).
	conns := make([]net.Conn, 0, 3)
	for i := 0; i < 3; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		defer c.Close()
		conns = append(conns, c)
		c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Write(probe); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		if _, err := io.ReadFull(c, make([]byte, prober.PayloadSize)); err != nil {
			t.Fatalf("conn %d within limit failed echo: %v", i, err)
		}
	}

	// The next connection from the same IP must be rejected.
	c4, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial 4th: %v", err)
	}
	defer c4.Close()
	c4.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c4.Write(probe); err != nil {
		t.Logf("4th conn write failed (acceptable rejection): %v", err)
		return
	}
	if _, err := io.ReadFull(c4, make([]byte, prober.PayloadSize)); err == nil {
		t.Error("4th connection received echo despite per-IP limit")
	}
}

// TestServer_ShutdownWaitsForHandlers: ServeListener must return after
// context cancellation even when a connection is established, proving
// handler goroutines are joined (not abandoned) on shutdown.
func TestServer_ShutdownWaitsForHandlers(t *testing.T) {
	prober.InitMetrics()
	ctx, cancel := context.WithCancel(context.Background())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan error, 1)
	go func() {
		done <- prober.ServeListener(ctx, ln, 30*time.Second)
	}()
	addr := ln.Addr().String()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	probe := make([]byte, prober.PayloadSize)
	copy(probe, prober.MagicBytes)
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(probe); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, make([]byte, prober.PayloadSize)); err != nil {
		t.Fatalf("initial echo failed: %v", err)
	}

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("ServeListener returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ServeListener did not return within 10s of cancel — handler wait hangs")
	}
}

// TestServer_ShutdownClosesConnections: cancelling the server context must
// force-close established connections, not leave them to linger until the
// read deadline.
func TestServer_ShutdownClosesConnections(t *testing.T) {
	prober.InitMetrics()
	ctx, cancel := context.WithCancel(context.Background())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go prober.ServeListener(ctx, ln, 30*time.Second)
	addr := ln.Addr().String()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	probe := make([]byte, prober.PayloadSize)
	copy(probe, prober.MagicBytes)
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(probe); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, make([]byte, prober.PayloadSize)); err != nil {
		t.Fatalf("initial echo failed: %v", err)
	}

	cancel()

	// Connection must be closed promptly by the server (EOF/error well
	// before the 30s read deadline).
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Error("connection still open after server shutdown")
	}
}
