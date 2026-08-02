package prober_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"tcp_ping_prometheus/internal/prober"
)

func TestMultiTargetProbing(t *testing.T) {
	prober.InitMetrics()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr1 := startEchoServer(ctx, t)
	addr2 := startEchoServer(ctx, t)

	targets := []prober.Target{
		{Name: "target1", Address: addr1},
		{Name: "target2", Address: addr2},
	}

	cfg := cfgWith(false, 50*time.Millisecond, 200*time.Millisecond, targets...)

	go func() {
		_ = prober.RunClient(ctx, cfg)
	}()

	time.Sleep(500 * time.Millisecond)

	verifyCounter(t, prober.ProbesSent, "target1", addr1)
	verifyCounter(t, prober.ProbesReceived, "target1", addr1)
	verifyCounter(t, prober.ProbesSent, "target2", addr2)
	verifyCounter(t, prober.ProbesReceived, "target2", addr2)
}

func TestServerDropout(t *testing.T) {
	prober.InitMetrics()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen error: %v", err)
	}
	serverAddr := ln.Addr().String()

	serverCtx, serverCancel := context.WithCancel(context.Background())
	defer serverCancel()

	closeConnCh := make(chan struct{})
	stopEchoCh := make(chan struct{})

	go func() {
		defer ln.Close()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, prober.PayloadSize)
		for {
			select {
			case <-closeConnCh:
				return
			case <-serverCtx.Done():
				return
			default:
				conn.SetReadDeadline(time.Now().Add(1 * time.Second))
				_, err := io.ReadFull(conn, buf)
				if err != nil {
					return
				}
				select {
				case <-stopEchoCh:
					continue
				default:
					conn.Write(buf)
				}
			}
		}
	}()

	targetName := "dropout_test"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := cfgWith(false, 50*time.Millisecond, 1*time.Second, prober.Target{Name: targetName, Address: serverAddr})

	initialTimeouts := getCounterValue(prober.ProbesTimedOut, targetName, serverAddr)

	go prober.RunClient(ctx, cfg)

	time.Sleep(200 * time.Millisecond)

	close(stopEchoCh)
	time.Sleep(190 * time.Millisecond)

	close(closeConnCh)
	time.Sleep(500 * time.Millisecond)

	finalTimeouts := getCounterValue(prober.ProbesTimedOut, targetName, serverAddr)
	diff := finalTimeouts - initialTimeouts

	t.Logf("Timeouts: initial=%v, final=%v, diff=%v", initialTimeouts, finalTimeouts, diff)

	if diff == 0 {
		t.Errorf("Expected timeouts to increase after dropout, got 0 increase")
	}
}

func TestStress_ManyTargets(t *testing.T) {
	prober.InitMetrics()

	count := 10
	var targets []prober.Target
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for i := 0; i < count; i++ {
		addr := startEchoServer(ctx, t)
		targets = append(targets, prober.Target{
			Name:    fmt.Sprintf("stress_%d", i),
			Address: addr,
		})
	}

	cfg := cfgWith(false, 50*time.Millisecond, 500*time.Millisecond, targets...)

	go prober.RunClient(ctx, cfg)

	time.Sleep(1 * time.Second)

	for _, tg := range targets {
		sent := getCounterValue(prober.ProbesSent, tg.Name, tg.Address)
		if sent < 5 {
			t.Errorf("Target %s sent count too low: %v", tg.Name, sent)
		}
	}
}
