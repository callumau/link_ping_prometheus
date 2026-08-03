package prober_test

import (
	"context"
	"fmt"
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
	verifyHistogramCount(t, prober.RTTSeconds, "target1", addr1)
	verifyCounter(t, prober.ProbesSent, "target2", addr2)
	verifyHistogramCount(t, prober.RTTSeconds, "target2", addr2)
}

// TestServerDropout: a remote that stops echoing (then disappears) must
// show up as real timeouts and a down link — UDP has no retransmission
// to hide it.
func TestServerDropout(t *testing.T) {
	prober.InitMetrics()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen error: %v", err)
	}
	serverAddr := pc.LocalAddr().String()

	stopEchoCh := make(chan struct{})
	closeCh := make(chan struct{})

	go func() {
		buf := make([]byte, 1500)
		for {
			select {
			case <-closeCh:
				pc.Close()
				return
			default:
			}
			n, raddr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n != prober.PayloadSize || string(buf[0:8]) != prober.MagicBytes {
				continue
			}
			select {
			case <-stopEchoCh:
				continue
			default:
				pc.WriteTo(buf[:n], raddr)
			}
		}
	}()

	targetName := "dropout_test"
	cfg := cfgWith(false, 50*time.Millisecond, 300*time.Millisecond, prober.Target{Name: targetName, Address: serverAddr})

	initialTimeouts := getCounterValue(prober.ProbesTimedOut, targetName, serverAddr)

	go prober.RunClient(ctx, cfg)

	time.Sleep(200 * time.Millisecond)

	close(stopEchoCh)
	// Probes now go unanswered and must time out after the 300ms RTO.
	time.Sleep(500 * time.Millisecond)

	close(closeCh)
	time.Sleep(200 * time.Millisecond)

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
