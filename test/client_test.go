package prober_test

import (
	"context"
	"io"
	"math"
	"net"
	"testing"
	"time"

	"tcp_ping_prometheus/internal/prober"
)

func TestConnectionRefusedMetrics(t *testing.T) {
	prober.InitMetrics()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := cfgWith(false, 100*time.Millisecond, 100*time.Millisecond, prober.Target{Name: "refused_test", Address: addr})

	initialSent := getCounterValue(prober.ProbesSent, "refused_test", addr)
	initialTimeouts := getCounterValue(prober.ProbesTimedOut, "refused_test", addr)
	initialConnectFails := getCounterValue(prober.ConnectFailures, "refused_test", addr)
	initialDrops := getCounterValue(prober.ConnectionsDropped, "refused_test", addr)

	go prober.RunClient(ctx, cfg)

	time.Sleep(500 * time.Millisecond)

	finalSent := getCounterValue(prober.ProbesSent, "refused_test", addr)
	finalTimeouts := getCounterValue(prober.ProbesTimedOut, "refused_test", addr)
	finalConnectFails := getCounterValue(prober.ConnectFailures, "refused_test", addr)
	finalDrops := getCounterValue(prober.ConnectionsDropped, "refused_test", addr)

	if finalConnectFails <= initialConnectFails {
		t.Errorf("Expected connect failures to increase on connection refused, got %v -> %v", initialConnectFails, finalConnectFails)
	}
	if finalSent != initialSent {
		t.Errorf("Dial failures must not count as sent probes, got %v -> %v", initialSent, finalSent)
	}
	if finalTimeouts != initialTimeouts {
		t.Errorf("Dial failures must not count as probe timeouts, got %v -> %v", initialTimeouts, finalTimeouts)
	}
	if finalDrops != initialDrops {
		t.Errorf("Dial failures must not count as mid-connection drops, got %v -> %v", initialDrops, finalDrops)
	}
}

func TestAccuracy_PacketLoss(t *testing.T) {
	prober.InitMetrics()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	dropRate := 3
	totalPackets := 10

	go func() {
		defer ln.Close()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, prober.PayloadSize)
		count := 0
		for {
			if _, err := io.ReadFull(conn, buf); err != nil {
				return
			}
			count++
			if count%dropRate == 0 {
				continue
			}
			conn.Write(buf)
		}
	}()

	targetName := "loss_accuracy_test"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := cfgWith(false, 50*time.Millisecond, 100*time.Millisecond, prober.Target{Name: targetName, Address: addr})

	startSent := getCounterValue(prober.ProbesSent, targetName, addr)
	startTimeout := getCounterValue(prober.ProbesTimedOut, targetName, addr)

	go prober.RunClient(ctx, cfg)

	time.Sleep(time.Duration(totalPackets+2) * 50 * time.Millisecond)
	cancel()

	time.Sleep(200 * time.Millisecond)

	endSent := getCounterValue(prober.ProbesSent, targetName, addr)
	endTimeout := getCounterValue(prober.ProbesTimedOut, targetName, addr)

	sentCount := endSent - startSent
	timeoutCount := endTimeout - startTimeout

	if sentCount < float64(totalPackets) {
		t.Logf("Warning: Sent less packets than intended (%v < %v), cpu load?", sentCount, totalPackets)
	}

	expectedDrops := int(sentCount) / dropRate

	if math.Abs(timeoutCount-float64(expectedDrops)) > 1.5 {
		t.Errorf("Expected approx %d timeouts (sent %d, rate 1/%d), got %v", expectedDrops, int(sentCount), dropRate, timeoutCount)
	}
}

func TestAccuracy_HighLatency(t *testing.T) {
	prober.InitMetrics()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	delay := 150 * time.Millisecond

	go func() {
		defer ln.Close()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, prober.PayloadSize)
		for {
			if _, err := io.ReadFull(conn, buf); err != nil {
				return
			}
			time.Sleep(delay)
			conn.Write(buf)
		}
	}()

	targetName := "latency_test"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := cfgWith(true, 300*time.Millisecond, 50*time.Millisecond, prober.Target{Name: targetName, Address: addr})
	go prober.RunClient(ctx, cfg)

	time.Sleep(1500 * time.Millisecond)

	rttVal := getGaugeValue(prober.LastRTT, targetName, addr)

	if rttVal < delay.Seconds()-0.02 || rttVal > delay.Seconds()+0.05 {
		t.Errorf("RTT Accuracy mismatch: expected ~%vs, got %vs", delay.Seconds(), rttVal)
	}
}

func TestRobustness_CorruptSeq(t *testing.T) {
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
		buf := make([]byte, prober.PayloadSize)
		for {
			if _, err := io.ReadFull(conn, buf); err != nil {
				return
			}
			for i := 0; i < 8; i++ {
				buf[i] = ^buf[i]
			}
			conn.Write(buf)
		}
	}()

	targetName := "corrupt_test"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := cfgWith(false, 50*time.Millisecond, 100*time.Millisecond, prober.Target{Name: targetName, Address: addr})

	startRecv := getCounterValue(prober.ProbesReceived, targetName, addr)
	startTimeout := getCounterValue(prober.ProbesTimedOut, targetName, addr)

	go prober.RunClient(ctx, cfg)
	time.Sleep(500 * time.Millisecond)
	cancel()
	time.Sleep(100 * time.Millisecond)

	endRecv := getCounterValue(prober.ProbesReceived, targetName, addr)
	endTimeout := getCounterValue(prober.ProbesTimedOut, targetName, addr)

	if endRecv > startRecv {
		t.Errorf("Client should not have accepted corrupt packets, but Recv increased by %v", endRecv-startRecv)
	}
	if endTimeout <= startTimeout {
		t.Errorf("Client should have timed out on corrupt packets, but Timeout did not increase")
	}
}

func TestRobustness_PartialWrites(t *testing.T) {
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
		buf := make([]byte, prober.PayloadSize)
		for {
			if _, err := io.ReadFull(conn, buf); err != nil {
				return
			}
			chunk1 := buf[:8]
			chunk2 := buf[8:]
			conn.Write(chunk1)
			time.Sleep(10 * time.Millisecond)
			conn.Write(chunk2)
		}
	}()

	targetName := "partial_test"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := cfgWith(false, 100*time.Millisecond, 200*time.Millisecond, prober.Target{Name: targetName, Address: addr})

	startRecv := getCounterValue(prober.ProbesReceived, targetName, addr)
	go prober.RunClient(ctx, cfg)

	time.Sleep(500 * time.Millisecond)
	cancel()

	endRecv := getCounterValue(prober.ProbesReceived, targetName, addr)
	if endRecv <= startRecv {
		t.Errorf("Partial writes should be reassembled, but Recv count did not increase")
	}
}

func TestRobustness_StalledServer(t *testing.T) {
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
		buf := make([]byte, prober.PayloadSize)
		io.ReadFull(conn, buf)
		conn.Write(buf)
		io.Copy(io.Discard, conn)
	}()

	targetName := "stall_test"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := cfgWith(false, 50*time.Millisecond, 50*time.Millisecond, prober.Target{Name: targetName, Address: addr})

	startTimeout := getCounterValue(prober.ProbesTimedOut, targetName, addr)
	go prober.RunClient(ctx, cfg)

	time.Sleep(500 * time.Millisecond)
	cancel()
	time.Sleep(100 * time.Millisecond)

	endTimeout := getCounterValue(prober.ProbesTimedOut, targetName, addr)
	if endTimeout-startTimeout < 4 {
		t.Errorf("Expected significant timeouts during stall, got %v", endTimeout-startTimeout)
	}
}

func TestAccuracy_KnownLatencyAndLoss(t *testing.T) {
	prober.InitMetrics()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	delay := 17 * time.Millisecond
	dropMod := 4
	// Drop every 4th of the first dropWindow packets, echo everything
	// after that. All drops then age past the client timeout well before
	// measurement, so the expected count is exact and independent of
	// cancel-time in-flight state.
	dropWindow := 24

	go func() {
		defer ln.Close()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, prober.PayloadSize)
		count := 0
		for {
			if _, err := io.ReadFull(conn, buf); err != nil {
				return
			}
			count++
			if count <= dropWindow && count%dropMod == 0 {
				continue
			}
			time.Sleep(delay)
			conn.Write(buf)
		}
	}()

	targetName := "latency_loss_test"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := cfgWith(false, 50*time.Millisecond, 500*time.Millisecond, prober.Target{Name: targetName, Address: addr})

	startSent := getCounterValue(prober.ProbesSent, targetName, addr)
	startTimeout := getCounterValue(prober.ProbesTimedOut, targetName, addr)

	go prober.RunClient(ctx, cfg)
	// dropWindow packets take ~1.2s; their drops are all swept by ~1.7s.
	// 2.5s leaves ample margin under CI load.
	time.Sleep(2500 * time.Millisecond)
	cancel()
	time.Sleep(200 * time.Millisecond)

	endSent := getCounterValue(prober.ProbesSent, targetName, addr)
	endTimeout := getCounterValue(prober.ProbesTimedOut, targetName, addr)
	rttVal := getGaugeValue(prober.LastRTT, targetName, addr)

	sentCount := endSent - startSent
	timeoutCount := endTimeout - startTimeout

	if sentCount < float64(dropWindow) {
		t.Fatalf("Sent fewer probes (%v) than the drop window (%d) — cpu load?", sentCount, dropWindow)
	}

	expectedDrops := dropWindow / dropMod
	if math.Abs(timeoutCount-float64(expectedDrops)) > 0.5 {
		t.Errorf("Loss accuracy mismatch: expected exactly %d timeouts (1/%d of first %d), got %v", expectedDrops, dropMod, dropWindow, timeoutCount)
	}

	if rttVal < delay.Seconds()-0.003 || rttVal > delay.Seconds()+0.015 {
		t.Errorf("RTT accuracy mismatch: expected ~%vs (delay %v), got %vs", delay.Seconds(), delay, rttVal)
	}
}

func TestDuplicateResponse(t *testing.T) {
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
		buf := make([]byte, prober.PayloadSize)
		for {
			if _, err := io.ReadFull(conn, buf); err != nil {
				return
			}
			conn.Write(buf)
			conn.Write(buf)
		}
	}()

	targetName := "duplicate_test"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := cfgWith(false, 100*time.Millisecond, 500*time.Millisecond, prober.Target{Name: targetName, Address: addr})

	startRecv := getCounterValue(prober.ProbesReceived, targetName, addr)
	startSent := getCounterValue(prober.ProbesSent, targetName, addr)

	go prober.RunClient(ctx, cfg)
	time.Sleep(500 * time.Millisecond)
	cancel()

	endRecv := getCounterValue(prober.ProbesReceived, targetName, addr)
	endSent := getCounterValue(prober.ProbesSent, targetName, addr)

	recvDelta := endRecv - startRecv
	sentDelta := endSent - startSent

	if recvDelta > sentDelta+1 {
		t.Errorf("Duplicate responses counted! Sent %v, Recv %v", sentDelta, recvDelta)
	}
}

// TestRobustness_TimestampSpoof: responses with a valid seq but a tampered
// payload timestamp must be rejected (left to time out as loss), guarding
// RTT samples against corruption/replay/spoofing.
func TestRobustness_TimestampSpoof(t *testing.T) {
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
		buf := make([]byte, prober.PayloadSize)
		for {
			if _, err := io.ReadFull(conn, buf); err != nil {
				return
			}
			buf[16] ^= 0xFF // tamper with the echoed timestamp
			conn.Write(buf)
		}
	}()

	targetName := "spoof_ts_test"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := cfgWith(false, 50*time.Millisecond, 100*time.Millisecond, prober.Target{Name: targetName, Address: addr})

	startRecv := getCounterValue(prober.ProbesReceived, targetName, addr)
	startTimeout := getCounterValue(prober.ProbesTimedOut, targetName, addr)

	go prober.RunClient(ctx, cfg)
	time.Sleep(500 * time.Millisecond)
	cancel()
	time.Sleep(100 * time.Millisecond)

	endRecv := getCounterValue(prober.ProbesReceived, targetName, addr)
	endTimeout := getCounterValue(prober.ProbesTimedOut, targetName, addr)

	if endRecv > startRecv {
		t.Errorf("Client accepted responses with tampered timestamps: Recv increased by %v", endRecv-startRecv)
	}
	if endTimeout <= startTimeout {
		t.Errorf("Tampered responses should time out as loss, but Timeout did not increase")
	}
}

// TestLossRatioGauge: link_loss_ratio must track the application-
// visible loss ratio (timeouts over sent) over the sliding window.
func TestLossRatioGauge(t *testing.T) {
	prober.InitMetrics()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	// Echo every 2nd probe, drop the others.
	go func() {
		defer ln.Close()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, prober.PayloadSize)
		count := 0
		for {
			if _, err := io.ReadFull(conn, buf); err != nil {
				return
			}
			count++
			if count%2 == 0 {
				continue
			}
			conn.Write(buf)
		}
	}()

	targetName := "loss_gauge_test"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := cfgWith(false, 50*time.Millisecond, 150*time.Millisecond, prober.Target{Name: targetName, Address: addr})
	go prober.RunClient(ctx, cfg)

	time.Sleep(2 * time.Second)

	loss := getGaugeValue(prober.LinkLossRatio, targetName, addr)
	if loss <= 0 || loss >= 1 {
		t.Errorf("Expected loss gauge between 0 and 1 with 50%% drop server, got %v", loss)
	}
	if loss < 0.2 || loss > 0.8 {
		t.Errorf("Expected loss gauge near 0.5 with every-2nd probe dropped, got %v", loss)
	}
}

// TestGracefulShutdown_NoPhantomTimeouts: probes still in flight when the
// context is cancelled must NOT be flushed into ProbesTimedOut — otherwise
// every deploy/restart injects phantom packet loss.
func TestGracefulShutdown_NoPhantomTimeouts(t *testing.T) {
	prober.InitMetrics()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	// Echo only after 1s — far beyond the test window — so probes stay
	// in flight at cancel time without ever timing out (client timeout 5s).
	go func() {
		defer ln.Close()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, prober.PayloadSize)
		for {
			if _, err := io.ReadFull(conn, buf); err != nil {
				return
			}
			time.Sleep(1 * time.Second)
			conn.Write(buf)
		}
	}()

	targetName := "graceful_test"
	ctx, cancel := context.WithCancel(context.Background())

	cfg := cfgWith(false, 50*time.Millisecond, 5*time.Second, prober.Target{Name: targetName, Address: addr})

	startSent := getCounterValue(prober.ProbesSent, targetName, addr)
	startTimeout := getCounterValue(prober.ProbesTimedOut, targetName, addr)

	go prober.RunClient(ctx, cfg)
	time.Sleep(300 * time.Millisecond)
	cancel()
	time.Sleep(300 * time.Millisecond)

	endSent := getCounterValue(prober.ProbesSent, targetName, addr)
	endTimeout := getCounterValue(prober.ProbesTimedOut, targetName, addr)

	if endSent <= startSent {
		t.Fatalf("Expected probes to be sent, got %v -> %v", startSent, endSent)
	}
	if endTimeout != startTimeout {
		t.Errorf("Graceful shutdown must not flush in-flight probes to timeouts: %v -> %v", startTimeout, endTimeout)
	}
}

// TestDialHonoursCancellation: a dial to an unresponsive address must abort
// promptly on context cancellation, not block for the full dial timeout.
// 192.0.2.1 is TEST-NET-1 (RFC 5737) — SYNs go nowhere.
func TestDialHonoursCancellation(t *testing.T) {
	prober.InitMetrics()

	ctx, cancel := context.WithCancel(context.Background())
	cfg := cfgWith(false, 50*time.Millisecond, 100*time.Millisecond, prober.Target{Name: "dial_cancel_test", Address: "192.0.2.1:4000"})

	done := make(chan struct{})
	go func() {
		prober.RunClient(ctx, cfg)
		close(done)
	}()

	time.Sleep(200 * time.Millisecond) // let the dial get stuck
	cancel()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("RunClient did not return within 3s of cancel — dial ignored context")
	}
}
