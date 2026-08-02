package prober_test

import (
	"context"
	"encoding/binary"
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

	rttVal := getHistogramMean(prober.RTTSeconds, targetName, addr)

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
	rttVal := getHistogramMean(prober.RTTSeconds, targetName, addr)

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

// TestRobustness_OutOfOrderResponses: the echo server must be able to
// return responses in a different order than sent (groups of three
// reversed). Every response must still be matched by sequence number,
// counted once, and no timeouts may be attributed to reordering.
func TestRobustness_OutOfOrderResponses(t *testing.T) {
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
		group := make([][]byte, 0, 3)
		for {
			if _, err := io.ReadFull(conn, buf); err != nil {
				return
			}
			group = append(group, append([]byte(nil), buf...))
			if len(group) == 3 {
				for i := 2; i >= 0; i-- {
					if _, err := conn.Write(group[i]); err != nil {
						return
					}
				}
				group = group[:0]
			}
		}
	}()

	targetName := "reorder_test"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := cfgWith(false, 50*time.Millisecond, 300*time.Millisecond, prober.Target{Name: targetName, Address: addr})

	startRecv := getCounterValue(prober.ProbesReceived, targetName, addr)
	startTimeout := getCounterValue(prober.ProbesTimedOut, targetName, addr)

	go prober.RunClient(ctx, cfg)
	time.Sleep(900 * time.Millisecond)
	cancel()

	endRecv := getCounterValue(prober.ProbesReceived, targetName, addr)
	endTimeout := getCounterValue(prober.ProbesTimedOut, targetName, addr)

	if endRecv-startRecv < 5 {
		t.Errorf("Out-of-order responses should all be matched by seq: received %v", endRecv-startRecv)
	}
	if endTimeout != startTimeout {
		t.Errorf("Reordering must not cause timeouts: %v -> %v", startTimeout, endTimeout)
	}
	if rtt := getHistogramMean(prober.RTTSeconds, targetName, addr); rtt <= 0 {
		t.Errorf("RTT must stay positive under reordering, got %v", rtt)
	}
}

// TestRobustness_DuplicateWithTamperedCopy: a valid echo followed
// immediately by a copy with a tampered timestamp must count exactly
// once — the second copy must be rejected, not double-counted or
// counted as a different response.
func TestRobustness_DuplicateWithTamperedCopy(t *testing.T) {
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
			tampered := append([]byte(nil), buf...)
			tampered[16] ^= 0xFF
			conn.Write(tampered)
		}
	}()

	targetName := "dup_tamper_test"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := cfgWith(false, 50*time.Millisecond, 300*time.Millisecond, prober.Target{Name: targetName, Address: addr})

	startRecv := getCounterValue(prober.ProbesReceived, targetName, addr)
	startSent := getCounterValue(prober.ProbesSent, targetName, addr)

	go prober.RunClient(ctx, cfg)
	time.Sleep(600 * time.Millisecond)
	cancel()

	recvDelta := getCounterValue(prober.ProbesReceived, targetName, addr) - startRecv
	sentDelta := getCounterValue(prober.ProbesSent, targetName, addr) - startSent

	if math.Abs(recvDelta-sentDelta) > 1 {
		t.Errorf("Tampered duplicate copies must not count: sent %v, received %v", sentDelta, recvDelta)
	}
}

// TestRobustness_LateResponsesIgnored: responses arriving after their
// probe already timed out must be silently dropped — never counted as
// received, never disrupting the probe loop.
func TestRobustness_LateResponsesIgnored(t *testing.T) {
	prober.InitMetrics()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	// Echo everything, but 250ms late — beyond the 100ms client timeout.
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
			time.Sleep(250 * time.Millisecond)
			if _, err := conn.Write(buf); err != nil {
				return
			}
		}
	}()

	targetName := "late_test"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := cfgWith(false, 50*time.Millisecond, 100*time.Millisecond, prober.Target{Name: targetName, Address: addr})

	startSent := getCounterValue(prober.ProbesSent, targetName, addr)
	startTimeout := getCounterValue(prober.ProbesTimedOut, targetName, addr)
	startRecv := getCounterValue(prober.ProbesReceived, targetName, addr)

	go prober.RunClient(ctx, cfg)
	time.Sleep(600 * time.Millisecond)
	cancel()

	sentDelta := getCounterValue(prober.ProbesSent, targetName, addr) - startSent
	timeoutDelta := getCounterValue(prober.ProbesTimedOut, targetName, addr) - startTimeout
	recvDelta := getCounterValue(prober.ProbesReceived, targetName, addr) - startRecv

	if sentDelta < 6 {
		t.Errorf("Expected probes to keep flowing through late responses, got %v", sentDelta)
	}
	if timeoutDelta < 3 {
		t.Errorf("Expected late responses to be counted as timeouts, got %v", timeoutDelta)
	}
	if recvDelta != 0 {
		t.Errorf("Late responses must never count as received, got %v", recvDelta)
	}
}

// TestRobustness_TrickleWrites: responses arriving one byte at a time
// must be reassembled by the reader and counted normally.
func TestRobustness_TrickleWrites(t *testing.T) {
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
			for i := 0; i < prober.PayloadSize; i++ {
				if _, err := conn.Write(buf[i : i+1]); err != nil {
					return
				}
				time.Sleep(8 * time.Millisecond)
			}
		}
	}()

	targetName := "trickle_test"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// One frame takes ~192ms to arrive and the server is serial, so the
	// probe interval must stay above the trickle duration or the backlog
	// would genuinely time out.
	cfg := cfgWith(false, 250*time.Millisecond, 400*time.Millisecond, prober.Target{Name: targetName, Address: addr})

	startRecv := getCounterValue(prober.ProbesReceived, targetName, addr)
	startTimeout := getCounterValue(prober.ProbesTimedOut, targetName, addr)

	go prober.RunClient(ctx, cfg)
	time.Sleep(1 * time.Second)
	cancel()

	recvDelta := getCounterValue(prober.ProbesReceived, targetName, addr) - startRecv
	timeoutDelta := getCounterValue(prober.ProbesTimedOut, targetName, addr) - startTimeout

	if recvDelta < 2 {
		t.Errorf("Trickled frames should be reassembled and counted, got %v", recvDelta)
	}
	if timeoutDelta != 0 {
		t.Errorf("Trickled frames must not time out, got %v", timeoutDelta)
	}
}

// TestRobustness_SpuriousValidFrames: frames with a valid magic header
// but a sequence number the client never sent must be ignored — they
// must not inflate the received counter or disturb in-flight probes.
func TestRobustness_SpuriousValidFrames(t *testing.T) {
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
		spurious := make([]byte, prober.PayloadSize)
		for {
			if _, err := io.ReadFull(conn, buf); err != nil {
				return
			}
			conn.Write(buf)
			// Valid magic + valid-looking ts, but a seq the client
			// could not have sent (client seqs start at 1 and grow).
			copy(spurious, buf)
			binary.LittleEndian.PutUint64(spurious[8:16], math.MaxUint64)
			conn.Write(spurious)
		}
	}()

	targetName := "spurious_test"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := cfgWith(false, 50*time.Millisecond, 300*time.Millisecond, prober.Target{Name: targetName, Address: addr})

	startRecv := getCounterValue(prober.ProbesReceived, targetName, addr)
	startSent := getCounterValue(prober.ProbesSent, targetName, addr)

	go prober.RunClient(ctx, cfg)
	time.Sleep(600 * time.Millisecond)
	cancel()

	recvDelta := getCounterValue(prober.ProbesReceived, targetName, addr) - startRecv
	sentDelta := getCounterValue(prober.ProbesSent, targetName, addr) - startSent

	if math.Abs(recvDelta-sentDelta) > 1 {
		t.Errorf("Spurious frames must be ignored: sent %v, received %v", sentDelta, recvDelta)
	}
}

// TestIsolation_BrokenTargetDoesNotAffectHealthy: a dead link and a
// healthy link monitored together must not contaminate each other's
// metrics — the healthy link keeps probing while the broken one
// accumulates connect failures.
func TestIsolation_BrokenTargetDoesNotAffectHealthy(t *testing.T) {
	prober.InitMetrics()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	healthyAddr := startEchoServer(ctx, t)
	deadAddr := "127.0.0.1:1" // nothing listening: instant refusal

	targets := []prober.Target{
		{Name: "healthy", Address: healthyAddr},
		{Name: "broken", Address: deadAddr},
	}
	cfg := cfgWith(false, 100*time.Millisecond, 500*time.Millisecond, targets...)

	go prober.RunClient(ctx, cfg)
	time.Sleep(1 * time.Second)

	if recv := getCounterValue(prober.ProbesReceived, "healthy", healthyAddr); recv <= 0 {
		t.Errorf("Healthy link should receive probes, got %v", recv)
	}
	if up := getGaugeValue(prober.LinkUp, "healthy", healthyAddr); up != 1 {
		t.Errorf("Healthy link must be up, got %v", up)
	}

	if up := getGaugeValue(prober.LinkUp, "broken", deadAddr); up != 0 {
		t.Errorf("Broken link must be down, got %v", up)
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
