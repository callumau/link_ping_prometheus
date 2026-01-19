package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestLoadTargets(t *testing.T) {
	// Create a temporary file
	tmpfile, err := os.CreateTemp("", "targets-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name()) // clean up

	// Case 1: Valid targets
	targets := []Target{
		{Name: "google", Address: "google.com:80"},
		{Name: "local", Address: "localhost:4000"},
	}
	data, _ := json.Marshal(targets)
	if _, err := tmpfile.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	loaded, err := loadTargets(tmpfile.Name())
	if err != nil {
		t.Fatalf("loadTargets failed: %v", err)
	}
	if len(loaded) != 2 {
		t.Errorf("expected 2 targets, got %d", len(loaded))
	}
	if loaded[0].Name != "google" {
		t.Errorf("expected first target name 'google', got %s", loaded[0].Name)
	}

	// Case 2: Invalid JSON
	tmpfileInvalid, _ := os.CreateTemp("", "invalid-*.json")
	defer os.Remove(tmpfileInvalid.Name())
	tmpfileInvalid.Write([]byte("{invalid-json"))
	tmpfileInvalid.Close()

	_, err = loadTargets(tmpfileInvalid.Name())
	if err == nil {
		t.Error("expected error for invalid json, got nil")
	}

	// Case 3: Missing file
	_, err = loadTargets("non-existent-file.json")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestMultiTargetProbing(t *testing.T) {
	initMetrics()

	// Start two echo servers
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr1 := startEchoServer(ctx, t)
	addr2 := startEchoServer(ctx, t)

	targets := []Target{
		{Name: "target1", Address: addr1},
		{Name: "target2", Address: addr2},
	}

	interval := 50 * time.Millisecond
	timeout := 200 * time.Millisecond

	*flAdaptive = false
	*flBaseInterval = interval
	*flBaseTimeout = timeout

	// Run clients in a background goroutine
	go func() {
		_ = startProbing(ctx, targets)
	}()

	// Wait for some probes to happen
	time.Sleep(500 * time.Millisecond)

	// Verify metrics for both targets
	verifyMetric(t, metricSent, "target1", addr1)
	verifyMetric(t, metricRecv, "target1", addr1)
	verifyMetric(t, metricSent, "target2", addr2)
	verifyMetric(t, metricRecv, "target2", addr2)
}

func TestServerDropout(t *testing.T) {
	initMetrics()

	// 1. Setup global flags
	// We use a short interval to ensure we send packets quickly
	interval := 50 * time.Millisecond
	*flAdaptive = false
	*flBaseInterval = interval
	*flBaseTimeout = 1 * time.Second

	// 2. Start a custom "flaky" server
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen error: %v", err)
	}
	serverAddr := ln.Addr().String()

	serverCtx, serverCancel := context.WithCancel(context.Background())
	defer serverCancel()

	// Control channel to tell server when to close connection
	closeConnCh := make(chan struct{})
	// Control channel to tell server to stop echoing (simulate packet loss/hang)
	stopEchoCh := make(chan struct{})

	go func() {
		defer ln.Close()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, payloadSize)
		for {
			select {
			case <-closeConnCh:
				return // Close connection
			case <-serverCtx.Done():
				return
			default:
				// Read
				conn.SetReadDeadline(time.Now().Add(1 * time.Second))
				_, err := io.ReadFull(conn, buf)
				if err != nil {
					return
				}

				// Decide whether to echo
				select {
				case <-stopEchoCh:
					// Don't echo, just consume
					continue
				default:
					// Echo back
					conn.Write(buf)
				}
			}
		}
	}()

	// 3. Start Client Prober
	targetName := "dropout_test"
	targets := []Target{{Name: targetName, Address: serverAddr}}

	clientCtx, clientCancel := context.WithCancel(context.Background())
	defer clientCancel()

	// Initial timeout count
	initialTimeouts := getCounterValue(metricTimeout, targetName, serverAddr)

	go func() {
		startProbing(clientCtx, targets)
	}()

	// 4. Let it run normally for a bit
	time.Sleep(200 * time.Millisecond)

	// 5. Tell server to stop echoing (packets will be pending)
	close(stopEchoCh)

	// Let client send a few more packets that won't get responses
	time.Sleep(190 * time.Millisecond)

	// 6. Kill the connection
	close(closeConnCh)

	// Wait for client to detect error and run cleanup
	time.Sleep(500 * time.Millisecond)

	// 7. Check metrics
	finalTimeouts := getCounterValue(metricTimeout, targetName, serverAddr)
	diff := finalTimeouts - initialTimeouts

	t.Logf("Timeouts: initial=%v, final=%v, diff=%v", initialTimeouts, finalTimeouts, diff)

	if diff == 0 {
		t.Errorf("Expected timeouts to increase after dropout, got 0 increase")
	}
}

func startEchoServer(ctx context.Context, t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	// Start accepting
	go func() {
		defer ln.Close()
		go func() {
			<-ctx.Done()
			ln.Close()
		}()

		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleServerConn(ctx, conn)
		}
	}()

	return ln.Addr().String()
}

func verifyMetric(t *testing.T, vec *prometheus.CounterVec, targetName, address string) {
	val := getCounterValue(vec, targetName, address)
	if val <= 0 {
		t.Errorf("expected metric value > 0 for target %s (addr %s), got %v", targetName, address, val)
	}
}

func getCounterValue(vec *prometheus.CounterVec, targetName, address string) float64 {
	var m dto.Metric
	if err := vec.WithLabelValues(targetName, address).Write(&m); err != nil {
		return 0
	}
	return m.GetCounter().GetValue()
}

func TestConnectionRefusedMetrics(t *testing.T) {
	initMetrics()

	// Pick a random port that is likely closed
	// or use a listener to get a free port, then close it immediately
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close() // Close immediately so connection gets refused

	targets := []Target{
		{Name: "refused_test", Address: addr},
	}

	// Set short interval/timeouts for test speed
	*flAdaptive = false
	*flBaseInterval = 100 * time.Millisecond
	*flBaseTimeout = 100 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	initialSent := getCounterValue(metricSent, "refused_test", addr)
	initialTimeouts := getCounterValue(metricTimeout, "refused_test", addr)

	go startProbing(ctx, targets)

	// Wait for a few "probes" (connection attempts)
	// The code currently has a 2s backoff on connection failure.
	// We matched 2s hardcoded in the source.
	// To test this effectively without waiting 2s per inc, we might need to sleep > 2s
	// or rely on the initial failure incrementing at least once.
	// Since we sleep 2s, let's wait 100ms. We should see at least 1 increment immediately on the first attempt.
	time.Sleep(500 * time.Millisecond)

	finalSent := getCounterValue(metricSent, "refused_test", addr)
	finalTimeouts := getCounterValue(metricTimeout, "refused_test", addr)

	if finalSent <= initialSent {
		t.Errorf("Expected sent count to increase on connection refused, got %v -> %v", initialSent, finalSent)
	}
	if finalTimeouts <= initialTimeouts {
		t.Errorf("Expected timeout count to increase on connection refused, got %v -> %v", initialTimeouts, finalTimeouts)
	}

	cancel()
}

// ==========================================
// Stringent / Real World Test Cases (Added)
// ==========================================

// TestAdaptiveStats_Logic verifies the math behind RTO calculations
func TestAdaptiveStats_Logic(t *testing.T) {
	stats := newAdaptiveStats()

	// Initial State
	if stats.srtt != 0 {
		t.Errorf("Expected initial SRTT 0, got %f", stats.srtt)
	}

	// 1. First RTT measurement: 100ms
	rtt := 0.100
	stats.update(rtt)
	// SRTT = R = 0.1
	// RTTVAR = R/2 = 0.05
	// RTO = 0.1 + 4*0.05 = 0.3
	if math.Abs(stats.srtt-0.1) > 0.0001 {
		t.Errorf("After 1st update: expected SRTT 0.1, got %f", stats.srtt)
	}
	if math.Abs(stats.rttvar-0.05) > 0.0001 {
		t.Errorf("After 1st update: expected RTTVAR 0.05, got %f", stats.rttvar)
	}
	if math.Abs(stats.rto-0.3) > 0.0001 {
		t.Errorf("After 1st update: expected RTO 0.3, got %f", stats.rto)
	}

	// 2. Stable RTT: 100ms again
	stats.update(0.100)
	// RTTVAR = 0.75 * 0.05 + 0.25 * |0.1 - 0.1| = 0.0375
	// SRTT = 0.875 * 0.1 + 0.125 * 0.1 = 0.1
	// RTO = 0.1 + 4*0.0375 = 0.1 + 0.15 = 0.25
	if math.Abs(stats.rto-0.25) > 0.0001 {
		t.Errorf("After 2nd update: expected RTO 0.25, got %f", stats.rto)
	}

	// 3. Spike: 200ms
	stats.update(0.200)
	// RTTVAR = 0.75 * 0.0375 + 0.25 * |0.1 - 0.2| = 0.028125 + 0.025 = 0.053125
	// SRTT = 0.875 * 0.1 + 0.125 * 0.2 = 0.0875 + 0.025 = 0.1125
	// RTO = 0.1125 + 4*0.053125 = 0.1125 + 0.2125 = 0.325
	if stats.rto <= 0.25 {
		t.Errorf("Expected RTO to increase after spike, got %f", stats.rto)
	}
}

// TestAccuracy_PacketLoss checks if we accurately count exact number of lost packets
func TestAccuracy_PacketLoss(t *testing.T) {
	initMetrics()
	// Mock server that drops every Nth packet
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dropRate := 3 // Drop every 3rd packet (1, 2, DROP, 4, 5, DROP...)
	totalPackets := 10

	go func() {
		defer ln.Close() // Close listener to avoid leak
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, payloadSize)
		count := 0
		for {
			if _, err := io.ReadFull(conn, buf); err != nil {
				return
			}
			count++
			if count%dropRate == 0 {
				// Drop: do not write back
				continue
			}
			conn.Write(buf)
		}
	}()

	// Client Setup
	targetName := "loss_accuracy_test"
	targets := []Target{{Name: targetName, Address: addr}}
	*flAdaptive = false
	*flBaseInterval = 50 * time.Millisecond
	*flBaseTimeout = 100 * time.Millisecond // Fast timeout

	startSent := getCounterValue(metricSent, targetName, addr)
	startTimeout := getCounterValue(metricTimeout, targetName, addr)

	// Run probe in background
	go startProbing(ctx, targets)

	// We want to send roughly 'totalPackets'
	// Interval 50ms needs 500ms for 10 packets. Let's wait a bit more.
	time.Sleep(time.Duration(totalPackets+2) * 50 * time.Millisecond)
	cancel()

	// Wait for cleanup
	time.Sleep(200 * time.Millisecond)

	endSent := getCounterValue(metricSent, targetName, addr)
	endTimeout := getCounterValue(metricTimeout, targetName, addr)

	sentCount := endSent - startSent
	timeoutCount := endTimeout - startTimeout

	if sentCount < float64(totalPackets) {
		t.Logf("Warning: Sent less packets than intended (%v < %v), cpu load?", sentCount, totalPackets)
	}

	// Calculate expected drops
	// If we sent N, and dropped every Kth:
	expectedDrops := int(sentCount) / dropRate

	// Allow off-by-one jitter due to timing/cleanup
	if math.Abs(timeoutCount-float64(expectedDrops)) > 1.5 {
		t.Errorf("Expected approx %d timeouts (sent %d, rate 1/%d), got %v", expectedDrops, int(sentCount), dropRate, timeoutCount)
	}
}

// TestAccuracy_HighLatency ensures RTT metrics reflect actual network delay
func TestAccuracy_HighLatency(t *testing.T) {
	initMetrics()
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

		buf := make([]byte, payloadSize)
		for {
			if _, err := io.ReadFull(conn, buf); err != nil {
				return
			}
			time.Sleep(delay)
			conn.Write(buf)
		}
	}()

	targetName := "latency_test"
	targets := []Target{{Name: targetName, Address: addr}}
	*flAdaptive = true // Enable adaptive to ensure it adjusts to > 150ms timeout
	*flBaseInterval = 300 * time.Millisecond
	*flBaseTimeout = 50 * time.Millisecond // Starts low, must adapt

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go startProbing(ctx, targets)

	// Wait for stabilization
	time.Sleep(1500 * time.Millisecond) // ~5 pings

	rttVal := getMetricValue(metricLastRTT, targetName, addr)
	// Allow 50ms variance for scheduling
	if rttVal < delay.Seconds()-0.02 || rttVal > delay.Seconds()+0.05 {
		t.Errorf("RTT Accuracy mismatch: expected ~%vs, got %vs", delay.Seconds(), rttVal)
	}
}

// TestRobustness_CorruptSeq verifies client ignores packets with wrong sequence
func TestRobustness_CorruptSeq(t *testing.T) {
	initMetrics()
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
		buf := make([]byte, payloadSize)
		for {
			if _, err := io.ReadFull(conn, buf); err != nil {
				return
			}
			// Corrupt sequence number (first 8 bytes)
			// Flip all bits
			for i := 0; i < 8; i++ {
				buf[i] = ^buf[i]
			}
			conn.Write(buf)
		}
	}()

	targetName := "corrupt_test"
	*flAdaptive = false
	*flBaseInterval = 50 * time.Millisecond
	*flBaseTimeout = 100 * time.Millisecond

	startRecv := getCounterValue(metricRecv, targetName, addr)
	startTimeout := getCounterValue(metricTimeout, targetName, addr)

	ctx, cancel := context.WithCancel(context.Background())
	go startProbing(ctx, []Target{{Name: targetName, Address: addr}})

	time.Sleep(500 * time.Millisecond) // ~10 pings
	cancel()
	time.Sleep(100 * time.Millisecond) // cleanup

	endRecv := getCounterValue(metricRecv, targetName, addr)
	endTimeout := getCounterValue(metricTimeout, targetName, addr)

	if endRecv > startRecv {
		t.Errorf("Client should not have accepted corrupt packets, but Recv increased by %v", endRecv-startRecv)
	}
	if endTimeout <= startTimeout {
		t.Errorf("Client should have timed out on corrupt packets, but Timeout did not increase")
	}
}

// TestRobustness_PartialWrites checks if client can read fragmented responses
func TestRobustness_PartialWrites(t *testing.T) {
	initMetrics()
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
		buf := make([]byte, payloadSize)
		for {
			if _, err := io.ReadFull(conn, buf); err != nil {
				return
			}
			// Write in chunks
			chunk1 := buf[:8]
			chunk2 := buf[8:]
			conn.Write(chunk1)
			time.Sleep(10 * time.Millisecond)
			conn.Write(chunk2)
		}
	}()

	targetName := "partial_test"
	*flAdaptive = false
	*flBaseInterval = 100 * time.Millisecond
	*flBaseTimeout = 200 * time.Millisecond

	startRecv := getCounterValue(metricRecv, targetName, addr)
	ctx, cancel := context.WithCancel(context.Background())
	go startProbing(ctx, []Target{{Name: targetName, Address: addr}})

	time.Sleep(500 * time.Millisecond)
	cancel()

	endRecv := getCounterValue(metricRecv, targetName, addr)
	if endRecv <= startRecv {
		t.Errorf("Partial writes should be reassembled, but Recv count did not increase")
	}
}

// TestRobustness_StalledServer checks behavior when server stops sending data completely
func TestRobustness_StalledServer(t *testing.T) {
	initMetrics()
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
		buf := make([]byte, payloadSize)
		// Read one, reply one, then stall
		io.ReadFull(conn, buf)
		conn.Write(buf)

		// Just read forever, never write
		io.Copy(io.Discard, conn)
	}()

	targetName := "stall_test"
	*flAdaptive = false
	*flBaseInterval = 50 * time.Millisecond
	*flBaseTimeout = 50 * time.Millisecond

	startTimeout := getCounterValue(metricTimeout, targetName, addr)
	ctx, cancel := context.WithCancel(context.Background())
	go startProbing(ctx, []Target{{Name: targetName, Address: addr}})

	time.Sleep(500 * time.Millisecond)
	cancel()
	time.Sleep(100 * time.Millisecond)

	endTimeout := getCounterValue(metricTimeout, targetName, addr)
	// We expect multiple timeouts because client keeps sending every 50ms,
	// server reads them (so TCP window still open), but never replies.
	if endTimeout-startTimeout < 4 {
		t.Errorf("Expected significant timeouts during stall, got %v", endTimeout-startTimeout)
	}
}

// TestAdaptive_RespondsToJitter validates that RTO adapts
func TestAdaptive_RespondsToJitter(t *testing.T) {
	initMetrics()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	// Server behavior:
	// Phase 1: Fast (10ms)
	// Phase 2: Slow (100ms)
	var delay atomicLatency
	delay.set(10 * time.Millisecond)

	go func() {
		defer ln.Close()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, payloadSize)
		for {
			if _, err := io.ReadFull(conn, buf); err != nil {
				return
			}
			time.Sleep(delay.get())
			conn.Write(buf)
		}
	}()

	targetName := "adaptive_jitter"
	*flAdaptive = true
	*flBaseInterval = 50 * time.Millisecond
	*flBaseTimeout = 500 * time.Millisecond // Start high

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go startProbing(ctx, []Target{{Name: targetName, Address: addr}})

	// Let it settle on low latency
	time.Sleep(1 * time.Second)
	rtoLow := getMetricValue(metricRTO, targetName, addr)

	// Increase latency
	delay.set(150 * time.Millisecond)
	time.Sleep(2 * time.Second)
	rtoHigh := getMetricValue(metricRTO, targetName, addr)

	// In adaptive mode, RTO should differ
	// Initial RTO settled likely near 100ms (minRTO)
	// New RTO should be > 150ms + margin
	t.Logf("RTO Low: %v, RTO High: %v", rtoLow, rtoHigh)

	if rtoHigh <= rtoLow {
		t.Errorf("RTO should allow adaptation: high latency %v should > low latency %v", rtoHigh, rtoLow)
	}
	if rtoHigh < 0.15 {
		t.Errorf("RTO High %v is too low for 150ms latency", rtoHigh)
	}
}

// TestStress_ManyTargets
func TestStress_ManyTargets(t *testing.T) {
	initMetrics()

	// Start 10 servers
	count := 10
	var targets []Target
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for i := 0; i < count; i++ {
		addr := startEchoServer(ctx, t)
		targets = append(targets, Target{
			Name:    fmt.Sprintf("stress_%d", i),
			Address: addr,
		})
	}

	*flAdaptive = false
	*flBaseInterval = 50 * time.Millisecond
	*flBaseTimeout = 500 * time.Millisecond

	// Run in background
	go startProbing(ctx, targets)

	time.Sleep(1 * time.Second)

	// Verify all up
	for _, tg := range targets {
		sent := getCounterValue(metricSent, tg.Name, tg.Address)
		if sent < 5 {
			t.Errorf("Target %s sent count too low: %v", tg.Name, sent)
		}
	}
}

// TestGarbageData_Server sends random garbage
func TestGarbageData_Server(t *testing.T) {
	initMetrics()
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
		// Spam garbage
		for {
			_, err := conn.Write([]byte("garbage data garbage data garbage data\n"))
			if err != nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	targetName := "garbage_test"
	*flAdaptive = false
	*flBaseInterval = 100 * time.Millisecond
	*flBaseTimeout = 100 * time.Millisecond

	startRecv := getCounterValue(metricRecv, targetName, addr)

	ctx, cancel := context.WithCancel(context.Background())
	go startProbing(ctx, []Target{{Name: targetName, Address: addr}})

	time.Sleep(500 * time.Millisecond)
	cancel()

	endRecv := getCounterValue(metricRecv, targetName, addr)
	if endRecv > startRecv {
		// It's possible for garbage to coincidentally form a valid packet but highly unlikely (uint64 match)
		t.Errorf("Garbage data counted as valid response? %v -> %v", startRecv, endRecv)
	}
}

// TestDuplicateResponse checks if duplicate sequences are handled
func TestDuplicateResponse(t *testing.T) {
	initMetrics()
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

		buf := make([]byte, payloadSize)
		for {
			if _, err := io.ReadFull(conn, buf); err != nil {
				return
			}
			// Echo twice
			conn.Write(buf)
			conn.Write(buf)
		}
	}()

	targetName := "duplicate_test"
	*flAdaptive = false
	*flBaseInterval = 100 * time.Millisecond
	*flBaseTimeout = 500 * time.Millisecond

	startRecv := getCounterValue(metricRecv, targetName, addr)
	startSent := getCounterValue(metricSent, targetName, addr)

	ctx, cancel := context.WithCancel(context.Background())
	go startProbing(ctx, []Target{{Name: targetName, Address: addr}})

	time.Sleep(500 * time.Millisecond)
	cancel()

	endRecv := getCounterValue(metricRecv, targetName, addr)
	endSent := getCounterValue(metricSent, targetName, addr)

	recvDelta := endRecv - startRecv
	sentDelta := endSent - startSent

	// Sent ~5. Recv should be ~5 (or ~10 if doubles count).
	// Logic says: delete(pending, seq). If OK -> Inc. If NOT OK -> Ignore.
	// So duplicates should be ignored.
	// We sent X packets. Server echoed 2X. We should only count X receives.

	if recvDelta > sentDelta+1 { // Allow +1 race
		t.Errorf("Duplicate responses counted! Sent %v, Recv %v", sentDelta, recvDelta)
	}
}

// --- Helpers ---

type atomicLatency struct {
	sync.Mutex
	d time.Duration
}

func (a *atomicLatency) set(d time.Duration) {
	a.Lock()
	a.d = d
	a.Unlock()
}
func (a *atomicLatency) get() time.Duration {
	a.Lock()
	defer a.Unlock()
	return a.d
}

func getMetricValue(vec *prometheus.GaugeVec, targetName, address string) float64 {
	var m dto.Metric
	if err := vec.WithLabelValues(targetName, address).Write(&m); err != nil {
		return 0
	}
	return m.GetGauge().GetValue()
}

// TestServer_EnforceSizeAndHeader verifies server disconnects if payload doesn't align or is invalid
func TestServer_EnforceSizeAndHeader(t *testing.T) {
	initMetrics()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start real server
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleServerConn(ctx, conn)
		}
	}()

	addr := ln.Addr().String()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// 1. Send Valid packet + Garbage attached (Total > 24 bytes)
	// We send 24 bytes valid + 10 bytes garbage = 34 bytes
	buf := make([]byte, 34)
	copy(buf[0:8], magicBytes) // Valid Header
	// .. rest is zeros (valid seq/ts)
	// last 10 bytes are zeros which is NOT a valid header for the 2nd chunk

	_, err = conn.Write(buf)
	if err != nil {
		t.Fatal(err)
	}

	// 2. We expect to read EXACTLY 24 bytes back (the first valid packet)
	reply := make([]byte, 24)
	// Set a deadline
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = io.ReadFull(conn, reply)
	if err != nil {
		t.Fatalf("Should have received echo for first valid part: %v", err)
	}

	// 3. Verify magic bytes on reply
	if string(reply[0:8]) != magicBytes {
		t.Errorf("Reply header invalid")
	}

	// 4. Try to read again. Server should have tried to read the next chunk (the 10 bytes + waiting 14 bytes OR just 10 bytes if it was full garbage?).
	// Actually, the server loop:
	// - Reads 24 bytes.
	// - Next iteration: Reads 24 bytes.
	// Our client sent 34 bytes.
	// Server read 24.
	// Server tries to read next 24. It has 10 bytes in buffer. It waits for 14 more.
	// BUT, we want to prove it validates the header.
	// Let's send 48 bytes (2 packets). 1st valid, 2nd invalid header.

	// Close and Reset for cleaner test
	conn.Close()
	conn, err = net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Send 48 bytes: [Valid Packet (24)] + [Invalid Packet (24)]
	buf = make([]byte, 48)
	copy(buf[0:8], magicBytes)   // 1st Header OK
	copy(buf[24:32], "BADHEADR") // 2nd Header BAD

	conn.Write(buf)

	// Read 1st reply
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = io.ReadFull(conn, reply)
	if err != nil {
		t.Fatalf("Should get 1st reply: %v", err)
	}

	// Read 2nd reply -> Should FAIL (EOF or Closed)
	// Server should have read 2nd chunk, seen BADHEADR, and returned/closed.
	// So this ReadFull should fail.
	_, err = io.ReadFull(conn, reply)
	if err == nil {
		t.Errorf("Expected server to close connection on invalid 2nd packet header, but got reply")
	} else {
		// Expecting error (EOF or connection reset)
		t.Logf("Got expected error on 2nd packet: %v", err)
	}
}
