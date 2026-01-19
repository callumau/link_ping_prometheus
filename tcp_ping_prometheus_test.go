package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
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
