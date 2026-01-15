package main

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestLossTracker(t *testing.T) {
	tests := []struct {
		name     string
		size     int
		inputs   []bool // true for success, false for failure
		wantLoss float64
	}{
		{
			name:     "empty buffer",
			size:     10,
			inputs:   []bool{},
			wantLoss: 0.0,
		},
		{
			name:     "partial filled - 0% loss",
			size:     10,
			inputs:   []bool{true, true, true},
			wantLoss: 0.0,
		},
		{
			name:     "partial filled - 50% loss",
			size:     10,
			inputs:   []bool{true, false, true, false},
			wantLoss: 50.0,
		},
		{
			name:     "partial filled - 100% loss",
			size:     10,
			inputs:   []bool{false, false, false},
			wantLoss: 100.0,
		},
		{
			name:     "full filled - overwrite with success",
			size:     3,
			inputs:   []bool{false, false, false, true, true, true}, // initially all loss, replaced by all success
			wantLoss: 0.0,
		},
		{
			name:     "full filled - mixed overwrite",
			size:     4,
			inputs:   []bool{true, true, true, true, false, false}, // 4 success -> 2 failures overwrite 2 successes -> expected [T, T, F, F] -> 50%
			wantLoss: 50.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lt := newLossTracker(tt.size, "test_target")
			for _, input := range tt.inputs {
				lt.record(input)
			}

			// We need to access the internal computation indirectly via the gauge or expose it.
			// Since computeLossPercent is unexported but record updates the gauge using it,
			// strictly speaking we are testing `computeLossPercent` logic.
			// However, since `computeLossPercent` is a method on *lossTracker, we can call it if it's in the same package (which it is, `package main`).
			got := lt.computeLossPercent()
			if got != tt.wantLoss {
				t.Errorf("computeLossPercent() = %v, want %v", got, tt.wantLoss)
			}
		})
	}
}

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
	// Start two echo servers
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr1 := startEchoServer(ctx, t)
	addr2 := startEchoServer(ctx, t)

	targets := []Target{
		{Name: "target1", Address: addr1},
		{Name: "target2", Address: addr2},
	}

	// Run clients in a background goroutine
	// Use short interval for quick testing
	go func() {
		_ = runClients(ctx, targets, 50*time.Millisecond, 200*time.Millisecond, 10)
	}()

	// Wait for some probes to happen
	time.Sleep(500 * time.Millisecond)

	// Verify metrics for both targets
	verifyMetric(t, sentCounter, "target1")
	verifyMetric(t, recvCounter, "target1")
	verifyMetric(t, sentCounter, "target2")
	verifyMetric(t, recvCounter, "target2")
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
			go handleConnection(ctx, conn)
		}
	}()

	return ln.Addr().String()
}

func verifyMetric(t *testing.T, vec *prometheus.CounterVec, label string) {
	val := getCounterValue(vec, label)
	if val <= 0 {
		t.Errorf("expected metric value > 0 for label %s, got %v", label, val)
	}
}

func getCounterValue(vec *prometheus.CounterVec, label string) float64 {
	var m dto.Metric
	if err := vec.WithLabelValues(label).Write(&m); err != nil {
		return 0
	}
	return m.GetCounter().GetValue()
}
