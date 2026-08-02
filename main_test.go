package main

import (
	"context"
	"testing"
	"time"
)

// saveFlags restores all mutated global flags after the test.
func saveFlags(t *testing.T) {
	t.Helper()
	oldMode, oldListen, oldMetrics := *flMode, *flListen, *flMetrics
	oldTarget, oldTargets := *flTarget, *flTargets
	oldUser, oldPass := *flMetricsBasicAuthUser, *flMetricsBasicAuthPass
	oldCert, oldKey := *flMetricsTLSCert, *flMetricsTLSKey
	oldReadTimeout := *flReadTimeout
	t.Cleanup(func() {
		*flMode, *flListen, *flMetrics = oldMode, oldListen, oldMetrics
		*flTarget, *flTargets = oldTarget, oldTargets
		*flMetricsBasicAuthUser, *flMetricsBasicAuthPass = oldUser, oldPass
		*flMetricsTLSCert, *flMetricsTLSKey = oldCert, oldKey
		*flReadTimeout = oldReadTimeout
	})
}

func TestResolveMetricsAuth(t *testing.T) {
	saveFlags(t)
	// Isolate from any real environment.
	t.Setenv("TCP_PING_METRICS_USER", "")
	t.Setenv("TCP_PING_METRICS_PASS", "")

	reset := func() { *flMetricsBasicAuthUser, *flMetricsBasicAuthPass = "", "" }

	reset()
	if _, _, err := resolveMetricsAuth(); err != nil {
		t.Errorf("empty pair must be allowed (auth disabled): %v", err)
	}

	reset()
	*flMetricsBasicAuthUser = "u"
	if _, _, err := resolveMetricsAuth(); err == nil {
		t.Error("user without password must error (would enable empty-password auth)")
	}

	reset()
	*flMetricsBasicAuthPass = "p"
	if _, _, err := resolveMetricsAuth(); err == nil {
		t.Error("password without user must error")
	}

	reset()
	*flMetricsBasicAuthUser = "u"
	*flMetricsBasicAuthPass = "p"
	if u, p, err := resolveMetricsAuth(); err != nil || u != "u" || p != "p" {
		t.Errorf("valid pair: got %q/%q, err %v", u, p, err)
	}

	// Flags win over env; env fills in when flags are empty.
	reset()
	t.Setenv("TCP_PING_METRICS_USER", "envu")
	t.Setenv("TCP_PING_METRICS_PASS", "envp")
	if u, p, err := resolveMetricsAuth(); err != nil || u != "envu" || p != "envp" {
		t.Errorf("env fallback: got %q/%q, err %v", u, p, err)
	}

	*flMetricsBasicAuthUser = "flagu"
	if u, _, err := resolveMetricsAuth(); err != nil || u != "flagu" {
		t.Errorf("flag should win over env: got %q, err %v", u, err)
	}
}

func TestRunRejectsBadFlagCombos(t *testing.T) {
	saveFlags(t)
	t.Setenv("TCP_PING_METRICS_USER", "")
	t.Setenv("TCP_PING_METRICS_PASS", "")

	t.Run("tls cert without key", func(t *testing.T) {
		saveFlags(t)
		*flMetricsTLSCert = "cert.pem"
		prg := &program{ctx: context.Background()}
		if err := prg.run(); err == nil {
			t.Error("expected error for cert without key")
		}
	})

	t.Run("metrics user without password", func(t *testing.T) {
		saveFlags(t)
		*flMetricsBasicAuthUser = "u"
		prg := &program{ctx: context.Background()}
		if err := prg.run(); err == nil {
			t.Error("expected error for user without password")
		}
	})

	t.Run("non-positive read timeout", func(t *testing.T) {
		saveFlags(t)
		*flReadTimeout = -1
		prg := &program{ctx: context.Background()}
		if err := prg.run(); err == nil {
			t.Error("expected error for negative read timeout")
		}
	})

	t.Run("client mode with invalid target", func(t *testing.T) {
		saveFlags(t)
		*flMode = "client"
		*flTarget = "not an address"
		prg := &program{ctx: context.Background()}
		if err := prg.run(); err == nil {
			t.Error("expected error for invalid target in client mode")
		}
	})
}

// TestProgramStartStopBothMode exercises the service Start/Stop lifecycle
// in "both" mode. With the race detector this proves the WaitGroup Add is
// correctly sequenced before Stop's Wait (previously Add ran concurrently
// inside run()).
func TestProgramStartStopBothMode(t *testing.T) {
	saveFlags(t)
	t.Setenv("TCP_PING_METRICS_USER", "")
	t.Setenv("TCP_PING_METRICS_PASS", "")

	*flMode = "both"
	*flListen = "127.0.0.1:0"
	*flMetrics = "127.0.0.1:0"
	*flTargets = ""
	*flTarget = "127.0.0.1:1" // nothing listening: client just reconnect-loops

	prg := &program{}
	if err := prg.Start(nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		prg.Stop(nil)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return within 5s — lifecycle/WaitGroup bug")
	}
}
