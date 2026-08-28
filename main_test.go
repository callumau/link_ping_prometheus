package main

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestServiceConfigHardening pins the SCM hardening options: recovery
// restart, delayed auto-start, and network/time dependencies. These were
// shipped unconfigured once (a crash left the service stopped forever) —
// this test fails if a refactor drops them again.
func TestServiceConfigHardening(t *testing.T) {
	cfg := serviceConfig()
	if cfg.Name != "link_ping_prometheus" {
		t.Errorf("service name changed unexpectedly: %q", cfg.Name)
	}
	if got := cfg.Option["OnFailure"]; got != "restart" {
		t.Errorf("OnFailure must be restart so crashes self-heal, got %v", got)
	}
	if cfg.Option["DelayedAutoStart"] != true {
		t.Error("DelayedAutoStart must be true to avoid boot-race bind failures")
	}
	for _, dep := range []string{"Tcpip", "W32Time"} {
		if !slices.Contains(cfg.Dependencies, dep) {
			t.Errorf("missing service dependency %q (got %v)", dep, cfg.Dependencies)
		}
	}
	// Version strings go stale after in-place upgrades; runtime truth is
	// in link_ping_build_info.
	if strings.Contains(cfg.Description, version) && version != "dev" {
		t.Errorf("Description must not embed the build version: %q", cfg.Description)
	}
}

// saveFlags restores all mutated global flags after the test.
func saveFlags(t *testing.T) {
	t.Helper()
	oldMode, oldListen, oldMetrics := *flMode, *flListen, *flMetrics
	oldTarget, oldTargets := *flTarget, *flTargets
	oldUser, oldPass := *flMetricsBasicAuthUser, *flMetricsBasicAuthPass
	oldCert, oldKey := *flMetricsTLSCert, *flMetricsTLSKey
	oldAllow, oldSource := *flAllow, *flSource
	oldAdaptive := *flAdaptive
	oldInterval, oldTimeout := *flBaseInterval, *flBaseTimeout
	oldLogFile, oldJSONLogs := *flLogFile, *flJSONLogs
	oldLogMaxSize, oldLogMaxBackups, oldLogMaxAge := *flLogMaxSize, *flLogMaxBackups, *flLogMaxAge
	oldAllowInsecure := *flMetricsAllowInsecure
	t.Cleanup(func() {
		*flMode, *flListen, *flMetrics = oldMode, oldListen, oldMetrics
		*flTarget, *flTargets = oldTarget, oldTargets
		*flMetricsBasicAuthUser, *flMetricsBasicAuthPass = oldUser, oldPass
		*flMetricsTLSCert, *flMetricsTLSKey = oldCert, oldKey
		*flAllow, *flSource = oldAllow, oldSource
		*flAdaptive = oldAdaptive
		*flBaseInterval, *flBaseTimeout = oldInterval, oldTimeout
		*flLogFile, *flJSONLogs = oldLogFile, oldJSONLogs
		*flLogMaxSize, *flLogMaxBackups, *flLogMaxAge = oldLogMaxSize, oldLogMaxBackups, oldLogMaxAge
		*flMetricsAllowInsecure = oldAllowInsecure
	})
}

// pi-lens-ignore: go-test-functions
func TestResolveMetricsAuth(t *testing.T) {
	saveFlags(t)
	// Isolate from any real environment.
	t.Setenv("LINK_PING_METRICS_USER", "")
	t.Setenv("LINK_PING_METRICS_PASS", "")

	reset := func() { *flMetricsBasicAuthUser, *flMetricsBasicAuthPass = "", "" }

	reset()
	if u, p, err := resolveMetricsAuth(); err != nil || u != "" || p != "" {
		t.Errorf("empty pair must be allowed (auth disabled): %q/%q, err %v", u, p, err)
	}

	reset()
	*flMetricsBasicAuthUser = "u"
	if u, p, err := resolveMetricsAuth(); err == nil {
		t.Errorf("user without password must error (would enable empty-password auth), got %q/%q", u, p)
	}

	reset()
	*flMetricsBasicAuthPass = "p"
	if u, p, err := resolveMetricsAuth(); err == nil {
		t.Errorf("password without user must error, got %q/%q", u, p)
	}

	reset()
	*flMetricsBasicAuthUser = "u"
	*flMetricsBasicAuthPass = "p"
	if u, p, err := resolveMetricsAuth(); err != nil || u != "u" || p != "p" {
		t.Errorf("valid pair: got %q/%q, err %v", u, p, err)
	}

	// Flags win over env; env fills in when flags are empty.
	reset()
	t.Setenv("LINK_PING_METRICS_USER", "envu")
	t.Setenv("LINK_PING_METRICS_PASS", "envp")
	if u, p, err := resolveMetricsAuth(); err != nil || u != "envu" || p != "envp" {
		t.Errorf("env fallback: got %q/%q, err %v", u, p, err)
	}

	*flMetricsBasicAuthUser = "flagu"
	if _, _, err := resolveMetricsAuth(); err == nil {
		t.Error("partial flag with env fallback must error with atomic pair semantics (flag+env hybrid not allowed)")
	}
	*flMetricsBasicAuthPass = "flagp"
	if u, p, err := resolveMetricsAuth(); err != nil || u != "flagu" || p != "flagp" {
		t.Errorf("full flag pair should win over env: got %q/%q, err %v", u, p, err)
	}
}

// pi-lens-ignore: go-test-functions
func TestFlagDefaultInt(t *testing.T) {
	// Pins the helper against the current flag defaults so the
	// "rotation flags require -log-file" guard keeps working.
	if got := flagDefaultInt("log-file-max-mb"); got != *flLogMaxSize {
		t.Errorf("flagDefaultInt(log-file-max-mb) = %d, want %d", got, *flLogMaxSize)
	}
	if got := flagDefaultInt("log-file-max-backups"); got != *flLogMaxBackups {
		t.Errorf("flagDefaultInt(log-file-max-backups) = %d, want %d", got, *flLogMaxBackups)
	}
	if got := flagDefaultInt("log-file-max-age"); got != *flLogMaxAge {
		t.Errorf("flagDefaultInt(log-file-max-age) = %d, want %d", got, *flLogMaxAge)
	}
}

func TestRunRejectsUnknownModeBeforeBind(t *testing.T) {
	saveFlags(t)
	t.Setenv("LINK_PING_METRICS_USER", "")
	t.Setenv("LINK_PING_METRICS_PASS", "")

	*flMode = "bogus"
	*flMetrics = "127.0.0.1:0"
	// pi-lens-ignore: go-context-background-handler
	prg := &program{ctx: context.Background()}
	err := prg.run()
	if err == nil {
		t.Fatal("expected error for unknown mode")
	}
	if !strings.Contains(err.Error(), "unknown mode") {
		t.Errorf("error should name the mode problem, got: %v", err)
	}
}

// pi-lens-ignore: go-test-functions
func TestRunRejectsBadFlagCombos(t *testing.T) {
	saveFlags(t)
	t.Setenv("LINK_PING_METRICS_USER", "")
	t.Setenv("LINK_PING_METRICS_PASS", "")

	t.Run("tls cert without key", func(t *testing.T) {
		saveFlags(t)
		*flMetricsTLSCert = "cert.pem"
		// pi-lens-ignore: go-context-background-handler
		prg := &program{ctx: context.Background()}
		if err := prg.run(); err == nil {
			t.Error("expected error for cert without key")
		}
	})

	t.Run("metrics user without password", func(t *testing.T) {
		saveFlags(t)
		*flMetricsBasicAuthUser = "u"
		// pi-lens-ignore: go-context-background-handler
		prg := &program{ctx: context.Background()}
		if err := prg.run(); err == nil {
			t.Error("expected error for user without password")
		}
	})

	t.Run("client mode with invalid target", func(t *testing.T) {
		saveFlags(t)
		*flMode = "client"
		*flTarget = "not an address"
		// pi-lens-ignore: go-context-background-handler
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
// pi-lens-ignore: go-test-functions
func TestProgramStartStopBothMode(t *testing.T) {
	saveFlags(t)
	t.Setenv("LINK_PING_METRICS_USER", "")
	t.Setenv("LINK_PING_METRICS_PASS", "")

	*flMode = "both"
	*flListen = "127.0.0.1:0"
	*flMetrics = "127.0.0.1:0"
	*flTargets = ""
	*flTarget = "127.0.0.1:1" // nothing listening: client just reconnect-loops
	// Valid server allowlist: run() must SUCCEED here. A run() failure now
	// exits the process uncleanly (os.Exit(1)) so the SCM restart action
	// fires — an invalid-config Start would abort the whole test binary.
	*flAllow = "127.0.0.1"

	prg := &program{}
	if err := prg.Start(nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// pi-lens-ignore: go-time-sleep-test
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
