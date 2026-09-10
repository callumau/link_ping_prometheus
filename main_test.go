package main

import (
	"context"
	"log/slog"
	"runtime"
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

// pi-lens-ignore: go-test-functions
func TestUnreleasedHeap(t *testing.T) {
	tests := []struct {
		name string
		m    runtime.MemStats
		want uint64
	}{
		{
			// Fully released heap: nothing left to give back.
			"all released",
			runtime.MemStats{Sys: 10 << 20, HeapReleased: 10 << 20},
			0,
		},
		{
			// Sys can transiently dip below HeapReleased; an unsigned
			// subtraction would wrap and force a scavenge every tick.
			"released exceeds sys underflows to zero",
			runtime.MemStats{Sys: 4 << 20, HeapReleased: 8 << 20},
			0,
		},
		{
			"unreleased is sys minus released",
			runtime.MemStats{Sys: 20 << 20, HeapReleased: 6 << 20},
			14 << 20,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := unreleasedHeap(tc.m); got != tc.want {
				t.Errorf("unreleasedHeap(%+v) = %d, want %d", tc.m, got, tc.want)
			}
		})
	}
}

// pi-lens-ignore: go-test-functions
func TestShouldScavenge(t *testing.T) {
	tests := []struct {
		name          string
		m             runtime.MemStats
		minUnreleased uint64
		want          bool
	}{
		{"below threshold is skipped", runtime.MemStats{Sys: 6 << 20, HeapReleased: 3 << 20}, 4 << 20, false},
		{"exactly at threshold scavenges", runtime.MemStats{Sys: 8 << 20, HeapReleased: 4 << 20}, 4 << 20, true},
		{"above threshold scavenges", runtime.MemStats{Sys: 12 << 20, HeapReleased: 2 << 20}, 4 << 20, true},
		{"lean heap is skipped", runtime.MemStats{Sys: 8 << 20, HeapReleased: 8 << 20}, minScavengeUnreleased, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldScavenge(tc.m, tc.minUnreleased); got != tc.want {
				t.Errorf("shouldScavenge(%+v, %d) = %v, want %v", tc.m, tc.minUnreleased, got, tc.want)
			}
		})
	}
}

// chanHandler forwards log records to a channel so the scavenger test can
// observe a tick without sleeping for a real interval.
type chanHandler struct{ ch chan string }

func (h chanHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h chanHandler) Handle(_ context.Context, r slog.Record) error {
	select {
	case h.ch <- r.Message:
	default:
	}
	return nil
}
func (h chanHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h chanHandler) WithGroup(string) slog.Handler      { return h }

// pi-lens-ignore: go-test-functions
func TestStartHeapScavengerDisabled(t *testing.T) {
	before := runtime.NumGoroutine()
	// every <= 0 must not spawn anything at all.
	// pi-lens-ignore: go-context-background-handler
	startHeapScavenger(context.Background(), 0, minScavengeUnreleased, slog.Default())
	if after := runtime.NumGoroutine(); after > before {
		t.Errorf("every=0 must not spawn a goroutine, count went %d -> %d", before, after)
	}
}

// pi-lens-ignore: go-test-functions
func TestStartHeapScavengerTicksThenStopsOnCancel(t *testing.T) {
	// pi-lens-ignore: go-context-background-handler
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := make(chan string, 1)
	before := runtime.NumGoroutine()
	// minUnreleased=0 makes every tick take the scavenge path, so the log
	// line proves the ticker actually fired before we cancel it.
	startHeapScavenger(ctx, 5*time.Millisecond, 0, slog.New(chanHandler{ch: ch}))

	select {
	case msg := <-ch:
		if !strings.Contains(msg, "scavenge") {
			t.Errorf("unexpected scavenger log message %q", msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("scavenger never ticked")
	}

	cancel()
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		// pi-lens-ignore: go-time-sleep-test
		time.Sleep(2 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > before {
		t.Errorf("scavenger goroutine still running after ctx cancel: %d > %d", n, before)
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
	for name, want := range map[string]int{
		"log-file-max-mb":      *flLogMaxSize,
		"log-file-max-backups": *flLogMaxBackups,
		"log-file-max-age":     *flLogMaxAge,
	} {
		got, err := flagDefaultInt(name)
		if err != nil {
			t.Errorf("flagDefaultInt(%s): %v", name, err)
			continue
		}
		if got != want {
			t.Errorf("flagDefaultInt(%s) = %d, want %d", name, got, want)
		}
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
