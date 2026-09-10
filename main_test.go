package main

import (
	"context"
	"flag"
	dto "github.com/prometheus/client_model/go"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"link_ping_prometheus/internal/prober"
)

// TestMetricsCompressionToggle pins the /metrics compression wiring. With the
// default (-metrics-gzip off) a scraper offering gzip must still receive an
// identity response: promhttp pools a ~0.7MB flate compressor per P, which is
// more live heap than a small fleet's response is worth. With the flag on the
// response must be gzip-encoded.
func TestMetricsCompressionToggle(t *testing.T) {
	prober.InitMetrics()
	for _, tc := range []struct {
		name string
		gzip bool
		want string
	}{
		{"off by default", false, ""},
		{"enabled", true, "gzip"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
			req.Header.Set("Accept-Encoding", "gzip")
			rec := httptest.NewRecorder()
			metricsHandler(tc.gzip).ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			if got := rec.Header().Get("Content-Encoding"); got != tc.want {
				t.Errorf("Content-Encoding = %q, want %q", got, tc.want)
			}
			if rec.Body.Len() == 0 {
				t.Error("empty /metrics body")
			}
		})
	}
}

// TestMetricsHandlerInstrumentsScrapes pins the scrape instrumentation that
// promhttp.HandlerFor alone does not register (promhttp.Handler used to):
// without promhttp_metric_handler_requests_total{code="503"} and
// _requests_in_flight a scrape rejected by the concurrency cap is invisible.
// Building the handler twice must not panic either - InstrumentMetricHandler
// reuses the already-registered collector, which is what keeps repeated test
// runs (-count>1) and repeated scrapes safe.
func TestMetricsHandlerInstrumentsScrapes(t *testing.T) {
	prober.InitMetrics()
	scrape := func(h http.Handler) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	rec := scrape(metricsHandler(false))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"promhttp_metric_handler_requests_total",
		// The in-flight gauge counts the scrape serving it, so its value is
		// exactly 1 and is safe to pin.
		"promhttp_metric_handler_requests_in_flight 1",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics body is missing %q (scrape instrumentation lost)", want)
		}
	}

	// A second handler build (another call site, or a -count>1 run) must
	// re-register cleanly rather than panic.
	if rec := scrape(metricsHandler(true)); rec.Code != http.StatusOK {
		t.Fatalf("second handler build: status = %d, want 200", rec.Code)
	}
}

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
	// The 5s delay is the recovery ladder the README and the installer
	// scripts document; a default (1s) would change restart behaviour
	// silently. OnFailureResetPeriod keeps repeated restarts inside one
	// SCM failure-accounting window.
	if got := cfg.Option["OnFailureDelayDuration"]; got != "5s" {
		t.Errorf("OnFailureDelayDuration must stay 5s (documented recovery ladder), got %v", got)
	}
	if got := cfg.Option["OnFailureResetPeriod"]; got == nil {
		t.Error("OnFailureResetPeriod must be set so the restart counter resets on a healthy day")
	}
	if got := cfg.Option["StartType"]; got != "automatic" {
		t.Errorf("StartType must be automatic, got %v", got)
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

// TestReleasableHeap pins the scavenge trigger's input: idle heap the runtime
// has not yet returned to the OS. The trigger used Sys-HeapReleased, which
// covers the whole process and is therefore always above the threshold, so the
// documented "skip an already-lean process" guard never fired.
// pi-lens-ignore: go-test-functions
func TestReleasableHeap(t *testing.T) {
	tests := []struct {
		name string
		m    runtime.MemStats
		want uint64
	}{
		{
			// Already-lean process: Sys is large (stacks, GC metadata, mmap'd
			// spans), but every idle span has been released - nothing to give
			// back, so nothing to scavenge.
			"all idle heap released",
			runtime.MemStats{Sys: 100 << 20, HeapIdle: 10 << 20, HeapReleased: 10 << 20},
			0,
		},
		{
			// HeapReleased can transiently exceed HeapIdle; an unsigned
			// subtraction would wrap and force a scavenge every tick. Released
			// is strictly GREATER here so the clamp is actually exercised.
			"released exceeds idle underflows to zero",
			runtime.MemStats{Sys: 4 << 20, HeapIdle: 8 << 20, HeapReleased: 12 << 20},
			0,
		},
		{
			"releasable is idle minus released",
			runtime.MemStats{Sys: 20 << 20, HeapIdle: 20 << 20, HeapReleased: 6 << 20},
			14 << 20,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := releasableHeap(tc.m); got != tc.want {
				t.Errorf("releasableHeap(%+v) = %d, want %d", tc.m, got, tc.want)
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
		// The regression: a long-running agent always holds tens of MB in Sys,
		// so keying the guard on the process total made it fire on every tick
		// of an otherwise lean process.
		{"lean process is skipped despite a large Sys", runtime.MemStats{Sys: 90 << 20, HeapIdle: 8 << 20, HeapReleased: 8 << 20}, minScavengeUnreleased, false},
		{"below threshold is skipped", runtime.MemStats{HeapIdle: 6 << 20, HeapReleased: 3 << 20}, 4 << 20, false},
		{"exactly at threshold scavenges", runtime.MemStats{HeapIdle: 8 << 20, HeapReleased: 4 << 20}, 4 << 20, true},
		{"above threshold scavenges", runtime.MemStats{HeapIdle: 12 << 20, HeapReleased: 2 << 20}, 4 << 20, true},
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

// TestAbsolutizeFlagValue pins the service-install argument rewriting: path
// flags must be persisted absolute (the SCM's working directory is unrelated
// to the install directory), while every other flag - notably the integer
// log-rotation flags - must be persisted verbatim. Absolutizing
// log-file-max-mb=50 produced "C:\cwd\50", so the service exited 2 at
// flag.Parse with stderr discarded under the SCM: a crash loop with no
// diagnostics at all.
func TestAbsolutizeFlagValue(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	absLog := filepath.Join(cwd, "logs", "agent.log")

	tests := []struct{ name, flag, value, want string }{
		{"int size flag is untouched", "log-file-max-mb", "50", "50"},
		{"int backups flag is untouched", "log-file-max-backups", "0", "0"},
		{"int age flag is untouched", "log-file-max-age", "28", "28"},
		{"relative log path is absolutized", "log-file", filepath.Join("logs", "agent.log"), absLog},
		{"relative targets path is absolutized", "targets", "targets.json", filepath.Join(cwd, "targets.json")},
		{"already absolute path is unchanged", "metrics-tls-cert", absLog, absLog},
		{"empty path value stays empty", "log-file", "", ""},
		{"non-path flag is untouched", "mode", "client", "client"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := absolutizeFlagValue(tc.flag, tc.value); got != tc.want {
				t.Errorf("absolutizeFlagValue(%q, %q) = %q, want %q", tc.flag, tc.value, got, tc.want)
			}
		})
	}
}

// TestReadyzSemantics pins the liveness/readiness split: /healthz stays
// always-200, while /readyz must report 503 for a client-side agent that has
// never held a working socket (DNS outage, firewall) - alive but probing
// nothing is exactly the failure mode an orchestrator must be able to see.
// socket_age_seconds is set only after a successful dial, so it is the signal
// the gate reads.
func TestReadyzSemantics(t *testing.T) {
	// A target still in the dial-retry loop publishes a target entry with
	// socket_age_seconds == 0; one with a live socket publishes > 0.
	dialStuck := []prober.TargetStatus{{Name: "a"}}
	working := []prober.TargetStatus{{Name: "a"}, {Name: "b", SocketAgeSeconds: 12.5}}

	tests := []struct {
		name    string
		mode    string
		targets []prober.TargetStatus
		want    int
	}{
		{"server mode is ready without targets", "server", nil, http.StatusOK},
		{"client with an empty registry is not ready", "client", nil, http.StatusServiceUnavailable},
		{"client still dialing is not ready", "client", dialStuck, http.StatusServiceUnavailable},
		{"client with one working socket is ready", "client", working, http.StatusOK},
		{"both mode with one working socket is ready", "both", working, http.StatusOK},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reg := prober.NewStatusRegistry()
			for _, s := range tc.targets {
				reg.Update(s)
			}
			rec := httptest.NewRecorder()
			readinessHandler(tc.mode, reg).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
			if rec.Code != tc.want {
				t.Errorf("/readyz in mode %s = %d, want %d (body %q)", tc.mode, rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

// TestStartMetricsServerTimeouts pins the HTTP timeouts: a multi-megabyte
// scrape over a slow link needs more than 10s to write, and a truncated
// response reads as the monitor itself being down. Reads stay short so a slow
// client still cannot hold a connection.
func TestStartMetricsServerTimeouts(t *testing.T) {
	p := &program{}
	srv, done, err := p.startMetricsServer("127.0.0.1:0", "", "", "", "", prober.NewStatusRegistry(), false, "client")
	if err != nil {
		t.Fatalf("startMetricsServer: %v", err)
	}
	t.Cleanup(func() {
		// pi-lens-ignore: go-ignored-call-result
		_ = srv.Close()
		<-done
	})
	if srv.WriteTimeout != 30*time.Second {
		t.Errorf("WriteTimeout = %v, want 30s (10s truncates large scrapes)", srv.WriteTimeout)
	}
	if srv.ReadTimeout != 10*time.Second || srv.ReadHeaderTimeout != 10*time.Second {
		t.Errorf("ReadTimeout/ReadHeaderTimeout = %v/%v, want 10s/10s", srv.ReadTimeout, srv.ReadHeaderTimeout)
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

// blockingGatherer parks every Gather until release is closed, making the
// MaxRequestsInFlight cap deterministic: without the park, the cap could only
// be tested by racing real gathers against each other.
type blockingGatherer struct {
	entered chan struct{}
	release chan struct{}
}

func (g *blockingGatherer) Gather() ([]*dto.MetricFamily, error) {
	select {
	case g.entered <- struct{}{}:
	default:
	}
	<-g.release
	return nil, nil
}

// TestMetricsHandler_ConcurrencyCapReturns503: /metrics must serve at most
// maxConcurrentScrapes gathers at once (a large fleet's response is ~10-15MB
// of text and every concurrent scrape builds its own copy against
// GOMEMLIMIT). Excess scrapes get a 503, which Prometheus retries; without
// this an unbounded scrape storm multiplies the agent's own heap and can make
// the monitor report ITSELF down. The rejected request must not reach Gather.
func TestMetricsHandler_ConcurrencyCapReturns503(t *testing.T) {
	prober.InitMetrics()
	g := &blockingGatherer{entered: make(chan struct{}, 8), release: make(chan struct{})}
	h := metricsHandlerFor(g, false)

	recs := make([]*httptest.ResponseRecorder, maxConcurrentScrapes)
	done := make([]chan struct{}, len(recs))
	for i := range recs {
		recs[i] = httptest.NewRecorder()
		done[i] = make(chan struct{})
		go func(i int) {
			defer close(done[i])
			h.ServeHTTP(recs[i], httptest.NewRequest(http.MethodGet, "/metrics", nil))
		}(i)
	}
	for range maxConcurrentScrapes {
		select {
		case <-g.entered:
		case <-time.After(5 * time.Second):
			t.Fatal("scrapes never reached the gatherer (cap not applied?)")
		}
	}

	// The next scrape arrives while both slots are held: 503, no gather.
	// Served from a goroutine with a bound so a regression that removes the cap
	// fails fast instead of hanging until the package timeout: if the cap is
	// gone, the third request parks inside Gather and announces itself on
	// g.entered (whose buffer this test drained above).
	type result struct {
		code int
	}
	third := make(chan result, 1)
	go func() {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		third <- result{code: rec.Code}
	}()
	select {
	case got := <-third:
		if got.code != http.StatusServiceUnavailable {
			t.Errorf("a scrape beyond the %d-scrape cap must get 503, got %d", maxConcurrentScrapes, got.code)
		}
	case <-g.entered:
		t.Error("the concurrency cap is not applied: a third scrape reached the gatherer")
		close(g.release)
		<-third // let it finish so the test can report cleanly
		return
	case <-time.After(5 * time.Second):
		t.Fatal("the third scrape neither returned nor reached the gatherer")
	}

	close(g.release)
	for i := range recs {
		select {
		case <-done[i]:
		case <-time.After(5 * time.Second):
			t.Fatalf("scrape %d did not finish after release", i)
		}
		if recs[i].Code != http.StatusOK {
			t.Errorf("in-flight scrape %d must complete with 200, got %d", i, recs[i].Code)
		}
	}

	// And the cap must not leak: a scrape after the burst is served normally.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("cap must release after the burst, got %d", rec.Code)
	}
}

// TestREADME_FlagsTableAndBucketsMatchCode ties the user-facing documentation
// to the code. Both have drifted before: -echo-secret was registered but
// missing from the flags table, and the bucket list lost its 2.5s/3s edges.
// A hand-maintained copy in a test would drift too, so this reads README.md
// itself. The comparison is one-directional (registered ⊆ documented): the
// README may legitimately show example rows the binary does not register.
func TestREADME_FlagsTableAndBucketsMatchCode(t *testing.T) {
	data, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	doc := string(data)

	rowRe := regexp.MustCompile("(?m)^\\| `(-[a-z0-9-]+)` \\|")
	documented := make(map[string]bool)
	for _, m := range rowRe.FindAllStringSubmatch(doc, -1) {
		documented[m[1]] = true
	}
	if len(documented) < 20 {
		t.Fatalf("parsed only %d flag rows from README.md — the table format changed, so this test would pass vacuously", len(documented))
	}
	flag.VisitAll(func(f *flag.Flag) {
		// go test registers its own -test.* flags in the same FlagSet: not
		// ours to document.
		if strings.HasPrefix(f.Name, "test.") {
			return
		}
		if !documented["-"+f.Name] {
			t.Errorf("flag -%s is registered in main.go but has no row in the README flags table", f.Name)
		}
	})

	bucketRe := regexp.MustCompile("explicit buckets `\\{([^}]+)\\}`")
	m := bucketRe.FindStringSubmatch(doc)
	if m == nil {
		t.Fatal("README no longer documents the RTT bucket edges as 'explicit buckets `{...}`'")
	}
	var want []float64
	for _, part := range strings.Split(m[1], ",") {
		v, err := strconv.ParseFloat(strings.TrimSpace(part), 64)
		if err != nil {
			t.Fatalf("unparsable bucket edge %q in README: %v", part, err)
		}
		want = append(want, v)
	}
	if !slices.Equal(want, prober.RTTBuckets) {
		t.Errorf("README bucket list %v != prober.RTTBuckets %v — update both in the same commit", want, prober.RTTBuckets)
	}
}

// TestStatusEndpointIsGatedLikeMetrics: /status exposes live link state and
// peer addresses, so it must carry the same Basic auth as /metrics; /healthz
// and /readyz stay open for orchestrators. Pins the wiring in
// startMetricsServer, not just the MetricsAuth handler in isolation.
func TestStatusEndpointIsGatedLikeMetrics(t *testing.T) {
	prober.InitMetrics()
	p := &program{}
	reg := prober.NewStatusRegistry()
	reg.Update(prober.TargetStatus{Name: "t", Address: "127.0.0.1:4000"})
	srv, done, err := p.startMetricsServer("127.0.0.1:0", "alice", "s3cret", "", "", reg, false, "client")
	if err != nil {
		t.Fatalf("startMetricsServer: %v", err)
	}
	t.Cleanup(func() {
		// pi-lens-ignore: go-ignored-call-result
		_ = srv.Close()
		<-done
	})
	if srv.Addr == "" {
		t.Fatal("startMetricsServer must publish the bound address for callers/tests")
	}
	get := func(path string, user, pass string) int {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, "http://"+srv.Addr+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if user != "" {
			req.SetBasicAuth(user, pass)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	if got := get("/status", "", ""); got != http.StatusUnauthorized {
		t.Errorf("/status without credentials = %d, want 401 (it exposes peer addresses and link state)", got)
	}
	if got := get("/status", "alice", "s3cret"); got != http.StatusOK {
		t.Errorf("/status with credentials = %d, want 200", got)
	}
	if got := get("/healthz", "", ""); got != http.StatusOK {
		t.Errorf("/healthz must stay unauthenticated, got %d", got)
	}
	if got := get("/readyz", "", ""); got == http.StatusUnauthorized {
		t.Error("/readyz must stay unauthenticated (orchestrators cannot send credentials)")
	}
}
