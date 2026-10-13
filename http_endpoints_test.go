package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"link_ping_prometheus/internal/prober"
)

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

func TestStatusHandler_ConcurrencyCapReturns503(t *testing.T) {
	prober.InitMetrics()
	inner := &blockingStatusHandler{entered: make(chan struct{}, 8), release: make(chan struct{})}
	h := limitConcurrent(maxConcurrentScrapes, inner)

	recs := make([]*httptest.ResponseRecorder, maxConcurrentScrapes)
	done := make([]chan struct{}, len(recs))
	for i := range recs {
		recs[i] = httptest.NewRecorder()
		done[i] = make(chan struct{})
		go func(i int) {
			defer close(done[i])
			h.ServeHTTP(recs[i], httptest.NewRequest(http.MethodGet, "/status", nil))
		}(i)
	}
	for range maxConcurrentScrapes {
		select {
		case <-inner.entered:
		case <-time.After(5 * time.Second):
			t.Fatal("status requests never reached the handler (cap not applied?)")
		}
	}

	// The third request arrives while both slots are held: 503, and it must
	// never reach the status handler itself.
	third := make(chan int, 1)
	go func() {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/status", nil))
		third <- rec.Code
	}()
	select {
	case got := <-third:
		if got != http.StatusServiceUnavailable {
			t.Errorf("a request beyond the %d-request cap must get 503, got %d", maxConcurrentScrapes, got)
		}
	case <-inner.entered:
		t.Error("the concurrency cap is not applied: a third request reached the status handler")
		close(inner.release)
		<-third
		return
	case <-time.After(5 * time.Second):
		t.Fatal("the third request neither returned nor reached the handler")
	}

	close(inner.release)
	for i := range recs {
		select {
		case <-done[i]:
		case <-time.After(5 * time.Second):
			t.Fatalf("request %d did not finish after release", i)
		}
		if recs[i].Code != http.StatusOK {
			t.Errorf("in-flight request %d must complete with 200, got %d", i, recs[i].Code)
		}
	}

	// Release happens on every path (including a handler panic), and slots
	// must have returned, so 10 sequential requests after the burst are all
	// served normally (release is closed above, so they complete at once).
	for range 10 {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/status", nil))
		if rec.Code != http.StatusOK {
			t.Errorf("cap must serve sequential requests after the burst, got %d", rec.Code)
		}
	}
}

// blockingStatusHandler parks every request until release is closed, making
// the /status concurrency cap deterministic (the same pattern as
// blockingGatherer for /metrics). After release is closed, later requests
// complete immediately, so the test can verify slots are reusable afterward.

// TestStatusHandler_CapReleasesOnPanic pins that a panicking request still
// frees its semaphore slot: the cap wraps arbitrary handlers and a leaked
// slot would eventually 503 every /status request forever. The wrapper lets
// the panic propagate to net/http's server-side recovery, so the test
// mirrors that by recovering it itself. The inner handler panics exactly
// once, so the request after the panic also proves the freed slot serves.
func TestStatusHandler_CapReleasesOnPanic(t *testing.T) {
	var panicked bool
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !panicked {
			panicked = true
			panic("boom")
		}
		w.WriteHeader(http.StatusOK)
	})
	h := limitConcurrent(1, inner)
	func() {
		defer func() {
			if r := recover(); r != nil {
				return
			}
		}()
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/status", nil))
	}()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/status", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("slot leaked after a panicking request: recovery request got %d, want 200", rec.Code)
	}
}

// TestREADME_FlagsTableAndBucketsMatchCode ties the user-facing documentation
// to the code. Both have drifted before: -echo-secret was registered but
// missing from the flags table, and the bucket list lost its 2.5s/3s edges.
// A hand-maintained copy in a test would drift too, so this reads README.md
// itself. The comparison is one-directional (registered ⊆ documented): the
// README may legitimately show example rows the binary does not register.

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

// TestRulesAndDashboardReferenceOnlyDefinedMetrics pins a coupling that has
// drifted before: a renamed metric silently turns a shipped alert or dashboard
// panel into "no data". Every link_* identifier in rules/link-monitor.yml and
// grafana-dashboard.json must be a metric defined in internal/prober/metrics.go
// (or one of the histogram suffixes the client library appends). promtool in CI
// would validate PromQL syntax, but not this, and the repo's suite needs nothing
// beyond go test.
// pi-lens-ignore: go-test-functions
