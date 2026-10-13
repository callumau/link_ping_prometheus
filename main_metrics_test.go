package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

// TestServiceConfigHardening pins the service hardening set (previously
// the kardianos service.Config Option map; now the OS-neutral
// serviceInstallSpec the windows manager applies): recovery restart,
// delayed auto-start, and network/time dependencies. These were shipped
// unconfigured once (a crash left the service stopped forever) — this
// test fails if a refactor drops them again. Rewritten against
// serviceInstallSpec with justification: the kardianous swap (supply-
// chain remediation) replaced the config type, and a package-agnostic
// spec keeps the pins testable on every platform.
