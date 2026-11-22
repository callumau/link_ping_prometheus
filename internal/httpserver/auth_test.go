package httpserver

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"link_ping_prometheus/internal/prober"
)

// plainCounterValue reads a label-less counter (MetricsAuthFailures), which the
// variadic-label getCounterValue helper cannot address.
func plainCounterValue(c prometheus.Counter) float64 {
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		return 0
	}
	return m.GetCounter().GetValue()
}

func TestMetricsAuth(t *testing.T) {
	prober.InitMetrics()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	// Auth disabled: empty user passes everything through.
	h := MetricsAuth("", "", next)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusNoContent {
		t.Errorf("no-auth: expected 204, got %d", rec.Code)
	}

	h = MetricsAuth("alice", "s3cret", next)

	cases := []struct {
		name     string
		user     string
		pass     string
		setCreds bool
		want     int
	}{
		{"no credentials", "", "", false, http.StatusUnauthorized},
		{"wrong password", "alice", "wrong", true, http.StatusUnauthorized},
		{"wrong user", "bob", "s3cret", true, http.StatusUnauthorized},
		{"empty password attempt", "alice", "", true, http.StatusUnauthorized},
		{"correct credentials", "alice", "s3cret", true, http.StatusNoContent},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		if tc.setCreds {
			req.SetBasicAuth(tc.user, tc.pass)
		}
		rec := httptest.NewRecorder()
		before := plainCounterValue(prober.MetricsAuthFailures)
		h.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("%s: expected %d, got %d", tc.name, tc.want, rec.Code)
		}
		if tc.want == http.StatusUnauthorized && rec.Header().Get("WWW-Authenticate") == "" {
			t.Errorf("%s: missing WWW-Authenticate header on 401", tc.name)
		}
		// The failure counter is the alerting signal (MetricsAuthFailures) for
		// a misconfigured scraper or credential scanning; it must count every
		// rejection and nothing else.
		if delta := plainCounterValue(prober.MetricsAuthFailures) - before; (delta > 0) != (tc.want == http.StatusUnauthorized) {
			t.Errorf("%s: link_metrics_auth_failures_total moved by %v, want %v", tc.name, delta, tc.want == http.StatusUnauthorized)
		}
	}
}

// TestMetricsAuth_RateLimitsFailuresWhileAllowingValid pins that repeated
// failed Basic Auth attempts from the same IP are throttled with 429 while
// valid credentials still succeed immediately.
func TestMetricsAuth_RateLimitsFailuresWhileAllowingValid(t *testing.T) {
	prober.InitMetrics()
	h := MetricsAuth("prom", "secret", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 60; i++ {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		req.RemoteAddr = "198.51.100.10:12345"
		req.SetBasicAuth("prom", "wrong")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d, want 401", i+1, rec.Code)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.RemoteAddr = "198.51.100.10:12345"
	req.SetBasicAuth("prom", "wrong")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("burst failure status = %d, want 429", rec.Code)
	}

	// Valid credentials from the same IP must still pass.
	validReq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	validReq.RemoteAddr = "198.51.100.10:12345"
	validReq.SetBasicAuth("prom", "secret")
	validRec := httptest.NewRecorder()
	h.ServeHTTP(validRec, validReq)
	if validRec.Code != http.StatusOK {
		t.Fatalf("valid auth while throttled status = %d, want 200", validRec.Code)
	}
}
