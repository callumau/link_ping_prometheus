package prober_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"tcp_ping_prometheus/internal/prober"
)

func TestMetricsAuth(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	// Auth disabled: empty user passes everything through.
	h := prober.MetricsAuth("", "", next)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusNoContent {
		t.Errorf("no-auth: expected 204, got %d", rec.Code)
	}

	h = prober.MetricsAuth("alice", "s3cret", next)

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
		h.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("%s: expected %d, got %d", tc.name, tc.want, rec.Code)
		}
		if tc.want == http.StatusUnauthorized && rec.Header().Get("WWW-Authenticate") == "" {
			t.Errorf("%s: missing WWW-Authenticate header on 401", tc.name)
		}
	}
}

// TestSeedMetrics verifies every metric series exists for a fresh target
// immediately after seeding — checked via the registry, since
// WithLabelValues would create the series as a side effect of reading.
func TestSeedMetrics(t *testing.T) {
	prober.InitMetrics()

	name := "seed_unique_target"
	prober.SeedMetrics([]prober.Target{{Name: name, Address: "192.0.2.1:4000"}})

	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, mf := range mfs {
		for _, m := range mf.Metric {
			for _, l := range m.Label {
				if l.GetName() == "target" && l.GetValue() == name {
					found[mf.GetName()] = true
				}
			}
		}
	}

	want := []string{
		"link_probes_sent_total",
		"link_probes_received_total",
		"link_probes_timed_out_total",
		"link_connections_dropped_total",
		"link_connect_failures_total",
		"link_up",
		"link_rto_seconds",
		"link_rtt_seconds",
	}
	for _, w := range want {
		if !found[w] {
			t.Errorf("metric %s has no series for freshly seeded target", w)
		}
	}
}
