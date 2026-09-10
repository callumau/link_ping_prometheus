package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"link_ping_prometheus/internal/prober"
)

// TestMetricsBodyDecodes checks the DECODED /metrics payload, not just the
// Content-Encoding header: a handler that advertised gzip but wrote identity
// (or garbage) bytes would pass a header-only assertion while real scrapers
// fail to parse it. Both compression modes must deliver a parseable
// exposition containing a known metric family.
func TestMetricsBodyDecodes(t *testing.T) {
	prober.InitMetrics()
	// Seed a series so the link_up family is actually exported: a metric vec
	// with no children emits nothing at all, HELP line included.
	prober.SeedMetrics("metrics-body-test", []prober.Target{{Name: "t", Address: "127.0.0.1:4000"}})

	const marker = "# HELP link_up"

	for _, tc := range []struct {
		name         string
		gzip         bool
		wantEncoding string
	}{
		{"identity", false, ""},
		{"gzip", true, "gzip"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
			req.Header.Set("Accept-Encoding", "gzip")
			rec := httptest.NewRecorder()
			metricsHandler(tc.gzip).ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			if got := rec.Header().Get("Content-Encoding"); got != tc.wantEncoding {
				t.Fatalf("Content-Encoding = %q, want %q", got, tc.wantEncoding)
			}

			body := rec.Body.Bytes()
			if tc.gzip {
				zr, err := gzip.NewReader(bytes.NewReader(body))
				if err != nil {
					t.Fatalf("body is not valid gzip — header set but payload not encoded: %v", err)
				}
				defer zr.Close()
				body, err = io.ReadAll(zr)
				if err != nil {
					t.Fatalf("decoding gzip body: %v", err)
				}
			}

			if !strings.Contains(string(body), marker) {
				t.Errorf("decoded /metrics body missing %q (%d bytes decoded)", marker, len(body))
			}
		})
	}
}
