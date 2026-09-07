package prober_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"link_ping_prometheus/internal/prober"
)

// TestStatusRegistryReflectsProbeLoop: with a Status registry wired into
// the config, the probe loop publishes live per-target state and the
// /status handler serves it as JSON. Uses a real echo server so seq
// advance, link_up=1 and drained pending are all observable.
func TestStatusRegistryReflectsProbeLoop(t *testing.T) {
	prober.InitMetrics()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr := udpEcho(t, ctx, func(buf []byte, w func([]byte)) { w(buf) })

	reg := prober.NewStatusRegistry()
	runClientAsync(t, ctx, cancel, prober.Config{
		Source:       testSource,
		Targets:      []prober.Target{{Name: "statust", Address: addr}},
		BaseInterval: 50 * time.Millisecond,
		BaseTimeout:  1 * time.Second,
		Adaptive:     true,
		Status:       reg,
	})

	deadline := time.Now().Add(3 * time.Second)
	var s *prober.TargetStatus
	for time.Now().Before(deadline) {
		for _, st := range reg.Snapshot() {
			if st.Name == "statust" && st.LastSeq >= 2 && st.LinkUp && st.Pending == 0 {
				s = &st
			}
		}
		if s != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if s == nil {
		t.Fatalf("status snapshot never reflected successful probes: %+v", reg.Snapshot())
	}
	if s.Address != addr {
		t.Errorf("expected address %q, got %q", addr, s.Address)
	}
	if s.ConsecutiveMisses != 0 {
		t.Errorf("expected 0 consecutive misses, got %d", s.ConsecutiveMisses)
	}
	if s.SRTTSeconds <= 0 || s.RTOSeconds <= 0 {
		t.Errorf("expected populated SRTT/RTO, got srtt=%f rto=%f", s.SRTTSeconds, s.RTOSeconds)
	}
	if s.SocketAgeSeconds <= 0 {
		t.Errorf("expected socket age > 0, got %f", s.SocketAgeSeconds)
	}

	// The served JSON carries the same state.
	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"name":"statust"`) {
		t.Errorf("status JSON missing target entry: %s", rec.Body.String())
	}
}
