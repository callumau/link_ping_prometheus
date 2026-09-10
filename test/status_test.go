package prober_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"link_ping_prometheus/internal/prober"
)

// TestStatusSocketAgeWhileDialing pins the signal the /readyz gate reads: a
// target stuck in the dial-retry loop (DNS outage, firewall) publishes
// socket_age_seconds == 0, while a target that has held a working socket
// publishes > 0 (asserted in TestStatusRegistryReflectsProbeLoop). /readyz
// returns 503 only while NO target has ever had a working socket, so publishing
// a socket age before a successful dial would make a stuck agent report ready.
// Uses an unresolvable host; skips if this environment resolves it or resolves
// too slowly.
func TestStatusSocketAgeWhileDialing(t *testing.T) {
	prober.InitMetrics()

	const unresolvableHost = "link-ping-status.invalid"
	if _, err := net.LookupHost(unresolvableHost); err == nil {
		t.Skipf("%s resolves here, so the dial-failure path is unreachable", unresolvableHost)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reg := prober.NewStatusRegistry()
	runClientAsync(t, ctx, cancel, prober.Config{
		Source:       testSource,
		Targets:      []prober.Target{{Name: "dialstuck", Address: unresolvableHost + ":4000"}},
		BaseInterval: 50 * time.Millisecond,
		BaseTimeout:  time.Second,
		Status:       reg,
	})

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if snap := reg.Snapshot(); len(snap) == 1 {
			if snap[0].SocketAgeSeconds != 0 {
				t.Errorf("target stuck in the dial-retry loop must publish socket_age_seconds == 0, got %f", snap[0].SocketAgeSeconds)
			}
			if snap[0].LinkUp {
				t.Error("target stuck in the dial-retry loop must not publish link_up=true")
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Reaching here means the dial-failure path never published a snapshot:
	// unlike a slow resolver, that is a real regression (the publish happens on
	// the first failed dial), so fail rather than skip it away.
	t.Fatalf("dial failure never reached /status within 15s: the dial-retry path must publish socket_age_seconds=0 and link_up=false")
}

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

	// Decode rather than substring-match: the process block is the memory
	// observability path for the scrape-driven heap high-water mark, and a
	// silent key/label rename would otherwise go unnoticed.
	var body map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("status JSON is not an object: %v (%s)", err, rec.Body.String())
	}
	if _, ok := body["targets"]; !ok {
		t.Error(`status JSON lost its "targets" key (existing consumers depend on it)`)
	}
	rawProcess, ok := body["process"]
	if !ok {
		t.Fatalf(`status JSON missing "process" object: %s`, rec.Body.String())
	}
	var proc struct {
		HeapAllocBytes uint64 `json:"heap_alloc_bytes"`
		Goroutines     int    `json:"goroutines"`
	}
	if err := json.Unmarshal(rawProcess, &proc); err != nil {
		t.Fatalf("process object is malformed: %v (%s)", err, rawProcess)
	}
	if proc.HeapAllocBytes == 0 {
		t.Error("process.heap_alloc_bytes must be > 0 (a zero here means MemStats was never read)")
	}
	if proc.Goroutines < 1 {
		t.Errorf("process.goroutines must be >= 1, got %d", proc.Goroutines)
	}
}

// TestStatusProcessSnapshot_CachedWithinTTL: runtime.ReadMemStats stops the
// world, and /status is both unauthenticated (when no metrics credentials are
// set) and uncapped, so the snapshot must not be re-read per request —
// otherwise a burst of /status requests injects STW pauses into a process whose
// whole purpose is measuring RTT, inflating its own samples.
//
// The proof is that a forced GC between two rapid reads does not change
// gc_count. The read is retried because the package-global cache may happen to
// expire between the two calls (an earlier test populated it), which would
// otherwise flake; bypassing the cache fails every attempt, since runtime.GC()
// always moves gc_count.
func TestStatusProcessSnapshot_CachedWithinTTL(t *testing.T) {
	for attempt := range 5 {
		first := prober.ReadProcessStatus()
		runtime.GC()
		second := prober.ReadProcessStatus()
		if second.GCCount == first.GCCount {
			return // the cache held across a GC: this is the property under test
		}
		t.Logf("attempt %d: cache expired between reads, retrying", attempt+1)
	}
	t.Error("link_metrics_auth_failures-style staleness check failed: two /status snapshots inside the TTL must share gc_count even after a forced GC (cache bypassed?)")
}
