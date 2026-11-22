package prober

import (
	"bytes"
	"context"
	"encoding/binary"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// TestEchoDupGuardRingEviction: the guard must track a bounded FIFO
// window of dupRingSize identities — entry 0 is evicted exactly when
// entry dupRingSize is recorded, while newer entries stay remembered.
// This pins the eviction ORDER (not just the map size), which the
// integration suite cannot do without sending >8192 rate-limited frames.
func TestEchoDupGuardRingEviction(t *testing.T) {
	g := newEchoDupGuard()
	for i := range dupRingSize {
		g.record(uint64(i))
	}
	for i := range dupRingSize {
		if _, ok := g.seen[uint64(i)]; !ok {
			t.Fatalf("key %d must be remembered before the ring wraps", i)
		}
	}
	if g.count != dupRingSize {
		t.Fatalf("guard must hold exactly %d entries, holds %d", dupRingSize, g.count)
	}

	// Recording one more key evicts the OLDEST (ring position of key 0)
	// and only that one.
	g.record(dupRingSize)
	if _, ok := g.seen[uint64(0)]; ok {
		t.Error("key 0 must be FIFO-evicted when the ring wraps")
	}
	if _, ok := g.seen[dupRingSize]; !ok {
		t.Error("the newly recorded key must be remembered")
	}
	for i := 1; i < dupRingSize; i++ {
		if _, ok := g.seen[uint64(i)]; !ok {
			t.Errorf("key %d must survive the wrap", i)
		}
	}
	if g.count != dupRingSize {
		t.Errorf("guard must stay at %d entries after wrap, holds %d", dupRingSize, g.count)
	}

	// Steady state: every record evicts exactly one old key.
	for i := range 100 {
		g.record(uint64(dupRingSize + 1 + i))
	}
	if g.count != dupRingSize {
		t.Errorf("guard must stay bounded at %d entries, holds %d", dupRingSize, g.count)
	}
	if _, ok := g.seen[uint64(100)]; ok {
		t.Error("key 100 (evicted late in the sweep) must be gone")
	}
	if _, ok := g.seen[uint64(dupRingSize+100)]; !ok {
		t.Error("the most recently recorded key must be remembered")
	}
}

// TestEchoFrameKey: the identity must be a pure function of (source IP,
// seq, ts) and must distinguish every dimension the dup guard relies on —
// a different source address, seq or timestamp is a different probe, and
// only the exact repeat is a bounce. The source PORT is deliberately NOT
// part of it: a rotating-port replay must not look like a fresh probe.
func TestEchoFrameKey(t *testing.T) {
	ip := netip.MustParseAddr("10.0.0.1")
	frame := func(seq, ts uint64) []byte {
		f := make([]byte, PayloadSize)
		copy(f[0:8], MagicBytes)
		binary.LittleEndian.PutUint64(f[8:16], seq)
		binary.LittleEndian.PutUint64(f[16:24], ts)
		return f
	}
	base := frame(7, uint64(time.Now().UnixNano()))
	want := echoFrameKey(ip, base)

	if got := echoFrameKey(ip, base); got != want {
		t.Error("identity must be deterministic for identical inputs")
	}
	if got := echoFrameKey(netip.MustParseAddr("10.0.0.2"), base); got == want {
		t.Error("a different source IP must change the identity")
	}
	if got := echoFrameKey(ip, frame(8, binary.LittleEndian.Uint64(base[16:24]))); got == want {
		t.Error("a different seq must change the identity")
	}
	if got := echoFrameKey(ip, frame(7, binary.LittleEndian.Uint64(base[16:24])+1)); got == want {
		t.Error("a different timestamp must change the identity")
	}
}

// TestSkewReplayedBoundary pins the replay-window comparison exactly
// (audit finding): strict > / < against ±maxReplayWindow — a frame whose
// skew is exactly at the window edge is a live probe. A rewrite to >=
// would reject edge-exact frames; this test cannot pass either way, so
// both semantics are pinned by their negation cases below.
func TestSkewReplayedBoundary(t *testing.T) {
	for _, skew := range []time.Duration{
		-maxReplayWindow,     // exactly at the stale edge: live
		-maxReplayWindow + 1, // one tick inside: live
		-maxReplayWindow - 1, // one tick outside: replayed
		maxReplayWindow,      // exactly at the future edge: live
		maxReplayWindow - 1,  // one tick inside: live
		maxReplayWindow + 1,  // one tick outside: replayed
	} {
		if skewReplayed(skew) != (skew > maxReplayWindow || skew < -maxReplayWindow) {
			t.Fatalf("skewReplayed(%v) disagrees with the pinned > / < semantics", skew)
		}
	}
	if skewReplayed(0) {
		t.Fatal("zero skew must never replay")
	}
}

// TestMetricsAuth_RateLimitsFailuresWhileAllowingValid pins that repeated
// failed Basic Auth attempts from the same IP are throttled with 429 while
// valid credentials still succeed immediately.
func TestMetricsAuth_RateLimitsFailuresWhileAllowingValid(t *testing.T) {
	InitMetrics()
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

// TestRunServer_WarnsOnIPv6Slash64WithoutSecret pins that an IPv6 /64 allowlist
// without -echo-secret triggers the wide-prefix warning (a /64 covers 2^64
// addresses vs MaxClientSeries=1024).
func TestRunServer_WarnsOnIPv6Slash64WithoutSecret(t *testing.T) {
	InitMetrics()
	var buf bytes.Buffer
	orig := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	defer slog.SetDefault(orig)

	allow, err := ParseAllowlist("2001:db8:1:2::/64")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = RunServer(ctx, "127.0.0.1:0", "test", allow, "")
	if !strings.Contains(buf.String(), "wide client allowlist prefix without -echo-secret") {
		t.Fatalf("expected wide-prefix warning for IPv6 /64 without secret, got logs: %s", buf.String())
	}
}
