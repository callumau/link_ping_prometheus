package prober

import (
	"crypto/sha256"
	"crypto/subtle"
	"log/slog"
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// RTTBuckets are the explicit histogram buckets for link_rtt_seconds.
// Fixed values (not generated) avoid floating-point label artifacts.
// They span sub-100ms LAN links up to the RTO cap (DefaultMaxRTO = 3s).
// The 3s edge keeps samples from degraded-but-alive links (RTT between
// 2.5s and the 3s RTO cap) out of +Inf so histogram_quantile stays exact.
// Buckets above the RTO cap would be dead weight: any probe unresolved
// past the RTO is counted as loss and its late response discarded, so RTT
// samples can never approach 5s/10s. +Inf is always appended by the
// Prometheus client.
var RTTBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 3.0}

// Prometheus metric descriptors. All use the label set {source, target, address}.
var (
	ProbesSent = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "link_probes_sent_total",
		Help: "Total UDP probes sent. Probes into a down link still count as sent and time out naturally, so loss reads ~100% during an outage.",
	}, []string{"source", "target", "address"})
	ProbesTimedOut = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "link_probes_timed_out_total",
		Help: "Total probes with no echo within the RTO. Loss = rate(timed_out) / rate(sent). No TCP retransmission: this is true network loss.",
	}, []string{"source", "target", "address"})
	SendErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "link_probes_send_errors_total",
		Help: "Total probes that failed to send locally (UDP write errors). They never reach the wire, so they are not counted in link_probes_sent_total; a sustained rate means a local NIC/socket problem, not network loss.",
	}, []string{"source", "target", "address"})
	CorruptedProbes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "link_probes_corrupted_total",
		Help: "Probes whose echo came back with corrupted payload bytes (-payload mode only): magic, sequence and timestamp intact, data altered in flight. Data-path corruption, not loss — the round trip completed.",
	}, []string{"source", "target", "address"})
	ProbesInflight = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "link_probes_inflight",
		Help: "Current number of probes sent but waiting for a response or timeout. Grows during stalls.",
	}, []string{"source", "target", "address"})
	// RTTSeconds is a classic histogram with explicit buckets plus
	// native histogram support (client-side observation of the same
	// series with finer native buckets). Quantiles and means are
	// derived in PromQL via rate()/histogram_quantile() so any time
	// window can be queried.
	RTTSeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:                        "link_rtt_seconds",
		Help:                        "Round-trip time in seconds.",
		Buckets:                     RTTBuckets,
		NativeHistogramBucketFactor: 1.1,
	}, []string{"source", "target", "address"})
	// JitterSeconds is the smoothed RTT jitter (RFC 3550 §6.4.1:
	// J += (|D(i-1,i)| - J)/16) computed from consecutive probe RTT
	// deltas. The estimate resets after any gap in sequence numbers
	// (a timed-out probe), so link recovery never spikes the gauge.
	JitterSeconds = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "link_rtt_jitter_seconds",
		Help: "Smoothed RTT jitter in seconds (RFC 3550, consecutive RTT deltas). Resets after a probe timeout; a single lost probe does not feed an artificial spike into the estimate.",
	}, []string{"source", "target", "address"})
	LinkUp = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "link_up",
		// keep in sync with LinkUpMissThreshold — test/metrics_test.go pins the
		// Help text to the constant so they cannot silently diverge.
		Help: "1 while probes are getting echoes, 0 after 3 consecutive probes time out (LinkUpMissThreshold). A single lost probe or brief stall does not flap the state.",
	}, []string{"source", "target", "address"})
	RTOEstimate = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "link_rto_seconds",
		Help: "Current adaptive RTO (RFC 6298: SRTT + 4*RTTVAR, doubled on consecutive timeouts). Floor is max(200ms, 2*SRTT) so a link's timeout always has headroom over its measured RTT.",
	}, []string{"source", "target", "address"})
	SRTTSeconds = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "link_rtt_srtt_seconds",
		Help: "Smoothed RTT estimate in seconds (RFC 6298 SRTT). A stable latency signal for dashboards and baseline-shift alerts, without window-dependent histogram math. Non-adaptive mode leaves this at 0.",
	}, []string{"source", "target", "address"})
	ServerProbesReceived = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "link_server_probes_received_total",
		Help: "Total validated probes received by the server, labelled by source and remote client address. Cross-check against the client's link_probes_sent_total: any mismatch is probes that never reached the server.",
	}, []string{"source", "client"})
	ServerProbesDropped = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "link_server_probes_dropped_total",
		Help: "Total probes dropped by the server, labelled by source and reason (allowlist, rate_ip, rate_global, size, magic, hmac, replay). Distinguishes misconfig (wrong secret, clock skew) and overload from true network loss.",
	}, []string{"source", "reason"})
	ServerClockSkew = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "link_server_clock_skew_seconds",
		Help: "Last observed clock skew in seconds (server time minus client timestamp) for HMAC-authenticated probes. Positive means client is behind. Used to diagnose NTP drift causing replay drops.",
	}, []string{"source", "client"})
	BuildInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "link_ping_build_info",
		Help: "Build information; value is always 1 and the version label holds the build version (git tag for releases, UTC timestamp to the minute for dev builds).",
	}, []string{"version"})
)

var registerOnce sync.Once

// InitMetrics registers all Prometheus metrics with the global registry.
// Safe to call multiple times; registration happens exactly once.
func InitMetrics() {
	registerOnce.Do(func() {
		prometheus.MustRegister(
			ProbesSent, ProbesTimedOut, SendErrors, CorruptedProbes, ProbesInflight,
			RTTSeconds, JitterSeconds, LinkUp, RTOEstimate, SRTTSeconds,
			ServerProbesReceived, ServerProbesDropped, ServerClockSkew, BuildInfo,
		)
	})
}

// SeedMetrics initialises every metric series for each target so they all
// surface in /metrics output even before the first event. source is the
// topology label applied to every series (e.g. the local datacenter).
func SeedMetrics(source string, targets []Target) {
	for _, t := range targets {
		m := newTargetMetrics(source, t)
		m.sent.Add(0)
		m.sendErr.Add(0)
		m.corrupted.Add(0)
		m.timedOut.Add(0)
		m.inflight.Set(0)
		m.linkUp.Set(0)
		m.rto.Set(0)
		m.srtt.Set(0)
		m.jitter.Set(0)
	}
}

// MetricsAuth returns an HTTP handler that wraps next with HTTP Basic
// Authentication. If user is empty, authentication is disabled.
func MetricsAuth(user, pass string, next http.Handler) http.Handler {
	if user == "" {
		return next
	}
	// Hash the reference credentials once at handler creation; the
	// request-path hashes are computed per request.
	uhRef, phRef := sha256.Sum256([]byte(user)), sha256.Sum256([]byte(pass))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		// Hash before comparing: ConstantTimeCompare returns immediately on
		// length mismatch, which would otherwise leak credential length.
		uh, ph := sha256.Sum256([]byte(u)), sha256.Sum256([]byte(p))
		if !ok || subtle.ConstantTimeCompare(uh[:], uhRef[:]) != 1 || subtle.ConstantTimeCompare(ph[:], phRef[:]) != 1 {
			slog.Warn("metrics auth failed", "remote", r.RemoteAddr)
			w.Header().Set("WWW-Authenticate", `Basic realm="metrics"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
