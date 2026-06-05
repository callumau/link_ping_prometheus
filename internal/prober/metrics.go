package prober

import (
	"crypto/subtle"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Prometheus metric descriptors. All use the label set {target, address}.
var (
	SentTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tcp_echo_sent_total",
		Help: "Total echo requests sent (attempts).",
	}, []string{"target", "address"})
	ReceivedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tcp_echo_received_total",
		Help: "Total echo responses received.",
	}, []string{"target", "address"})
	TimeoutTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tcp_echo_timeouts_total",
		Help: "Total echo requests that timed out.",
	}, []string{"target", "address"})
	DropTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tcp_echo_dropped_total",
		Help: "Total connections dropped/failed.",
	}, []string{"target", "address"})
	RTTSeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "tcp_echo_rtt_seconds",
		Help:    "Round-trip time in seconds.",
		Buckets: prometheus.ExponentialBuckets(0.0005, 2, 14),
	}, []string{"target", "address"})
	RTTSecondsRecent = prometheus.NewSummaryVec(prometheus.SummaryOpts{
		Name:       "tcp_echo_rtt_recent_seconds",
		Help:       "Sliding-window RTT percentiles over the last 10 minutes.",
		Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		MaxAge:     10 * time.Minute,
		AgeBuckets: 5,
	}, []string{"target", "address"})
	LastRTTSeconds = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "tcp_echo_last_rtt_seconds",
		Help: "Most recent RTT in seconds.",
	}, []string{"target", "address"})
	Connected = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "tcp_echo_connected",
		Help: "1 if currently connected, 0 otherwise.",
	}, []string{"target", "address"})
	RTOEstimate = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "tcp_echo_estimated_timeout_seconds",
		Help: "Current adaptive timeout (RTO) being used.",
	}, []string{"target", "address"})
)

var registerOnce sync.Once

// InitMetrics registers all Prometheus metrics with the global registry.
// Safe to call multiple times; registration happens exactly once.
func InitMetrics() {
	registerOnce.Do(func() {
		prometheus.MustRegister(SentTotal, ReceivedTotal, TimeoutTotal, DropTotal, RTTSeconds, RTTSecondsRecent, LastRTTSeconds, Connected, RTOEstimate)
	})
}

// SeedMetrics initialises counters to 0 for each target so they surface
// in /metrics output even before first event.
func SeedMetrics(targets []Target) {
	for _, t := range targets {
		TimeoutTotal.WithLabelValues(t.Name, t.Address).Add(0)
	}
}

// MetricsAuth returns an HTTP handler that wraps next with HTTP Basic
// Authentication. If user is empty, authentication is disabled.
func MetricsAuth(user, pass string, next http.Handler) http.Handler {
	if user == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(u), []byte(user)) != 1 || subtle.ConstantTimeCompare([]byte(p), []byte(pass)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="metrics"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
