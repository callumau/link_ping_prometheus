package prober

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Prometheus metric descriptors. All use the label set {target, address}.
var (
	ProbesSent = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "link_probes_sent_total",
		Help: "Total link probes sent on established connections (dial failures excluded).",
	}, []string{"target", "address"})
	ProbesReceived = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "link_probes_received_total",
		Help: "Total link probe responses received.",
	}, []string{"target", "address"})
	ProbesTimedOut = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "link_probes_timed_out_total",
		Help: "Total link probes that timed out.",
	}, []string{"target", "address"})
	ConnectionsDropped = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "link_connections_dropped_total",
		Help: "Total established connections that were lost mid-probing.",
	}, []string{"target", "address"})
	ConnectFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "link_connect_failures_total",
		Help: "Total failed connection attempts (dial errors). Not counted in sent/timeout totals.",
	}, []string{"target", "address"})
	RTTRecent = prometheus.NewSummaryVec(prometheus.SummaryOpts{
		Name:       "link_rtt_seconds",
		Help:       "Sliding-window RTT percentiles over the last 10 minutes.",
		Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		MaxAge:     10 * time.Minute,
		AgeBuckets: 5,
	}, []string{"target", "address"})
	LastRTT = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "link_last_rtt_seconds",
		Help: "Most recent RTT in seconds.",
	}, []string{"target", "address"})
	LinkUp = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "link_up",
		Help: "1 if currently connected, 0 otherwise.",
	}, []string{"target", "address"})
	RTOEstimate = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "link_rto_seconds",
		Help: "Current adaptive timeout (RTO) being used.",
	}, []string{"target", "address"})
	LossPercent = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "link_loss_percent",
		Help: "Packet loss percentage over the last 10 minutes (timeouts / sent on the wire).",
	}, []string{"target", "address"})
	ServerProbesReceivedTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "link_server_probes_received_total",
		Help: "Total validated echo probes received by the server. Compare with the client's link_probes_sent_total to measure true network loss: TCP retransmission hides lost segments from the client, so (sent - server_received) / sent is the real loss rate.",
	})
)

var registerOnce sync.Once

// InitMetrics registers all Prometheus metrics with the global registry.
// Safe to call multiple times; registration happens exactly once.
func InitMetrics() {
	registerOnce.Do(func() {
		prometheus.MustRegister(ProbesSent, ProbesReceived, ProbesTimedOut, ConnectionsDropped, ConnectFailures, RTTRecent, LastRTT, LinkUp, RTOEstimate, LossPercent, ServerProbesReceivedTotal)
	})
}

// SeedMetrics initialises every metric series for each target so they all
// surface in /metrics output even before the first event.
func SeedMetrics(targets []Target) {
	for _, t := range targets {
		ProbesSent.WithLabelValues(t.Name, t.Address).Add(0)
		ProbesReceived.WithLabelValues(t.Name, t.Address).Add(0)
		ProbesTimedOut.WithLabelValues(t.Name, t.Address).Add(0)
		ConnectionsDropped.WithLabelValues(t.Name, t.Address).Add(0)
		ConnectFailures.WithLabelValues(t.Name, t.Address).Add(0)
		LinkUp.WithLabelValues(t.Name, t.Address).Set(0)
		LastRTT.WithLabelValues(t.Name, t.Address).Set(0)
		RTOEstimate.WithLabelValues(t.Name, t.Address).Set(0)
		LossPercent.WithLabelValues(t.Name, t.Address).Set(0)
		RTTRecent.WithLabelValues(t.Name, t.Address)
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
		// Hash before comparing: ConstantTimeCompare returns immediately on
		// length mismatch, which would otherwise leak credential length.
		uh, ph := sha256.Sum256([]byte(u)), sha256.Sum256([]byte(p))
		uhRef, phRef := sha256.Sum256([]byte(user)), sha256.Sum256([]byte(pass))
		if !ok || subtle.ConstantTimeCompare(uh[:], uhRef[:]) != 1 || subtle.ConstantTimeCompare(ph[:], phRef[:]) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="metrics"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
