package httpserver

import (
	"crypto/sha256"
	"crypto/subtle"
	"link_ping_prometheus/internal/prober"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// MetricsAuth returns an HTTP handler that wraps next with HTTP Basic
// Authentication. If user is empty, authentication is disabled.
func MetricsAuth(user, pass string, next http.Handler) http.Handler {
	if user == "" {
		return next
	}
	// Hash the reference credentials once at handler creation; the
	// request-path hashes are computed per request.
	uhRef, phRef := sha256.Sum256([]byte(user)), sha256.Sum256([]byte(pass))
	// lastAuthLog throttles the failure warning to once per minute: an
	// unauthenticated scanner must not be able to flood the log. The
	// counter still records every failure.
	var lastAuthLog atomic.Int64
	const (
		authFailWindow   = time.Minute
		authFailBurstMax = 60
		authFailTableCap = 1024
	)
	type failBucket struct {
		windowStart int64
		count       int
	}
	var failMu sync.Mutex
	failMap := make(map[string]failBucket)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		// Hash before comparing: ConstantTimeCompare returns immediately on
		// length mismatch, which would otherwise leak credential length.
		uh, ph := sha256.Sum256([]byte(u)), sha256.Sum256([]byte(p))
		if !ok || subtle.ConstantTimeCompare(uh[:], uhRef[:]) != 1 || subtle.ConstantTimeCompare(ph[:], phRef[:]) != 1 {
			prober.MetricsAuthFailures.Inc()
			now := time.Now().UnixNano()
			if last := lastAuthLog.Load(); now-last >= int64(time.Minute) && lastAuthLog.CompareAndSwap(last, now) {
				slog.Warn("metrics auth failed (further failures logged at most once per minute)", "remote", r.RemoteAddr)
			}
			host := r.RemoteAddr
			if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
				host = h
			}
			throttled := false
			failMu.Lock()
			b, exists := failMap[host]
			if !exists && len(failMap) >= authFailTableCap {
				clear(failMap)
			}
			if !exists || now-b.windowStart >= int64(authFailWindow) {
				b = failBucket{windowStart: now, count: 1}
			} else {
				b.count++
				if b.count > authFailBurstMax {
					throttled = true
				}
			}
			failMap[host] = b
			failMu.Unlock()
			if throttled {
				w.Header().Set("Retry-After", "60")
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
			w.Header().Set("WWW-Authenticate", `Basic realm="metrics"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
