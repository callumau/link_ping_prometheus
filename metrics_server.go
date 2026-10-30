package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"link_ping_prometheus/internal/prober"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// maxConcurrentScrapes bounds simultaneous /metrics gathers. A large fleet's
// response is ~10-15MB of text and every concurrent scrape builds its own copy,
// so unbounded overlap multiplies both the live heap and the wall time of each
// response (risking a truncated scrape, i.e. the monitor reporting ITSELF
// down). Excess scrapes get a 503 instead; Prometheus retries.
const maxConcurrentScrapes = 2

// shutdownJoinGrace bounds the wait for the metrics serve goroutine to exit
// after Shutdown: an in-flight scrape holds Serve open up to the 30s
// WriteTimeout, which exceeds the service Stop deadline (20s). The drain is
// best-effort, so the join is cut short rather than making Stop report a
// timeout while the process drains a clean shutdown.
const shutdownJoinGrace = 2 * time.Second

// metricsHandler builds the /metrics handler for the default gatherer.
func metricsHandler(gzip bool) http.Handler {
	return metricsHandlerFor(prometheus.DefaultGatherer, gzip)
}

// metricsHandlerFor builds the /metrics handler for an arbitrary gatherer.
// gzip=false disables response compression on purpose: promhttp pools a
// gzip.Writer per P and each writer holds a flate compressor of roughly 0.7MB
// (hashHead 1<<17 + hashPrev 1<<15 plus a 32KB window), so compression costs up
// to ~0.7MB x GOMAXPROCS of live heap that only a GC reclaims - measured as the
// dominant scrape-driven heap growth. For a small fleet the whole response is
// smaller than one compressor, so plain is the lighter default; large fleets
// should enable it. The gatherer is a parameter so the concurrency cap it
// applies (MaxRequestsInFlight) can be exercised deterministically in tests.
func metricsHandlerFor(g prometheus.Gatherer, gzip bool) http.Handler {
	h := promhttp.HandlerFor(g, promhttp.HandlerOpts{
		DisableCompression:  !gzip,
		MaxRequestsInFlight: maxConcurrentScrapes,
	})
	// Restore the scrape instrumentation that promhttp.Handler() used to
	// register and HandlerFor() does not: without
	// promhttp_metric_handler_requests_total{code="503"} and
	// _requests_in_flight, a scrape rejected by the concurrency cap above is
	// invisible. Safe to call on every handler build (tests, repeated
	// registrations): it reuses the already-registered collector instead of
	// panicking.
	return promhttp.InstrumentMetricHandler(prometheus.DefaultRegisterer, h)
}

func readyToProbe(mode string, statusReg *prober.StatusRegistry) bool {
	if mode == "server" {
		// Server-only mode has no targets at all, and a server that cannot
		// bind dies instead of limping, so it is ready by definition.
		return true
	}
	return statusReg.AnyReady()
}

// readinessHandler answers /readyz: 200 when probing is possible, 503 when a
// client-side agent has never held a working socket for any target.
func readinessHandler(mode string, statusReg *prober.StatusRegistry) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if !readyToProbe(mode, statusReg) {
			w.WriteHeader(http.StatusServiceUnavailable)
			// pi-lens-ignore: go-ignored-call-result
			_, _ = w.Write([]byte("not ready: no target has ever had a working socket\n"))
			return
		}
		w.WriteHeader(http.StatusOK)
		// pi-lens-ignore: go-ignored-call-result
		_, _ = w.Write([]byte("ok\n"))
	})
}

// limitConcurrent wraps handler in a counting semaphore of limit slots:
// the first limit concurrent requests are served normally, any further
// request gets a plain-text 503 (the same status and message shape the
// /metrics cap produces) and never reaches the handler. Slot release is
// tied to the ServeHTTP call itself (not to the handler's return), so a
// panic among the admitted requests unwinds through the deferred release
// and cannot leak a slot forever. The semaphore is a channel, exactly
// the promhttp MaxRequestsInFlight pattern, which /status cannot reuse
// because it is bound to a Gatherer rather than a plain handler.
func limitConcurrent(limit int, handler http.Handler) http.Handler {
	sem := make(chan struct{}, limit)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
			handler.ServeHTTP(w, r)
		default:
			// Same wording shape as promhttp's MaxRequestsInFlight body; the
			// limit is interpolated, not hardcoded, so the body cannot drift
			// from the cap a maintainer changes.
			http.Error(w, fmt.Sprintf("Limit of concurrent requests reached (%d), try again later.", limit), http.StatusServiceUnavailable)
		}
	})
}

// certReloadRetryCooldown is how long a fingerprint whose load FAILED is
// skipped before the pair is read again. The retry is what makes an in-place
// repair observable: a pair fixed without touching (mtime, size) — a
// chmod-only fix, a same-size rewrite that preserves the timestamp — keeps the
// fingerprint the failed attempt was recorded under, so a pure memo would serve
// the expired certificate until the files changed again, i.e. exactly the
// silent scrape blackout the reloader exists to prevent. The cooldown keeps the
// other side of that tradeoff: a genuinely broken renewal costs one file read
// (and at most one Warn) per cooldown, not one per handshake. A var so tests
// can lower it.
var certReloadRetryCooldown = 30 * time.Second

// metricsCertReloader serves the metrics TLS pair from a cache that is re-read
// when either file's (mtime, size) changes, so a renewed certificate takes
// effect without a restart. ServeTLS otherwise loads the pair exactly once: on
// 90-day certificates plus a service that is never restarted, that one-shot load
// is a silent scrape blackout the day the cert expires — and under the SCM the
// resulting handshake error is invisible (stderr is discarded). Set as
// TLSConfig.GetCertificate, which crypto/tls consults for every handshake.
type metricsCertReloader struct {
	certPath, keyPath string

	mu sync.Mutex
	// cert is the pair currently served. Seeded at construction, so no
	// handshake can ever observe an empty cache.
	cert *tls.Certificate
	// loaded is the fingerprint of the pair in cert; attempted/attemptedAt are
	// the last fingerprint a reload was tried for and when. Kept apart so a
	// failed load is retried only after certReloadRetryCooldown rather than on
	// every handshake, which would flood the very log the reload exists to make
	// visible (see certReloadRetryCooldown for why the retry matters at all).
	loaded, attempted certFingerprint
	attemptedAt       time.Time
	// statFailed latches the stat-error warning the same way.
	statFailed bool
}

// certFingerprint identifies a certificate/key file pair by the metadata a
// renewal changes. Hashing the contents would cost a full read on every
// handshake; (mtime, size) is what rotators and `mv` in place actually touch.
type certFingerprint struct {
	certMod, keyMod   time.Time
	certSize, keySize int64
}

func fingerprintCertPair(certPath, keyPath string) (certFingerprint, error) {
	certInfo, err := os.Stat(certPath)
	if err != nil {
		return certFingerprint{}, err
	}
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		return certFingerprint{}, err
	}
	return certFingerprint{
		certMod: certInfo.ModTime(), certSize: certInfo.Size(),
		keyMod: keyInfo.ModTime(), keySize: keyInfo.Size(),
	}, nil
}

// newMetricsCertReloader loads the pair once and seeds the cache with it — the
// same load run() performs as startup validation. A pair that will not load is
// a startup error, never a listener that serves nothing.
func newMetricsCertReloader(certPath, keyPath string) (*metricsCertReloader, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	fp, err := fingerprintCertPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	return &metricsCertReloader{certPath: certPath, keyPath: keyPath, cert: &cert, loaded: fp, attempted: fp}, nil
}

// GetCertificate implements tls.Config.GetCertificate.
func (r *metricsCertReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	fp, err := fingerprintCertPair(r.certPath, r.keyPath)
	if err != nil {
		// Unstattable (a rename-in-progress, a rotated-away inode): keep serving
		// the cached pair rather than failing every handshake on the way past.
		if !r.statFailed {
			r.statFailed = true
			slog.Warn("Metrics TLS certificate files are not statable; keeping the previously loaded certificate",
				"cert", r.certPath, "key", r.keyPath, "err", err)
		}
		return r.cert, nil
	}
	r.statFailed = false
	if fp == r.loaded {
		return r.cert, nil
	}
	if fp == r.attempted && time.Since(r.attemptedAt) < certReloadRetryCooldown {
		return r.cert, nil
	}
	r.attempted, r.attemptedAt = fp, time.Now()
	cert, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		// A half-written renewal or a key that does not match: keep the working
		// cert and say so once. Failing the handshake instead would black out
		// every scrape over a transient write.
		slog.Warn("Metrics TLS certificate reload failed; keeping the previously loaded certificate",
			"cert", r.certPath, "key", r.keyPath, "err", err)
		return r.cert, nil
	}
	r.cert, r.loaded = &cert, fp
	slog.Info("Metrics TLS certificate reloaded", "cert", r.certPath, "key", r.keyPath)
	return r.cert, nil
}

// warnUnauthenticatedMetricsBind warns when the metrics listener came up on an
// address reachable from off-host with no Basic auth. The flag help says the
// default binds localhost only, but nothing at runtime says the operator just
// widened it without credentials — and the payload is the probe topology, peer
// IPs and per-link RTT/loss, i.e. the network map itself.
func warnUnauthenticatedMetricsBind(addr net.Addr, user string) {
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok || user != "" || tcpAddr.IP.IsLoopback() {
		return
	}
	slog.Warn("Metrics endpoint is bound to a non-loopback address WITHOUT authentication: anyone who can reach it sees the probe topology, peer IPs and per-link RTT/loss",
		"addr", tcpAddr.String(),
		"fix", "bind 127.0.0.1, or set -metrics-user/-metrics-pass with -metrics-tls-cert/-metrics-tls-key (or -metrics-allow-insecure to accept plaintext auth)")
}

// startMetricsServer binds addr, wires the metrics/status/probe handlers
// and starts serving in a goroutine. It returns the server plus a channel
// closed when serving stops; the listener is bound here rather than
// lazily so a bind failure reaches the caller as an error and aborts
// startup. String arguments are captured values, not flag reads: the
// serve goroutine may outlive flag mutation by tests or shutdown code.
func (p *program) startMetricsServer(addr, user, pass, cert, key string, statusReg *prober.StatusRegistry, gzip bool, mode string) (*http.Server, <-chan struct{}, error) {
	// Resolve the TLS pair BEFORE binding: a cert that cannot be loaded must
	// abort startup without leaving a bound port behind it.
	var tlsCfg *tls.Config
	if cert != "" {
		reloader, err := newMetricsCertReloader(cert, key)
		if err != nil {
			return nil, nil, fmt.Errorf("metrics TLS: %w", err)
		}
		// GetCertificate (not the Certificates slice) so every handshake can pick
		// up a renewed pair. Constructing the reloader here is also the startup
		// validation: a pair that will not load aborts the bind attempt.
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: reloader.GetCertificate}
	}
	metricsLn, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("metrics server: %w", err)
	}
	warnUnauthenticatedMetricsBind(metricsLn.Addr(), user)
	mx := http.NewServeMux()
	mx.Handle("/metrics", prober.MetricsAuth(user, pass, metricsHandler(gzip)))
	healthzHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		// pi-lens-ignore: go-ignored-call-result
		_, _ = w.Write([]byte("ok\n"))
	})
	// /healthz and /readyz are deliberately unauthenticated: they are
	// liveness/readiness probes that an orchestrator must reach without
	// credentials, and they expose no data. Do not gate them. /readyz is NOT
	// an alias of /healthz (it was): liveness means the process is running,
	// readiness means it is actually probing.
	mx.Handle("/healthz", healthzHandler)
	mx.Handle("/readyz", readinessHandler(mode, statusReg))
	// /status exposes live per-target probe state (link_up, inflight,
	// misses, RTO, socket age). Gated like /metrics: open only when no
	// metrics auth is configured. Capped like /metrics too: the snapshot
	// copies and sorts the whole registry and the process snapshot does a
	// potentially STW ReadMemStats, so a local burst loop must not pile
	// those on top of each other. /healthz and /readyz stay uncapped —
	// they are cheap booleans an orchestrator must always reach.
	mx.Handle("/status", prober.MetricsAuth(user, pass, limitConcurrent(maxConcurrentScrapes, statusReg.Handler())))
	metricsSrv := &http.Server{
		Handler: mx,
		// net/http reports its OWN failures (TLS handshake errors, accept
		// errors, recovered handler panics) through the std log package to
		// os.Stderr — and under the Windows service stderr is discarded, so a
		// failing handshake or a panicking handler would leave no trace at all.
		// Route them through slog so they land in -log-file / the event log
		// with everything else.
		ErrorLog: slog.NewLogLogger(slog.Default().Handler(), slog.LevelWarn),
		// Addr is informational (Serve uses the already-bound listener) but
		// lets tests and logs address the live server without guessing.
		Addr:        metricsLn.Addr().String(),
		ReadTimeout: 10 * time.Second,
		// 30s, not 10s: a large fleet on a slow link can need longer than 10s
		// to write a multi-megabyte scrape body, and a truncated response
		// reads as the monitor itself being down. Reads stay at 10s so a slow
		// client still cannot hold a connection.
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
		// Bounded header read: ReadTimeout alone starts only after the
		// headers land, so a slowloris client could otherwise hold a
		// connection open indefinitely.
		ReadHeaderTimeout: 10 * time.Second,
	}
	if tlsCfg != nil {
		metricsSrv.TLSConfig = tlsCfg
	}
	metricsDone := make(chan struct{})
	go func() {
		defer close(metricsDone)
		slog.Info("Starting metrics server", "addr", addr, "tls", cert != "", "auth", user != "")
		var serveErr error
		if tlsCfg == nil {
			serveErr = metricsSrv.Serve(metricsLn)
		} else {
			// Empty cert/key paths on purpose: ServeTLS only skips its own
			// tls.LoadX509KeyPair when the config already carries a certificate
			// source, and it is the pair loaded into TLSConfig.Certificates that
			// would freeze the renewal. crypto/tls consults GetCertificate only
			// while that slice is empty (or the client sent SNI), so a scraper
			// dialing an IP literal would otherwise keep being served the startup
			// copy. ServeTLS (unlike a hand-rolled tls.NewListener) still owns the
			// HTTP/2 ALPN setup. The reloader already loaded and validated the
			// pair when it was constructed.
			serveErr = metricsSrv.ServeTLS(metricsLn, "", "")
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			slog.Error("Metrics server error", "err", serveErr)
		}
	}()
	return metricsSrv, metricsDone, nil
}

// run initialises metrics, starts the Prometheus HTTP server, and
// dispatches to the selected mode (server, client, or both).
