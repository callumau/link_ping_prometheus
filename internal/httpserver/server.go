package httpserver

import (
	"crypto/tls"
	"errors"
	"fmt"
	"link_ping_prometheus/internal/prober"
	"log"
	"log/slog"
	"net"
	"net/http"
	"strings"
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

// maxHeaderBytes bounds the request header block the management listener will
// read before authentication. The only pre-auth header that matters is
// Authorization; the net/http default of 1 MiB let an unauthenticated client
// make the process parse ~900 KiB before the 401. Scrapers and orchestrators
// send well under a kilobyte.
const maxHeaderBytes = 16 << 10

// maxConcurrentConnections bounds accepted-but-unserved connections. The
// listener has no auth in front of the TCP accept (and /healthz is open), so
// an attacker on an exposed bind could otherwise hold an unbounded number of
// goroutines, TLS handshakes and buffers on a process whose job is measuring
// RTT. Accept blocks once the limit is reached; the kernel backlog absorbs the
// rest. 256 is far above any scrape/orchestrator concurrency.
var maxConcurrentConnections = 256

// handshakeLogInterval throttles the http.Server ErrorLog. net/http reports
// every failed TLS handshake through it, so an unauthenticated client could
// emit one log line per connection and rotate the auth-failure evidence out of
// the retained window.
var handshakeLogInterval = time.Minute

// rateLimitedLogWriter forwards one message per interval and reports how many
// similar messages it suppressed, so a flood cannot erase the log window while
// the first occurrence stays visible.
type rateLimitedLogWriter struct {
	mu         sync.Mutex
	last       time.Time
	suppressed int
	forward    func(string)
}

func (w *rateLimitedLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	now := time.Now()
	if !w.last.IsZero() && now.Sub(w.last) < handshakeLogInterval {
		w.suppressed++
		w.mu.Unlock()
		return len(p), nil
	}
	n := w.suppressed
	w.suppressed = 0
	w.last = now
	w.mu.Unlock()

	msg := strings.TrimSpace(string(p))
	if n > 0 {
		msg = fmt.Sprintf("%s (%d similar messages suppressed)", msg, n)
	}
	w.forward(msg)
	return len(p), nil
}

// limitListener caps concurrently accepted connections. Release is tied to
// Close of the returned connection.
type limitListener struct {
	net.Listener
	sem       chan struct{}
	closeOnce sync.Once
	done      chan struct{}
}

func limitListenerFor(l net.Listener, n int) net.Listener {
	return &limitListener{
		Listener: l,
		sem:      make(chan struct{}, n),
		done:     make(chan struct{}),
	}
}

func (l *limitListener) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	return l.Listener.Close()
}

func (l *limitListener) Accept() (net.Conn, error) {
	select {
	case <-l.done:
		return nil, net.ErrClosed
	case l.sem <- struct{}{}:
	}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return &limitConn{Conn: c, release: func() { <-l.sem }}, nil
}

type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

// ShutdownJoinGrace bounds the wait for the metrics serve goroutine to exit
// after Shutdown: an in-flight scrape holds Serve open up to the 30s
// WriteTimeout, which exceeds the service Stop deadline (20s). The drain is
// best-effort, so the join is cut short rather than making Stop report a
// timeout while the process drains a clean shutdown.
const ShutdownJoinGrace = 2 * time.Second

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
			_, _ = w.Write([]byte("not ready: no target has ever had a working socket\n"))
			return
		}
		w.WriteHeader(http.StatusOK)
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

// Start binds addr, wires the metrics/status/probe handlers
// and starts serving in a goroutine. It returns the server plus a channel
// closed when serving stops; the listener is bound here rather than
// lazily so a bind failure reaches the caller as an error and aborts
// startup. String arguments are captured values, not flag reads: the
// serve goroutine may outlive flag mutation by tests or shutdown code.
func Start(addr, user, pass, cert, key string, statusReg *prober.StatusRegistry, gzip bool, mode string) (*http.Server, <-chan struct{}, error) {
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
	mx.Handle("/metrics", MetricsAuth(user, pass, metricsHandler(gzip)))
	healthzHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
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
	mx.Handle("/status", MetricsAuth(user, pass, limitConcurrent(maxConcurrentScrapes, statusReg.Handler())))
	metricsSrv := &http.Server{
		Handler: mx,
		// net/http reports its OWN failures (TLS handshake errors, accept
		// errors, recovered handler panics) through the std log package to
		// os.Stderr — and under the Windows service stderr is discarded, so a
		// failing handshake or a panicking handler would leave no trace at all.
		// Route them through slog so they land in -log-file / the event log
		// with everything else.
		ErrorLog: log.New(&rateLimitedLogWriter{forward: func(msg string) {
			// The message itself, so the std-log line keeps its shape and
			// waitForLog/log-scraping rules still see "TLS handshake error".
			slog.Warn(msg)
		}}, "", 0),
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
		// The only pre-auth header that matters is Authorization.
		MaxHeaderBytes: maxHeaderBytes,
	}
	if tlsCfg != nil {
		metricsSrv.TLSConfig = tlsCfg
	}
	// Bound concurrently accepted connections before any request work.
	metricsLn = limitListenerFor(metricsLn, maxConcurrentConnections)
	metricsDone := make(chan struct{})
	go func() {
		defer close(metricsDone)
		slog.Info("Starting metrics server", "addr", addr, "tls", cert != "", "auth", user != "")
		var serveErr error
		if tlsCfg == nil {
			serveErr = metricsSrv.Serve(metricsLn)
		} else {
			// Empty cert/key paths keep TLSConfig.Certificates nil so GetCertificate
			// is consulted on every handshake (including IP-literal scrapes without SNI).
			serveErr = metricsSrv.ServeTLS(metricsLn, "", "")
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			slog.Error("Metrics server error", "err", serveErr)
		}
	}()
	return metricsSrv, metricsDone, nil
}
