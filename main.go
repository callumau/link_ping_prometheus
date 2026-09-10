// Command link_ping_prometheus is a UDP echo probing agent that exposes
// Prometheus metrics for latency, packet loss, and jitter.
//
// It operates in three modes:
//   - server: runs a UDP echo responder that validates a magic header.
//   - client: sends periodic probes to targets, recording RTT and loss.
//   - both: runs server and client simultaneously.
//
// pi-lens-ignore: typos, typos:unknown
// Adaptive RTO (RFC 6298) adjusts timeouts based on measured link
// quality when -adaptive is enabled (default). UDP has no
// retransmission, so the loss ratio is true network loss.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"link_ping_prometheus/internal/prober"

	"github.com/kardianos/service"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/natefinch/lumberjack.v2"
)

// version is the build version, injected at link time via
// -ldflags "-X main.version=...". Goreleaser sets it to the git tag;
// dev_build.sh sets it to a UTC timestamp to the minute. A plain
// `go build` (and CI test builds) leaves it as "dev".
var version = "dev"

// minScavengeUnreleased is the amount of heap the runtime must be holding
// beyond what it already returned to the OS before a scavenge is worth its
// stop-the-world-adjacent cost. An already-lean process must pay nothing.
const minScavengeUnreleased = 4 << 20

// unreleasedHeap returns heap bytes the process still holds outside what
// runtime/debug has already given back to the OS. Clamped at 0: Sys can
// dip below HeapReleased transiently, and an unsigned subtraction would
// otherwise wrap to an enormous "unreleased" value and force a scavenge
// on every tick.
func unreleasedHeap(m runtime.MemStats) uint64 {
	if m.Sys <= m.HeapReleased {
		return 0
	}
	return m.Sys - m.HeapReleased
}

func shouldScavenge(m runtime.MemStats, minUnreleased uint64) bool {
	return unreleasedHeap(m) >= minUnreleased
}

// startHeapScavenger returns the unused heap high-water mark to the OS on a
// fixed interval. The runtime scavenges in proportion to the allocation rate,
// so a scrape-driven high-water mark survives indefinitely while the agent is
// idle — visible on Windows as steady commit/RSS growth. every <= 0 disables
// it. The goroutine exits with ctx so it stops on shutdown in every mode.
func startHeapScavenger(ctx context.Context, every, minUnreleased time.Duration, logger *slog.Logger) {
	if every <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(every)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			var before runtime.MemStats
			runtime.ReadMemStats(&before)
			if !shouldScavenge(before, uint64(minUnreleased)) {
				continue
			}
			debug.FreeOSMemory()
			var after runtime.MemStats
			runtime.ReadMemStats(&after)
			logger.Debug("heap scavenge",
				"sys_before_mb", before.Sys>>20, "released_before_mb", before.HeapReleased>>20,
				"sys_after_mb", after.Sys>>20, "released_after_mb", after.HeapReleased>>20)
		}
	}()
}

// CLI flags.
var (
	flMode          = flag.String("mode", "server", "Mode: server, client, both")
	flListen        = flag.String("listen", ":4000", "Server: Listen address")
	flAllow         = flag.String("allow", "", "Server: Comma-separated client IP allowlist (fail-closed: required in server/both mode)")
	flTarget        = flag.String("target", "", "Client: Single target address")
	flTargets       = flag.String("targets", "", "Client: JSON file path with targets")
	flMetrics       = flag.String("metrics", "127.0.0.1:2112", "Metrics: Listen address (default binds localhost only; use \":2112\" or \"0.0.0.0:2112\" to expose on all interfaces)")
	flSvc           = flag.String("svc", "", "Service: install, uninstall, start, stop, run")
	flJSONLogs      = flag.Bool("json-logs", false, "Log in JSON format")
	flLogFile       = flag.String("log-file", "", "Log: append logs to this file in addition to stdout (stdout is discarded under the Windows service)")
	flLogMaxSize    = flag.Int("log-file-max-mb", 10, "Log: max size in MB before rotation (0 disables rotation; requires -log-file)")
	flLogMaxBackups = flag.Int("log-file-max-backups", 5, "Log: max rotated files to keep")
	flLogMaxAge     = flag.Int("log-file-max-age", 28, "Log: max days to keep rotated files")

	flAdaptive          = flag.Bool("adaptive", true, "Client: Use adaptive timeout based on link quality (RFC 6298)")
	flBaseInterval      = flag.Duration("interval", 500*time.Millisecond, "Client: Probe interval")
	flBaseTimeout       = flag.Duration("timeout", 1*time.Second, "Client: Base/Initial timeout")
	flReconnectInterval = flag.Duration("reconnect-interval", 5*time.Minute, "Client: How long to keep a UDP socket before re-dialing for DNS re-resolution (0 means global default 5m; use a large value e.g. 24h to effectively disable)")
	flSource            = flag.String("source", "", "Source label applied to all metrics, e.g. local datacenter (sydney-dc) (defaults to hostname)")

	flDSCP = flag.Int("dscp", 0, "Client: DSCP value 0-63 marked on probe packets (0 = no marking, default; e.g. 46 = EF). Best effort, requires OS support (Linux)")

	flPayload       = flag.Int("payload", 0, "Client: probe payload bytes beyond the 24/32-byte header (up to 1400), filled with a deterministic pattern and validated on echo; corruption is counted in link_probes_corrupted_total, distinct from loss")
	flTargetsReload = flag.Duration("targets-reload-interval", 0, "Client: poll the -targets file at this interval and apply changes without a restart (0 disables; SIGHUP also reloads on Unix; Windows services need this flag to reload)")
	flMTUSweep      = flag.Duration("mtu-sweep", time.Minute, "Client: periodically sweep DF-set probe sizes per target to find the largest frame the path carries (0 disables; Linux and Windows 10+; results in link_path_mtu_bytes and /status; separate counters, never in the loss ratio)")
	flMemScavenge   = flag.Duration("mem-scavenge", 5*time.Minute, "Process: force a heap scavenge at this interval so the unused heap high-water mark is returned to the OS (0 disables). Scrapes ratchet the heap high-water up and the runtime does not return it while the agent is otherwise idle; on Windows that reads as RSS/commit growth.")

	flMetricsBasicAuthUser = flag.String("metrics-user", "", "Metrics: Basic auth username (empty disables auth; env LINK_PING_METRICS_USER)")
	flMetricsBasicAuthPass = flag.String("metrics-pass", "", "Metrics: Basic auth password (env LINK_PING_METRICS_PASS; prefer env over CLI to avoid ps exposure)")
	flMetricsTLSCert       = flag.String("metrics-tls-cert", "", "Metrics: TLS certificate file (requires -metrics-tls-key)")
	flMetricsTLSKey        = flag.String("metrics-tls-key", "", "Metrics: TLS private key file (requires -metrics-tls-cert)")
	flMetricsAllowInsecure = flag.Bool("metrics-allow-insecure", false, "Metrics: allow Basic Auth over plaintext HTTP (otherwise requires TLS when auth is set)")
	flEchoSecret           = flag.String("echo-secret", "", "Wire: HMAC secret for UDP echo authentication (env LINK_PING_ECHO_SECRET; mitigates reflector spoof when set on both client and server)")
	flEchoSecretOld        = flag.String("echo-secret-old", "", "Wire: previous HMAC secret, still accepted by the SERVER during a zero-downtime rotation alongside -echo-secret (env LINK_PING_ECHO_SECRET_OLD; server side only)")
)

// flagDefaultInt returns the registered default value of an int flag so
// validation logic stays correct if the flag defaults ever change.
func flagDefaultInt(name string) (int, error) {
	f := flag.Lookup(name)
	if f == nil {
		return 0, fmt.Errorf("missing int flag %s", name)
	}
	v, err := strconv.Atoi(f.DefValue)
	if err != nil {
		return 0, fmt.Errorf("flag %s has non-int default %q", name, f.DefValue)
	}
	return v, nil
}

func main() {
	flag.Parse()
	// Bound the Go heap so long-running RSS stays flat even during
	// /metrics scrape or probe bursts. The standard GOMEMLIMIT env var
	// (with units) overrides this default. 128MB leaves headroom for the
	// largest supported config (1000 targets: ~2000 goroutine stacks plus
	// native-histogram buckets) while keeping the agent lightweight.
	//
	// GOGC is deliberately NOT overridden here: measured on one target, a
	// lower GOGC shrinks the heap high-water mark under a bursty scrape load
	// but costs more GC metadata and allocation churn at the sparse scrape
	// rate a quiet agent actually sees. Operators can set GOGC themselves.
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(128 << 20)
	}
	if *flLogMaxSize < 0 || *flLogMaxBackups < 0 || *flLogMaxAge < 0 {
		fmt.Fprintln(os.Stderr, "log rotation flags must be >= 0")
		os.Exit(1)
	}
	if *flLogFile == "" {
		dfltSize, errSize := flagDefaultInt("log-file-max-mb")
		dfltBackups, errBackups := flagDefaultInt("log-file-max-backups")
		dfltAge, errAge := flagDefaultInt("log-file-max-age")
		if err := errors.Join(errSize, errBackups, errAge); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if *flLogMaxSize != dfltSize ||
			*flLogMaxBackups != dfltBackups ||
			*flLogMaxAge != dfltAge {
			fmt.Fprintln(os.Stderr, "log rotation flags require -log-file")
			os.Exit(1)
		}
	}
	logW := io.Writer(os.Stdout)
	if *flLogFile != "" {
		if *flLogMaxSize == 0 {
			// 0600 matches lumberjack's default: logs carry peer IPs and
			// internal topology, so they are not world-readable.
			// pi-lens-ignore: go-path-traversal
			f, err := os.OpenFile(*flLogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
			if err != nil {
				fmt.Fprintf(os.Stderr, "open log file %q: %v\n", *flLogFile, err)
				os.Exit(1)
			}
			defer f.Close()
			logW = io.MultiWriter(os.Stdout, f)
		} else {
			// ponytail: lumberjack handles rotation (10 MB ×5 ×28d default); no per-line overhead, reopens on rotation
			// pi-lens-ignore: go-path-traversal
			lj := &lumberjack.Logger{
				Filename:   *flLogFile,
				MaxSize:    *flLogMaxSize,
				MaxBackups: *flLogMaxBackups,
				MaxAge:     *flLogMaxAge,
				Compress:   false,
			}
			logW = io.MultiWriter(os.Stdout, lj)
		}
	}
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	if *flJSONLogs {
		slog.SetDefault(slog.New(slog.NewJSONHandler(logW, opts)))
	} else {
		slog.SetDefault(slog.New(slog.NewTextHandler(logW, opts)))
	}

	if *flSvc != "" {
		handleService(*flSvc)
		return
	}

	// pi-lens-ignore: go-context-background-handler
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	prg := &program{
		ctx: ctx,
	}
	if err := prg.run(); err != nil {
		slog.Error("Program exited with error", "err", err)
		os.Exit(1)
	}
}

// resolveEchoSecret returns the echo HMAC secret from flag or env.
func resolveEchoSecret() string {
	if *flEchoSecret != "" {
		return *flEchoSecret
	}
	return os.Getenv("LINK_PING_ECHO_SECRET")
}

// resolveEchoSecretOld returns the rotation-previous echo HMAC secret
// from flag or env. Empty when no rotation is in progress.
func resolveEchoSecretOld() string {
	if *flEchoSecretOld != "" {
		return *flEchoSecretOld
	}
	return os.Getenv("LINK_PING_ECHO_SECRET_OLD")
}

func sanitizeHostname(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	out := b.String()
	if out == "" {
		return "unknown"
	}
	if len(out) > 63 {
		out = out[:63]
		for len(out) > 0 && out[len(out)-1] == '-' {
			out = out[:len(out)-1]
		}
		if out == "" {
			return "unknown"
		}
	}
	return out
}

func effectiveSource() string {
	if *flSource != "" {
		return *flSource
	}
	h, err := os.Hostname()
	if err != nil || strings.TrimSpace(h) == "" {
		slog.Info("source defaulted to hostname", "source", "unknown", "hostname", h)
		return "unknown"
	}
	sanitized := sanitizeHostname(h)
	if err := prober.ValidateTargetName(sanitized); err != nil {
		slog.Info("source defaulted to hostname", "source", "unknown", "hostname", h, "sanitized", sanitized, "validate_err", err)
		return "unknown"
	}
	if sanitized != h {
		slog.Info("source defaulted to hostname", "source", sanitized, "hostname", h)
	} else {
		slog.Info("source defaulted to hostname", "source", sanitized)
	}
	return sanitized
}

// buildConfig resolves CLI flags into a prober.Config. It handles single
// (-target) and multi-target (-targets) modes. Failures are returned as
// errors so the caller can abort before any server starts.
func buildConfig() (prober.Config, error) {
	var targets []prober.Target
	if *flTargets != "" {
		var err error
		targets, err = prober.LoadTargets(*flTargets)
		if err != nil {
			return prober.Config{}, fmt.Errorf("load targets: %w", err)
		}
	} else if *flTarget != "" {
		if err := prober.ValidateTarget(*flTarget); err != nil {
			return prober.Config{}, fmt.Errorf("invalid target: %w", err)
		}
		targets = []prober.Target{{Name: "default", Address: *flTarget}}
	}
	source := *flSource
	if source == "" {
		source = effectiveSource()
	}
	if err := prober.ValidateTargetName(source); err != nil {
		return prober.Config{}, fmt.Errorf("invalid source: %w", err)
	}
	cfg := prober.Config{
		Source:            source,
		Targets:           targets,
		Adaptive:          *flAdaptive,
		BaseInterval:      *flBaseInterval,
		BaseTimeout:       *flBaseTimeout,
		EchoSecret:        resolveEchoSecret(),
		ReconnectInterval: *flReconnectInterval,
		DSCP:              *flDSCP,
		Payload:           *flPayload,
		MTUSweep:          *flMTUSweep,
	}
	return cfg, nil
}

// resolveMetricsAuth combines the CLI flags with the LINK_PING_METRICS_USER /
// LINK_PING_METRICS_PASS environment variables (flags win). Username and
// password must be configured as a pair: user-only would otherwise enable
// auth with an empty password.
func resolveMetricsAuth() (string, string, error) {
	userFlag, passFlag := *flMetricsBasicAuthUser, *flMetricsBasicAuthPass
	hasFlag := userFlag != "" || passFlag != ""
	var user, pass string
	if hasFlag {
		user, pass = userFlag, passFlag
	} else {
		user = os.Getenv("LINK_PING_METRICS_USER")
		pass = os.Getenv("LINK_PING_METRICS_PASS")
	}
	if (user == "") != (pass == "") {
		return "", "", errors.New("metrics basic auth requires both username and password (-metrics-user/-metrics-pass or LINK_PING_METRICS_USER/LINK_PING_METRICS_PASS)")
	}
	return user, pass, nil
}

// serviceConfig returns the base Windows/SCM service configuration.
// Enterprise hardening baked in at install time:
//   - OnFailure restart (5s delay): a crash or non-zero exit is restarted
//     by the Service Control Manager instead of staying stopped forever.
//   - DelayedAutoStart: avoids racing network-stack availability at boot
//     (a metrics bind failure would otherwise be fatal with no recovery).
//   - Dependencies on Tcpip (sockets) and W32Time (the HMAC replay window
//     requires roughly NTP-synchronized clocks between nodes).
//
// The description deliberately omits the version string: it is frozen at
// install time and goes stale on in-place upgrades — runtime truth lives
// in the link_ping_build_info metric instead.
func serviceConfig() *service.Config {
	return &service.Config{
		Name:        "link_ping_prometheus",
		DisplayName: "Link Ping Prometheus",
		Description: "UDP echo link monitor: Prometheus latency, packet loss, and jitter metrics",
		Arguments:   []string{},
		Dependencies: []string{
			"Tcpip",
			"W32Time",
		},
		Option: service.KeyValue{
			"StartType":              "automatic",
			"DelayedAutoStart":       true,
			"OnFailure":              "restart",
			"OnFailureDelayDuration": "5s",
			"OnFailureResetPeriod":   86400,
		},
	}
}

// handleService manages the Windows service lifecycle via the
// kardianos/service package. It reconstructs CLI arguments at install
// time, excluding -svc itself and sensitive flags (-metrics-user,
// -metrics-pass).
func handleService(action string) {
	svcConfig := serviceConfig()

	if action == "install" {
		exePath, err := os.Executable()
		if err != nil {
			slog.Error("Failed to get executable path", "err", err)
			os.Exit(1)
		}
		var args []string
		// The two auth flags and echo secret are stripped here (with -svc) so credentials
		// are never persisted into the service configuration; they must be
		// configured via env LINK_PING_METRICS_USER/PASS and LINK_PING_ECHO_SECRET.
		flag.Visit(func(f *flag.Flag) {
			if f.Name != "svc" && f.Name != "metrics-user" && f.Name != "metrics-pass" && f.Name != "echo-secret" && f.Name != "echo-secret-old" {
				v := f.Value.String()
				switch f.Name {
				case "targets", "metrics-tls-cert", "metrics-tls-key", "log-file", "log-file-max-mb", "log-file-max-backups", "log-file-max-age":
					if v != "" && !filepath.IsAbs(v) {
						if abs, err := filepath.Abs(v); err == nil {
							v = abs
						}
					}
				}
				args = append(args, fmt.Sprintf("-%s=%s", f.Name, v))
			}
		})
		args = append(args, "-svc=run")
		svcConfig.Arguments = args
		svcConfig.Executable = exePath

		if *flMetricsBasicAuthUser != "" || *flMetricsBasicAuthPass != "" {
			fmt.Println("WARNING: -metrics-user/-metrics-pass are NOT persisted into the service configuration.")
			fmt.Println("Configure LINK_PING_METRICS_USER/LINK_PING_METRICS_PASS in the service environment instead.")
		}
		if *flEchoSecret != "" {
			fmt.Println("WARNING: -echo-secret is NOT persisted into the service configuration.")
			fmt.Println("Configure LINK_PING_ECHO_SECRET in the service environment instead.")
		}
		if *flEchoSecretOld != "" {
			fmt.Println("WARNING: -echo-secret-old is NOT persisted into the service configuration.")
			fmt.Println("Configure LINK_PING_ECHO_SECRET_OLD in the service environment instead.")
		}
		if *flLogFile == "" {
			// stdout is discarded under the service: without -log-file every
			// slog line vanishes and a crash can be completely invisible.
			fmt.Println("WARNING: -log-file is not set; under the service stdout is discarded so NO logs will be captured anywhere.")
			fmt.Println("Pass -log-file=<path> at install time (lifecycle events still reach the Windows event log).")
		}
	}

	// Zero-value program: ctx is only ever set by Start(), which
	// install/uninstall/start/stop never invoke.
	prg := &program{}

	s, err := service.New(prg, svcConfig)
	if err != nil {
		slog.Error("Failed to init service", "err", err)
		os.Exit(1)
	}

	switch action {
	case "install":
		if err := s.Install(); err != nil {
			slog.Error("Install failed", "err", err)
			os.Exit(1)
		}
		fmt.Println("Service installed.")
	case "uninstall":
		if err := s.Uninstall(); err != nil {
			slog.Error("Uninstall failed", "err", err)
			os.Exit(1)
		}
		fmt.Println("Service uninstalled.")
	case "start":
		if err := s.Start(); err != nil {
			slog.Error("Start failed", "err", err)
			os.Exit(1)
		}
		fmt.Println("Service started.")
	case "stop":
		if err := s.Stop(); err != nil {
			slog.Error("Stop failed", "err", err)
			os.Exit(1)
		}
		fmt.Println("Service stopped.")
	case "run":
		if err := s.Run(); err != nil {
			slog.Error("Run failed", "err", err)
			os.Exit(1)
		}
	default:
		// A typo like -svc=instal must not exit 0: the operator would
		// read that as "installed" and get no service and no error.
		slog.Error("Unknown action", "action", action)
		os.Exit(1)
	}
}

// program implements service.Interface for kardianos/service.
type program struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// Start is called by the service framework to begin execution.
// The WaitGroup Add happens here — before the goroutine starts — so
// Stop can never race it (the framework calls Stop only after Start
// has returned).
func (p *program) Start(s service.Service) error {
	// Lifecycle events go to the system logger (Windows event log under
	// the SCM, syslog elsewhere): the only channel a fleet operator sees
	// without access to -log-file. Best-effort — file logging stays the
	// primary sink.
	if s != nil {
		if sysLog, err := s.SystemLogger(nil); err == nil {
			sysLog.Infof("link_ping_prometheus service starting (version %s)", version)
		}
	}
	// pi-lens-ignore: go-context-background-handler
	p.ctx, p.cancel = context.WithCancel(context.Background())
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		if err := p.run(); err != nil {
			slog.Error("Service run error", "err", err)
			if s != nil {
				if sysLog, lerr := s.SystemLogger(nil); lerr == nil {
					sysLog.Errorf("service run failed: %v", err)
				}
			}
			// Die UNCLEANLY: exiting non-zero classifies this as a failure
			// to the SCM so the OnFailure restart action fires. Calling
			// s.Stop() here would report a clean SERVICE_STOPPED and the
			// monitor would stay down until manual intervention.
			os.Exit(1)
		}
	}()
	return nil
}

// Stop is called by the service framework to shut down gracefully.
// It cancels the context and waits for the run goroutine to finish.
func (p *program) Stop(s service.Service) error {
	if p.cancel != nil {
		p.cancel()
	}
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-time.After(20 * time.Second):
		slog.Error("Service stop deadline exceeded")
		return errors.New("service stop timed out after 20s")
	}
}

// startMetricsServer binds addr, wires the metrics/status/probe handlers
// and starts serving in a goroutine. It returns the server plus a channel
// closed when serving stops; the listener is bound here rather than
// lazily so a bind failure reaches the caller as an error and aborts
// startup. String arguments are captured values, not flag reads: the
// serve goroutine may outlive flag mutation by tests or shutdown code.
func (p *program) startMetricsServer(addr, user, pass, cert, key string, statusReg *prober.StatusRegistry) (*http.Server, <-chan struct{}, error) {
	metricsLn, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("metrics server: %w", err)
	}
	mx := http.NewServeMux()
	mx.Handle("/metrics", prober.MetricsAuth(user, pass, promhttp.Handler()))
	healthzHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		// pi-lens-ignore: go-ignored-call-result
		_, _ = w.Write([]byte("ok\n"))
	})
	// /healthz and /readyz are deliberately unauthenticated: they are
	// liveness/readiness probes that an orchestrator must reach without
	// credentials, and they expose no data. Do not gate them.
	mx.Handle("/healthz", healthzHandler)
	mx.Handle("/readyz", healthzHandler)
	// /status exposes live per-target probe state (link_up, inflight,
	// misses, RTO, socket age). Gated like /metrics: open only when no
	// metrics auth is configured.
	mx.Handle("/status", prober.MetricsAuth(user, pass, statusReg.Handler()))
	metricsSrv := &http.Server{
		Handler:      mx,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
		// Bounded header read: ReadTimeout alone starts only after the
		// headers land, so a slowloris client could otherwise hold a
		// connection open indefinitely.
		ReadHeaderTimeout: 10 * time.Second,
	}
	if cert != "" {
		metricsSrv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	metricsDone := make(chan struct{})
	go func() {
		defer close(metricsDone)
		slog.Info("Starting metrics server", "addr", addr, "tls", cert != "", "auth", user != "")
		var serveErr error
		if cert != "" {
			serveErr = metricsSrv.ServeTLS(metricsLn, cert, key)
		} else {
			serveErr = metricsSrv.Serve(metricsLn)
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			slog.Error("Metrics server error", "err", serveErr)
		}
	}()
	return metricsSrv, metricsDone, nil
}

// run initialises metrics, starts the Prometheus HTTP server, and
// dispatches to the selected mode (server, client, or both).
func (p *program) run() error {
	prober.InitMetrics()
	prober.BuildInfo.WithLabelValues(version).Set(1)
	slog.Info("starting", "version", version)

	// Fail fast on unknown mode BEFORE binding anything: a bad -mode
	// should never open ports or start servers.
	switch mode := *flMode; mode {
	case "server", "client", "both":
	default:
		return fmt.Errorf("unknown mode: %s", mode)
	}

	user, pass, err := resolveMetricsAuth()
	if err != nil {
		return err
	}
	cert, key := *flMetricsTLSCert, *flMetricsTLSKey
	if (cert == "") != (key == "") {
		return errors.New("-metrics-tls-cert and -metrics-tls-key must be set together")
	}
	if cert != "" {
		if _, err := tls.LoadX509KeyPair(cert, key); err != nil {
			return fmt.Errorf("metrics TLS: %w", err)
		}
	}
	if user != "" && cert == "" && !*flMetricsAllowInsecure {
		return errors.New("metrics basic auth requires TLS (-metrics-tls-cert/-key) or -metrics-allow-insecure to allow plaintext")
	} else if user != "" && cert == "" {
		slog.Warn("Metrics basic auth over plaintext HTTP: credentials are base64-only on the wire; consider -metrics-tls-cert/-metrics-tls-key")
	}

	var cfg prober.Config
	if *flMode != "server" {
		var err error
		cfg, err = buildConfig()
		if err != nil {
			return err
		}
	}
	// Periodic scavenger: shares p.ctx so it stops with the mode loops.
	startHeapScavenger(p.ctx, *flMemScavenge, minScavengeUnreleased, slog.Default())

	// Live per-target state for the /status debug endpoint. Always
	// registered so server-only mode still serves an empty list.
	statusReg := prober.NewStatusRegistry()
	cfg.Status = statusReg
	// SIGHUP hot-reload of the targets file (Unix; Windows services use
	// -targets-reload-interval). Signals coalesce: every delivery just
	// re-reads and re-validates the file, which is idempotent.
	if *flTargets != "" {
		cfg.TargetsPath = *flTargets
		cfg.ReloadInterval = *flTargetsReload
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGHUP)
		defer signal.Stop(sigCh)
		cfg.ReloadSignal = sigCh
	}

	// Resolve source for server metrics; defaults to hostname and is validated.
	// For client/both modes cfg.Source already holds the effective source (via buildConfig).
	// For server-only mode we resolve it here.
	sourceForServer := *flSource
	if sourceForServer == "" {
		if cfg.Source != "" {
			sourceForServer = cfg.Source
		} else {
			sourceForServer = effectiveSource()
			if err := prober.ValidateTargetName(sourceForServer); err != nil {
				return fmt.Errorf("invalid source: %w", err)
			}
		}
	} else {
		if err := prober.ValidateTargetName(sourceForServer); err != nil {
			return fmt.Errorf("invalid source: %w", err)
		}
	}

	// Fail-closed client allowlist: the echo responder refuses to run
	// without an explicit -allow list, so spoofed/unauthorised sources
	// can neither reflect datagrams nor grow metric label cardinality.
	allow, err := prober.ParseAllowlist(*flAllow)
	if err != nil {
		return err
	}
	if mode := *flMode; (mode == "server" || mode == "both") && allow.Len() == 0 {
		return errors.New("server mode requires -allow (comma-separated client IP allowlist); fail-closed")
	}

	// Bind the metrics listener before any probing starts so a bind
	// failure (port taken, permission denied) aborts startup instead of
	// leaving the agent running with no /metrics endpoint — a silent
	// partial failure for a monitoring agent.
	metricsSrv, metricsDone, err := p.startMetricsServer(*flMetrics, user, pass, cert, key, statusReg)
	if err != nil {
		return err
	}

	echoSecret := resolveEchoSecret()
	echoSecretOld := resolveEchoSecretOld()
	mode := *flMode
	var modeErr error
	switch mode {
	case "server":
		modeErr = prober.RunServer(p.ctx, *flListen, sourceForServer, allow, echoSecret, echoSecretOld)
	case "client":
		modeErr = prober.RunClient(p.ctx, cfg)
	case "both":
		// Local WaitGroup: Add is sequenced before the goroutine starts
		// and Wait runs in the same goroutine, so no Add/Wait race.
		modeCtx, modeCancel := context.WithCancel(p.ctx)
		var wg sync.WaitGroup
		var serverErr error
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := prober.RunServer(modeCtx, *flListen, sourceForServer, allow, echoSecret, echoSecretOld); err != nil {
				// A server that fails to start (e.g. port already in
				// use) is fatal in both mode: cancelling the client too
				// fails fast instead of probing silently without an
				// echo responder.
				serverErr = err
				modeCancel()
			}
		}()
		modeErr = prober.RunClient(modeCtx, cfg)
		modeCancel()
		wg.Wait()
		if serverErr != nil {
			modeErr = serverErr
		}
	default:
		modeErr = fmt.Errorf("unknown mode: %s", mode)
	}

	// Drain the metrics server on the way out so an in-flight scrape
	// finishes instead of being cut off by process exit. Best-effort:
	// the agent's own metrics are in-memory and die with it regardless.
	// pi-lens-ignore: go-context-background-handler
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// pi-lens-ignore: go-ignored-call-result
	_ = metricsSrv.Shutdown(shutCtx)
	<-metricsDone
	return modeErr
}
