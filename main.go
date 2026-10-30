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
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"sync"
	"syscall"
	"time"

	"link_ping_prometheus/internal/prober"

	"gopkg.in/natefinch/lumberjack.v2"
)

// version is the build version, injected at link time via
// -ldflags "-X main.version=...". Goreleaser sets it to the git tag;
// dev_build.sh sets it to a UTC timestamp to the minute. A plain
// `go build` (and CI test builds) leaves it as "dev".
var version = "dev"

// CLI flags.
var (
	flMode             = flag.String("mode", "server", "Mode: server, client, both")
	flListen           = flag.String("listen", ":4000", "Server: Listen address")
	flAllow            = flag.String("allow", "", "Server: Comma-separated client IP allowlist (fail-closed: required in server/both mode)")
	flAllowFromTargets = flag.Bool("allow-from-targets", false, "Server: derive the fail-closed allowlist from the -targets file addresses and skip the target whose name matches -source, so one targets file serves every site of a mesh (client/both mode; every target address must be an IP literal - a DNS name is an error, because config load never resolves). Combines with -allow for extra CIDRs.")
	flTarget           = flag.String("target", "", "Client: Single target address")
	flTargets          = flag.String("targets", "", "Client: JSON file path with targets")
	flMetrics          = flag.String("metrics", "127.0.0.1:2112", "Metrics: Listen address (default binds localhost only; use \":2112\" or \"0.0.0.0:2112\" to expose on all interfaces)")
	flSvc              = flag.String("svc", "", "Service: install, uninstall (Windows only; Linux uses the systemd unit), start, stop, run")
	flJSONLogs         = flag.Bool("json-logs", false, "Log in JSON format")
	flLogFile          = flag.String("log-file", "", "Log: append logs to this file in addition to stdout (stdout is discarded under the Windows service)")
	flLogMaxSize       = flag.Int("log-file-max-mb", 10, "Log: max size in MB before rotation (0 disables rotation; requires -log-file)")
	flLogMaxBackups    = flag.Int("log-file-max-backups", 5, "Log: max rotated files to keep (requires -log-file)")
	flLogMaxAge        = flag.Int("log-file-max-age", 28, "Log: max days to keep rotated files (requires -log-file)")

	flAdaptive          = flag.Bool("adaptive", true, "Client: Use adaptive timeout based on link quality (RFC 6298)")
	flBaseInterval      = flag.Duration("interval", 500*time.Millisecond, "Client: Probe interval")
	flBaseTimeout       = flag.Duration("timeout", 1*time.Second, "Client: Base/Initial timeout")
	flReconnectInterval = flag.Duration("reconnect-interval", 5*time.Minute, "Client: How long to keep a UDP socket before re-dialing for DNS re-resolution (0 means global default 5m; use a large value e.g. 24h to effectively disable)")
	flSource            = flag.String("source", "", "Source label applied to all metrics, e.g. local datacenter (sydney-dc) (defaults to hostname)")

	flDSCP = flag.Int("dscp", 0, "Client: DSCP value 0-63 marked on probe packets (0 = no marking, default; e.g. 46 = EF). Best effort, requires OS support (Linux)")

	flPayload       = flag.Int("payload", 0, "Client: probe payload bytes beyond the 24/32-byte header (up to 1400), filled with a deterministic pattern and validated on echo; corruption is counted in link_probes_corrupted_total, distinct from loss")
	flTargetsReload = flag.Duration("targets-reload-interval", 0, "Client: poll the -targets file at this interval and apply changes without a restart (0 disables; SIGHUP also reloads on Unix; Windows services need this flag to reload)")
	flMTUSweep      = flag.Duration("mtu-sweep", time.Minute, "Client: periodically sweep DF-set probe sizes per target to find the largest frame the path carries (0 disables; Linux, or Windows with IPv4 on 2003+ / IPv6 on 1703+; results in link_path_mtu_bytes and /status; separate counters, never in the loss ratio)")
	flMemScavenge   = flag.Duration("mem-scavenge", 5*time.Minute, "Process: force a heap scavenge at this interval so the unused heap high-water mark is returned to the OS (0 disables; the interval must be at least 100ms, because each scavenge stops the world). Scrapes ratchet the heap high-water up and the runtime does not return it while the agent is otherwise idle; on Windows that reads as RSS/commit growth.")

	flMetricsBasicAuthUser = flag.String("metrics-user", "", "Metrics: Basic auth username (empty disables auth; env LINK_PING_METRICS_USER)")
	flMetricsBasicAuthPass = flag.String("metrics-pass", "", "Metrics: Basic auth password (env LINK_PING_METRICS_PASS; prefer env over CLI to avoid ps exposure)")
	flMetricsTLSCert       = flag.String("metrics-tls-cert", "", "Metrics: TLS certificate file (requires -metrics-tls-key)")
	flMetricsTLSKey        = flag.String("metrics-tls-key", "", "Metrics: TLS private key file (requires -metrics-tls-cert)")
	flMetricsAllowInsecure = flag.Bool("metrics-allow-insecure", false, "Metrics: allow Basic Auth over plaintext HTTP (otherwise requires TLS when auth is set)")
	flMetricsGzip          = flag.Bool("metrics-gzip", false, "Metrics: gzip-compress /metrics responses when the scraper offers it. Off by default: promhttp pools a gzip writer per CPU, and each holds ~0.7MB of flate state, so compression costs up to ~0.7MB x GOMAXPROCS of live heap - more than a small fleet's whole response. Enable it for many targets, where the response size matters.")
	flEchoSecret           = flag.String("echo-secret", "", "Wire: HMAC secret for UDP echo authentication (env LINK_PING_ECHO_SECRET; mitigates reflector spoof when set on both client and server)")
	flEchoSecretOld        = flag.String("echo-secret-old", "", "Wire: previous HMAC secret, still accepted by the SERVER during a zero-downtime rotation alongside -echo-secret (env LINK_PING_ECHO_SECRET_OLD; server side only)")
	flHMACCoverage         = flag.String("hmac-coverage", "full-frame", "Wire: which frame bytes the client's HMAC tag covers when -echo-secret is set: 'full-frame' (default: header plus the -payload bytes, so a tampered payload or a payload riding a captured tag no longer authenticates; needs -payload > 0 to differ) or 'header' (the 24-byte header only — the v0.7 layout, byte-identical wire output; the escape hatch for probing through a v0.7 echo server while using -payload). The server side accepts both coverages whenever it has -echo-secret, so upgrading to ≥ v0.8 clears the one broken pairing (v0.7 server + full-frame client = payload probes read as loss).")
)

// flagWasSet reports whether the named flag was explicitly set on the
// command line (or via flag.Set). Use it instead of comparing a value against
// flag.Lookup(name).DefValue: a value comparison cannot distinguish "not set"
// from "explicitly set to the default". setFlagNames is the test seam because
// the process-wide FlagSet's "was set" bookkeeping cannot be undone.
func flagWasSet(name string) bool {
	for _, n := range setFlagNames() {
		if n == name {
			return true
		}
	}
	return false
}

// validateLogRotationFlags rejects rotation flags without -log-file. Under
// the SCM stdout is discarded, so a service installed with a rotation flag
// but no -log-file would rotate nothing and have no log at all; that is a
// startup error, not a warning. Explicitly passing a default value counts as
// "set": the operator asked for a rotation policy, not the default one.
func validateLogRotationFlags() error {
	if *flLogFile != "" {
		return nil
	}
	if flagWasSet("log-file-max-mb") || flagWasSet("log-file-max-backups") || flagWasSet("log-file-max-age") {
		return errors.New("log rotation flags require -log-file")
	}
	return nil
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
	if err := validateScavengeInterval(*flMemScavenge); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *flLogFile == "" {
		if err := validateLogRotationFlags(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	logW := io.Writer(os.Stdout)
	var logRepaired bool
	if *flLogFile != "" {
		// Enforce the 0600 invariant at the sink BEFORE either writer opens
		// the file: O_CREATE applies the mode only at creation, lumberjack
		// re-opens pre-existing files with no mode check and copies the live
		// file's mode onto every rotated artifact, and a symlink would
		// redirect topology-bearing lines into another local user's file.
		repaired, err := hardenLogSink(*flLogFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "harden log file %q: %v\n", *flLogFile, err)
			os.Exit(1)
		}
		logRepaired = repaired
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
			// File FIRST: io.MultiWriter stops at the first error, and under
			// the SCM the std handle can be invalid rather than a silent NUL
			// sink — stdout-first then silently swallows every line before
			// the file ever sees one, the exact total-log-loss the install
			// warning exists to prevent. Console-first was only ever cosmetic.
			logW = io.MultiWriter(f, os.Stdout)
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
			logW = io.MultiWriter(lj, os.Stdout)
		}
	}
	// Surface runtime sink failures (disk full, log dir removed): the
	// wrapper counts write errors and run()'s watcher reports them to the
	// event log / stderr. Wrapping once here covers both sink modes.
	var logSink *countedWriter
	if *flLogFile != "" {
		logSink = newCountedWriter(logW)
		logW = logSink
	}
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	if *flJSONLogs {
		slog.SetDefault(slog.New(slog.NewJSONHandler(logW, opts)))
	} else {
		slog.SetDefault(slog.New(slog.NewTextHandler(logW, opts)))
	}
	if logRepaired {
		// Land the repair notice in the log itself, so an operator whose
		// pre-created file was wide finds the evidence next to the logs it
		// would have leaked.
		slog.Warn("Log file had wider permissions; repaired to 0600", "path", *flLogFile)
	}

	// Only after hardenLogSink and slog.SetDefault: emitted before them, the
	// marker wrote through its own O_CREATE (which follows symlinks) into a
	// path hardenLogSink would refuse, and bypassed the configured handler.
	svcTraceMarker("main-post-logsetup")

	svcTraceMarker("main-pre-svc")
	if *flSvc != "" {
		handleService(*flSvc, logSink)
		return
	}

	// pi-lens-ignore: go-context-background-handler
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	prg := &program{
		ctx:     ctx,
		logSink: logSink,
	}
	if err := prg.run(); err != nil {
		slog.Error("Program exited with error", "err", err)
		os.Exit(1)
	}
}

// meshAllowFromTargets reports whether -allow-from-targets applies. The
// derived allowlist is a server control, so the flag needs the echo responder
// (server/both mode); in client mode it is ignored (warnIgnoredFlags says so)
// and no target is skipped. One spelling of the condition, used by both the
// config builder and the startup allowlist derivation so they cannot drift.
func (p *program) run() error {
	prober.InitMetrics()
	prober.BuildInfo.WithLabelValues(version).Set(1)
	slog.Info("starting", "version", version)

	// Fail fast on unknown mode BEFORE binding anything: a bad -mode
	// should never open ports or start servers.
	sf, err := checkStartupFlags()
	if err != nil {
		return err
	}
	echoSecret, echoSecretOld := sf.echoSecret, sf.echoSecretOld
	user, pass, cert, key := sf.metricsUser, sf.metricsPass, sf.metricsCert, sf.metricsKey
	if user != "" && cert == "" {
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

	// Log-durability watchers (see logsink.go / logacl_windows.go): sink
	// write failures surfaced outside the dead sink, and — Windows only —
	// a periodic idempotent re-apply of the restricted DACL, which a
	// lumberjack rotation silently regresses when the fresh live file
	// inherits a wide directory DACL. Both stop with p.ctx in every mode.
	watchLogSink(p.ctx, p.svc, p.logSink, sinkCheckInterval)
	startLogDACLRecheck(p.ctx, *flLogFile)

	// Live per-target state for the /status debug endpoint. Always
	// registered so server-only mode still serves an empty list.
	statusReg := prober.NewStatusRegistry()
	cfg.Status = statusReg
	// SIGHUP hot-reload of the targets file (Unix; Windows services use
	// -targets-reload-interval). Signals coalesce: every delivery just
	// re-reads and re-validates the file, which is idempotent.
	if *flTargets != "" {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGHUP)
		defer signal.Stop(sigCh)
		cfg.ReloadSignal = sigCh
	}

	// Resolve source for server metrics. buildConfig already validated it in
	// client/both mode (and set cfg.Source); server-only mode skips
	// buildConfig, so resolve and validate it here through the same helper.
	sourceForServer := cfg.Source
	if sourceForServer == "" {
		var err error
		sourceForServer, err = resolveSource()
		if err != nil {
			return err
		}
	}

	// Fail-closed client allowlist, resolved by the same helper -svc=install
	// validates against (see resolveAllowlist).
	allow, err := resolveAllowlist(*flMode, cfg)
	if err != nil {
		return err
	}

	// Bind the metrics listener before any probing starts so a bind
	// failure (port taken, permission denied) aborts startup instead of
	// leaving the agent running with no /metrics endpoint — a silent
	// partial failure for a monitoring agent.
	startMetrics := p.testServeMetrics
	if startMetrics == nil {
		startMetrics = func() (*http.Server, <-chan struct{}, error) {
			return p.startMetricsServer(*flMetrics, user, pass, cert, key, statusReg, *flMetricsGzip, *flMode)
		}
	}
	metricsSrv, metricsDone, err := startMetrics()
	if err != nil {
		return err
	}

	// echoSecret/echoSecretOld resolved at the top of run(): the rotation
	// guard must fire before any bind, not after the metrics server is up.
	mode := *flMode
	// runCtx: a mid-run metrics-serve failure must cancel the mode loops.
	// A monitor without a live /metrics endpoint is dead weight that looks
	// healthy — probes continue, the SCM/OS-level process is "running", and
	// nothing restarts until manual intervention. The serve goroutine runs
	// until Serve returns; any return other than deliberate Shutdown closes
	// metricsDone, which is fatal below.
	runCtx, runCancel := context.WithCancel(p.ctx)
	defer runCancel()
	modeDone := make(chan error, 1)
	go func() { modeDone <- runModes(runCtx, mode, cfg, sourceForServer, allow, echoSecret, echoSecretOld) }()
	var modeErr error
	select {
	case modeErr = <-modeDone:
	case <-metricsDone:
		// The serve goroutine returned before Shutdown: the listener or an
		// accept failed mid-run. Cancel the mode loops and fail the run so
		// the agent exits non-zero and service recovery can fire, instead of
		// probing without an endpoint for the remaining uptime.
		runCancel()
		<-modeDone
		modeErr = errors.New("metrics server terminated unexpectedly; monitor cannot serve metrics, status, or health endpoints")
	}
	// Drain the metrics server on the way out so an in-flight scrape
	// finishes instead of being cut off by process exit. On the
	// metricsDone path the server is already gone and Shutdown is a no-op;
	// on a normal mode exit it stops the listener and unblocks the select's
	// second case only if it had not fired yet.
	// pi-lens-ignore: go-context-background-handler
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// pi-lens-ignore: go-ignored-call-result
	_ = metricsSrv.Shutdown(shutCtx)
	// Bounded join: a scrape mid-write holds Serve open up to the 30s
	// WriteTimeout, which exceeds the service Stop deadline (20s) - waiting
	// unconditionally would make Stop report "timed out" while the process
	// was still draining a clean shutdown. The drain is best-effort (the
	// agent's own metrics die with the process), so after the Shutdown
	// deadline a short grace is all an in-flight scrape gets.
	select {
	case <-metricsDone:
	case <-time.After(shutdownJoinGrace):
		slog.Warn("metrics server drain grace exceeded; continuing exit", "grace", shutdownJoinGrace)
	}
	return modeErr
}

// runModes executes the selected probe/server mode until ctx is cancelled,
// returning its terminal error. Extracted from run() so the metrics-server
// death at the select above is comparable to (and can preempt) a mode exit.
func runModes(
	ctx context.Context,
	mode string,
	cfg prober.Config,
	sourceForServer string,
	allow *prober.Allowlist,
	echoSecret string,
	echoSecretOld string,
) error {
	switch mode {
	case "server":
		return prober.RunServer(ctx, *flListen, sourceForServer, allow, echoSecret, echoSecretOld)
	case "client":
		return prober.RunClient(ctx, cfg)
	case "both":
		// Local WaitGroup: Add is sequenced before the goroutine starts
		// and Wait runs in the same goroutine, so no Add/Wait race.
		modeCtx, modeCancel := context.WithCancel(ctx)
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
		clientErr := prober.RunClient(modeCtx, cfg)
		modeCancel()
		wg.Wait()
		if serverErr != nil {
			return serverErr
		}
		return clientErr
	default:
		return fmt.Errorf("unknown mode: %s", mode)
	}
}
