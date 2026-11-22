package service

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	"link_ping_prometheus/internal/config"
	"link_ping_prometheus/internal/httpserver"
	"link_ping_prometheus/internal/logging"
	"link_ping_prometheus/internal/prober"
)

// serviceInstallSpec is the OS-neutral shape of the service hardening
// (portable so TestServiceConfigHardening pins it directly): nothing else
// declares SCM behavior anywhere in the binary.
type serviceInstallSpec struct {
	Name                string
	DisplayName         string
	Description         string
	Dependencies        []string
	DelayedAutoStart    bool
	RecoveryDelay       time.Duration
	RecoveryResetPeriod uint32
}

func serviceSpec() serviceInstallSpec {
	return serviceInstallSpec{
		Name:        "link_ping_prometheus",
		DisplayName: "Link Ping Prometheus",
		Description: "UDP echo link monitor: Prometheus latency, packet loss, and jitter metrics",
		Dependencies: []string{
			"Tcpip",
			"W32Time",
		},
		DelayedAutoStart:    true,
		RecoveryDelay:       5 * time.Second,
		RecoveryResetPeriod: 86400,
	}
}

// absolutizeFlagValue returns the value to persist for a flag at service
// install time. Only the path flags are rewritten to absolute paths: the SCM
// starts the service with an unrelated working directory, so a relative path
// would resolve somewhere else at run time. Every other flag — notably the
// integer log-rotation flags log-file-max-mb/-backups/-age — is returned
// verbatim: absolutizing a bare number produced "C:\cwd\50", which made the
// service exit 2 at flag.Parse with stderr discarded under the SCM, i.e. an
// invisible crash loop.
func absolutizeFlagValue(name, value string) string {
	switch name {
	case "targets", "metrics-tls-cert", "metrics-tls-key", "log-file":
	default:
		return value
	}
	if value == "" || filepath.IsAbs(value) {
		return value
	}
	abs, err := filepath.Abs(value)
	if err != nil {
		// Unresolvable working directory: keep the value as given rather
		// than dropping the flag entirely.
		return value
	}
	return abs
}

// installServiceArgs validates the configuration -svc=install is about to
// freeze into the SCM command line, then returns that command line. Validation
// is not optional here: the flags are persisted and replayed on every service
// start, so a config Run() refuses — the DEFAULT -mode=server with no -allow,
// say — installs "successfully" and then exits 1 on every start, which the SCM
// OnFailure ladder turns into a restart every 5 seconds forever, with no log at
// all when -log-file is unset. The checks are Run()'s own, through the same
// helpers, so install and run cannot drift.
func installServiceArgs() ([]string, error) {
	// Both results are validation-only here; Run() consumes the values.
	if _, err := config.CheckStartupFlags(); err != nil {
		return nil, err
	}
	mode := *config.Default.Mode
	var cfg prober.Config
	if mode != "server" {
		var err error
		if cfg, err = config.BuildProberConfig(); err != nil {
			return nil, err
		}
	}
	// BuildProberConfig validates the resolved source in client/both mode;
	// server mode never calls it, so validate the flag here too. -svc=install
	// -mode=server -source="Sydney DC" used to install and then exit 1 on
	// every SCM start. Validate it here whatever the mode.
	if cfg.Source == "" {
		if _, err := config.ResolveSource(); err != nil {
			return nil, err
		}
	}
	// The bind addresses are the same crash loop when malformed (the persisted
	// flag can never bind), so resolve them here too. Resolution only — a bind
	// failure is the runtime's business.
	if _, err := net.ResolveTCPAddr("tcp", *config.Default.Metrics); err != nil {
		return nil, fmt.Errorf("invalid -metrics address: %w", err)
	}
	if mode == "server" || mode == "both" {
		if _, err := net.ResolveUDPAddr("udp", *config.Default.Listen); err != nil {
			return nil, fmt.Errorf("invalid -listen address: %w", err)
		}
	}
	if _, err := config.ResolveAllowlist(mode, cfg); err != nil {
		return nil, err
	}
	if *config.Default.Targets != "" && *config.Default.TargetsReload == 0 {
		// A Windows service has no SIGHUP, and -targets-reload-interval is the
		// only other reload trigger: without it the targets file is read once at
		// start and never again for the life of the process, so a peer edit
		// stays invisible until someone restarts the service.
		fmt.Println("WARNING: -targets is set but -targets-reload-interval is 0; a Windows service has no SIGHUP, so the targets file is read once at start and never re-read for the life of the process. Pass -targets-reload-interval (e.g. 1m) to pick up changes.")
	}
	// Build the SCM command line from the live flags at install time,
	// excluding -svc itself and the credential flags (-metrics-
	// user/-metrics-pass/-echo-secret/-echo-secret-old so credentials
	// are never persisted; they are delivered via env vars).
	var args []string
	flag.Visit(func(f *flag.Flag) {
		if f.Name != "svc" && f.Name != "metrics-user" && f.Name != "metrics-pass" && f.Name != "echo-secret" && f.Name != "echo-secret-old" {
			v := absolutizeFlagValue(f.Name, f.Value.String())
			args = append(args, fmt.Sprintf("-%s=%s", f.Name, v))
		}
	})
	args = append(args, "-svc=run")
	return args, nil
}

// runServiceInstall validates the persisted configuration and hands the
// validated argument array to install. Kept as one function so the array
// installServiceArgs validated and the array the platform installs cannot
// diverge, and so the flow is testable without Windows.
func runServiceInstall(install func([]string) error) error {
	args, err := installServiceArgs()
	if err != nil {
		return fmt.Errorf("service install refused: the persisted configuration would fail at startup: %w", err)
	}
	if err := install(args); err != nil {
		return fmt.Errorf("service install failed: %w", err)
	}
	return nil
}

// installServiceHook is the platform install seam. Production installs go
// through platformInstallService; tests substitute a stub to assert that the
// array installServiceArgs validated is the array handed to the platform.
// This exists because the two once drifted: platformInstallService received
// argv and silently dropped it, so every Windows service was registered with
// a bare ImagePath and could never start.
var installServiceHook = platformInstallService

// Handle manages the service lifecycle. Install/uninstall are
// Windows-only (gated by svcActionSupported: Linux deploys use the static
// systemd unit via the Ansible play, and the Linux renderers flagged by
// supply-chain scanners are thereby unreachable). start/stop are
// cross-platform conveniences around native service control. The service
// run mode follows the windows_exporter pattern: x/sys/windows/svc under
// the SCM, plain signal-driven foreground everywhere else.
func Handle(action, version string, logSink *logging.CountedWriter) {
	if !svcActionSupported(action) {
		slog.Error("unsupported -svc action on this OS: install/uninstall are Windows-only (Linux deploys use the systemd unit in installer/linux)", "action", action, "os", runtime.GOOS)
		os.Exit(1)
	}

	prg := NewProgram(version, logSink)

	switch action {
	case "install":
		// Validate first: nothing below may reach the SCM for a config the
		// runtime will refuse on every start (see installServiceArgs).
		// runServiceInstall passes the SAME array it validated to the
		// platform hook; the two once diverged (the hook received argv and
		// dropped it), which registered every Windows service with a bare
		// ImagePath.
		if err := runServiceInstall(installServiceHook); err != nil {
			slog.Error("Service install failed", "err", err)
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
		if *config.Default.MetricsBasicAuthUser != "" || *config.Default.MetricsBasicAuthPass != "" {
			fmt.Println("WARNING: -metrics-user/-metrics-pass are NOT persisted into the service configuration.")
			fmt.Println("Configure LINK_PING_METRICS_USER/LINK_PING_METRICS_PASS in the service environment instead.")
		}
		if *config.Default.EchoSecret != "" {
			fmt.Println("WARNING: -echo-secret is NOT persisted into the service configuration.")
			fmt.Println("Configure LINK_PING_ECHO_SECRET in the service environment instead.")
		}
		if *config.Default.EchoSecretOld != "" {
			fmt.Println("WARNING: -echo-secret-old is NOT persisted into the service config.")
			fmt.Println("Configure LINK_PING_ECHO_SECRET_OLD in the service environment instead.")
		}
		if *config.Default.LogFile == "" {
			// stdout is discarded under the service: without -log-file every
			// slog line vanishes and a crash can be completely invisible.
			fmt.Println("WARNING: -log-file is not set; under the service stdout is discarded so NO logs will be captured anywhere.")
			fmt.Println("Pass -log-file=<path> at install time (lifecycle events still reach the Windows event log).")
		}
		fmt.Println("Service installed.")
	case "uninstall":
		if err := platformUninstallService(); err != nil {
			slog.Error("Service uninstall failed", "err", err)
			os.Exit(1)
		}
		fmt.Println("Service uninstalled.")
	case "start":
		if err := platformStartService(); err != nil {
			slog.Error("Service start failed", "err", err)
			os.Exit(1)
		}
		fmt.Println("Service started.")
	case "stop":
		if err := platformStopService(); err != nil {
			slog.Error("Service stop failed", "err", err)
			os.Exit(1)
		}
		fmt.Println("Service stopped.")
	case "run":
		// The exit contract matters more than the return value: a run
		// error must leave the process unclean (non-zero) so the SCM
		// restart ladder fires - never a clean "handled" exit.
		if err := platformRunService(prg); err != nil {
			slog.Error("Service run error", "err", err)
			os.Exit(1)
		}
	default:
		// A typo like -svc=instal must not exit 0: the operator would
		// read that as "installed" and get no service and no error.
		slog.Error("Unknown action", "action", action)
		os.Exit(1)
	}
}

// Program implements the service lifecycle for Windows SCM and foreground runs.
type Program struct {
	version string
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	// svc is the lifecycle-event logger Start() received (nil for
	// anonymous foreground runs); the sink watcher writes log-sink
	// failures there so they reach the Windows event log even when the
	// log file itself is dead.
	svc logging.EventlogSink
	// logSink wraps the -log-file writer (nil without -log-file) so
	// runtime write failures become visible; see internal/logging/sink.go.
	logSink *logging.CountedWriter
	// testServeMetrics, when set (tests only), replaces httpserver.Start
	// in Run(): the test owns the *http.Server handle so it can kill the
	// listener mid-run and observe the fatal path deterministically.
	// Production leaves it nil; nil selects the real binder.
	testServeMetrics func() (*http.Server, <-chan struct{}, error)
}

// NewProgram constructs a Program for the given build version and optional
// counted log sink.
func NewProgram(version string, logSink *logging.CountedWriter) *Program {
	return &Program{
		version: version,
		logSink: logSink,
	}
}

// RunForeground drives the plain signal-handling foreground run shared by
// main() and the non-SCM -svc=run paths (Windows console debugging and
// systemd/launchd on unix, which manage the process themselves).
func (p *Program) RunForeground() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	p.ctx, p.cancel = ctx, cancel
	return p.Run()
}

// Run initializes metrics, starts the HTTP server, and dispatches to the selected mode.
func (p *Program) Run() error {
	ctx := p.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	prober.InitMetrics()
	prober.BuildInfo.WithLabelValues(p.version).Set(1)
	slog.Info("starting", "version", p.version)

	// Fail fast on unknown mode BEFORE binding anything: a bad -mode
	// should never open ports or start servers.
	sf, err := config.CheckStartupFlags()
	if err != nil {
		return err
	}
	echoSecret, echoSecretOld := sf.EchoSecret, sf.EchoSecretOld
	user, pass, cert, key := sf.MetricsUser, sf.MetricsPass, sf.MetricsCert, sf.MetricsKey
	if user != "" && cert == "" {
		slog.Warn("Metrics basic auth over plaintext HTTP: credentials are base64-only on the wire; consider -metrics-tls-cert/-metrics-tls-key")
	}

	var cfg prober.Config
	if *config.Default.Mode != "server" {
		var err error
		cfg, err = config.BuildProberConfig()
		if err != nil {
			return err
		}
	}
	// Periodic scavenger: shares ctx so it stops with the mode loops.
	startHeapScavenger(ctx, *config.Default.MemScavenge, minScavengeUnreleased, slog.Default())

	// Log-durability watchers: sink write failures surfaced outside the dead
	// sink, and — Windows only — a periodic idempotent re-apply of the
	// restricted DACL, which a rotation would otherwise regress when the fresh
	// live file inherits a wide directory DACL (the rotator applies it too; the
	// recheck covers a file created by another process). Both stop with ctx in
	// every mode.
	logging.WatchSink(ctx, p.svc, p.logSink, logging.SinkCheckInterval)
	logging.StartDACLRecheck(ctx, *config.Default.LogFile)

	// Live per-target state for the /status debug endpoint. Always
	// registered so server-only mode still serves an empty list.
	statusReg := prober.NewStatusRegistry()
	cfg.Status = statusReg
	// SIGHUP hot-reload of the targets file (Unix; Windows services use
	// -targets-reload-interval). Signals coalesce: every delivery just
	// re-reads and re-validates the file, which is idempotent.
	if *config.Default.Targets != "" {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGHUP)
		defer signal.Stop(sigCh)
		cfg.ReloadSignal = sigCh
	}

	// Resolve source for server metrics. BuildProberConfig already validated
	// it in client/both mode (and set cfg.Source); server-only mode skips
	// BuildProberConfig, so resolve and validate it here through the same
	// helper.
	sourceForServer := cfg.Source
	if sourceForServer == "" {
		var err error
		sourceForServer, err = config.ResolveSource()
		if err != nil {
			return err
		}
	}

	// Fail-closed client allowlist, resolved by the same helper -svc=install
	// validates against (see config.ResolveAllowlist).
	allow, err := config.ResolveAllowlist(*config.Default.Mode, cfg)
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
			return httpserver.Start(*config.Default.Metrics, user, pass, cert, key, statusReg, *config.Default.MetricsGzip, *config.Default.Mode)
		}
	}
	metricsSrv, metricsDone, err := startMetrics()
	if err != nil {
		return err
	}

	// echoSecret/echoSecretOld resolved at the top of Run(): the rotation
	// guard must fire before any bind, not after the metrics server is up.
	mode := *config.Default.Mode
	// runCtx: a mid-run metrics-serve failure must cancel the mode loops.
	// A monitor without a live /metrics endpoint is dead weight that looks
	// healthy — probes continue, the SCM/OS-level process is "running", and
	// nothing restarts until manual intervention. The serve goroutine runs
	// until Serve returns; any return other than deliberate Shutdown closes
	// metricsDone, which is fatal below.
	runCtx, runCancel := context.WithCancel(ctx)
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
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = metricsSrv.Shutdown(shutCtx)
	// Bounded join: a scrape mid-write holds Serve open up to the 30s
	// WriteTimeout, which exceeds the service Stop deadline (20s) - waiting
	// unconditionally would make Stop report "timed out" while the process
	// was still draining a clean shutdown. The drain is best-effort (the
	// agent's own metrics die with the process), so after the Shutdown
	// deadline a short grace is all an in-flight scrape gets.
	select {
	case <-metricsDone:
	case <-time.After(httpserver.ShutdownJoinGrace):
		slog.Warn("metrics server drain grace exceeded; continuing exit", "grace", httpserver.ShutdownJoinGrace)
	}
	return modeErr
}

// runModes executes the selected probe/server mode until ctx is cancelled,
// returning its terminal error. Extracted from Run() so the metrics-server
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
		return prober.RunServer(ctx, *config.Default.Listen, sourceForServer, allow, echoSecret, echoSecretOld)
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
			if err := prober.RunServer(modeCtx, *config.Default.Listen, sourceForServer, allow, echoSecret, echoSecretOld); err != nil {
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

// Start is called by the service framework to begin execution.
// The WaitGroup Add happens here — before the goroutine starts — so
// Stop can never race it (the framework calls Stop only after Start
// has returned).
func (p *Program) Start(sysLog logging.EventlogSink) error {
	p.svc = sysLog
	// Lifecycle events go to the system logger (Windows event log under
	// the SCM): the only channel a fleet operator sees without access to
	// -log-file. Best-effort — file logging stays the primary sink.
	if sysLog != nil {
		sysLog.Info(fmt.Sprintf("link_ping_prometheus service starting (version %s)", p.version))
	}
	p.ctx, p.cancel = context.WithCancel(context.Background())
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		if err := p.Run(); err != nil {
			slog.Error("Service run error", "err", err)
			if sysLog := p.svc; sysLog != nil {
				sysLog.Error(fmt.Sprintf("service run failed: %v", err))
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

// svcStopDeadline bounds Program.Stop's drain wait. A var so the
// timeout-arm test does not need a real 20s stall.
var svcStopDeadline = 20 * time.Second

// serviceName is the service identity across platforms (SCM name, the
// event-log source, and the unit/labelctl label the unix adapters call).
const serviceName = "link_ping_prometheus"

// svcActionSupported reports whether the -svc lifecycle action is
// supported on the current OS. install/uninstall are Windows-only: the
// Linux install path would run the binary's own service renderers
// (systemd/openrc/... unit and init-script generation), which no
// supported deployment exercises - Linux installs use the static systemd
// unit shipped via the Ansible play - and embedding configuration values
// into generated shell/unit scripts is exactly the surface
// supply-chain scanners flag on the OpenRC renderer (reachable only via
// this action). Every other action (run via the framework, start/stop
// helpers) stays cross-platform.
func svcActionSupported(action string) bool {
	switch action {
	case "install", "uninstall":
		return runtime.GOOS == "windows"
	default:
		return true
	}
}

// Stop is called by the service framework to shut down gracefully. It
// cancels the context and waits for the run goroutine (plus a bounded
// straggler drain), returning nil even when the drain deadline is
// exceeded so the SCM classifies an operator stop as clean.
func (p *Program) Stop(_ logging.EventlogSink) error {
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
	case <-time.After(svcStopDeadline):
		// Returning an error makes the SCM treat the stop as a failure and fire
		// the OnFailure restart ladder mid-maintenance. Classify operator stop as clean.
		slog.Error("Service stop deadline exceeded")
		return nil
	}
}

// TraceMarker records a service-path diagnostic (windows e2e triage aid
// under the SCM where stderr is dead). It emits through slog at Info: the
// handler is fixed at LevelInfo, so Debug markers were invisible in the
// service log the e2e dumps on failure. The configured handler still owns the
// format: the previous raw "svc-trace[...]" line written straight into
// -log-file broke -json-logs parsing (the file is then a mix of JSON records
// and bare text) on every foreground run too. Only the -svc paths emit at
// all; a plain foreground run has no service to trace. The marker text is
// what the Windows e2e triage reads out of the log, so keep the
// "svc-trace[...]" shape in the message.
func TraceMarker(tag string) {
	if *config.Default.Svc == "" {
		return
	}
	slog.Info(fmt.Sprintf("svc-trace[%s]", tag))
}
