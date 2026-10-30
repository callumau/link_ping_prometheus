package main

import (
	"context"
	"flag"
	"fmt"
	"link_ping_prometheus/internal/prober"
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

// foregroundRun drives the plain signal-handling foreground run shared by
// `main()` and the non-SCM -svc=run paths (Windows console debugging and
// systemd/launchd on unix, which manage the process themselves).
func foregroundRun(prg *program) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	prg.ctx, prg.cancel = ctx, cancel
	return prg.run()
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
// start, so a config run() refuses — the DEFAULT -mode=server with no -allow,
// say — installs "successfully" and then exits 1 on every start, which the SCM
// OnFailure ladder turns into a restart every 5 seconds forever, with no log at
// all when -log-file is unset. The checks are run()'s own, through the same
// helpers, so install and run cannot drift.
func installServiceArgs() ([]string, error) {
	// Both results are validation-only here; run() consumes the values.
	// pi-lens-ignore: go-ignored-call-result
	if _, err := checkStartupFlags(); err != nil {
		return nil, err
	}
	mode := *flMode
	var cfg prober.Config
	if mode != "server" {
		var err error
		if cfg, err = buildConfig(); err != nil {
			return nil, err
		}
	}
	// buildConfig validates the resolved source in client/both mode; server
	// mode never calls it, so validate the flag here too. -svc=install
	// -mode=server -source="Sydney DC" used to install and then exit 1 on
	// every SCM start. Validate it here whatever the mode.
	if cfg.Source == "" {
		if _, err := resolveSource(); err != nil {
			return nil, err
		}
	}
	// The bind addresses are the same crash loop when malformed (the persisted
	// flag can never bind), so resolve them here too. Resolution only — a bind
	// failure is the runtime's business.
	if _, err := net.ResolveTCPAddr("tcp", *flMetrics); err != nil {
		return nil, fmt.Errorf("invalid -metrics address: %w", err)
	}
	if mode == "server" || mode == "both" {
		if _, err := net.ResolveUDPAddr("udp", *flListen); err != nil {
			return nil, fmt.Errorf("invalid -listen address: %w", err)
		}
	}
	// pi-lens-ignore: go-ignored-call-result
	if _, err := resolveAllowlist(mode, cfg); err != nil {
		return nil, err
	}
	if *flTargets != "" && *flTargetsReload == 0 {
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

// handleService manages the service lifecycle. Install/uninstall are
// Windows-only (gated by svcActionSupported: Linux deploys use the static
// systemd unit via the Ansible play, and the Linux renderers flagged by
// supply-chain scanners are thereby unreachable). start/stop are
// cross-platform conveniences around native service control. The service
// run mode follows the windows_exporter pattern: x/sys/windows/svc under
// the SCM, plain signal-driven foreground everywhere else.
func handleService(action string, logSink *countedWriter) {
	if !svcActionSupported(action) {
		slog.Error("unsupported -svc action on this OS: install/uninstall are Windows-only (Linux deploys use the systemd unit in installer/linux)", "action", action, "os", runtime.GOOS)
		os.Exit(1)
	}

	prg := &program{logSink: logSink}

	switch action {
	case "install":
		// Validate first: nothing below may reach the SCM for a config the
		// runtime will refuse on every start (see installServiceArgs).
		args, err := installServiceArgs()
		if err != nil {
			slog.Error("Service install refused: the persisted configuration would fail at startup", "err", err)
			fmt.Fprintf(os.Stderr, "service install refused: %v\n", err)
			os.Exit(1)
		}
		if err := platformInstallService(args); err != nil {
			slog.Error("Service install failed", "err", err)
			os.Exit(1)
		}
		if *flMetricsBasicAuthUser != "" || *flMetricsBasicAuthPass != "" {
			fmt.Println("WARNING: -metrics-user/-metrics-pass are NOT persisted into the service configuration.")
			fmt.Println("Configure LINK_PING_METRICS_USER/LINK_PING_METRICS_PASS in the service environment instead.")
		}
		if *flEchoSecret != "" {
			fmt.Println("WARNING: -echo-secret is NOT persisted into the service configuration.")
			fmt.Println("Configure LINK_PING_ECHO_SECRET in the service environment instead.")
		}
		if *flEchoSecretOld != "" {
			fmt.Println("WARNING: -echo-secret-old is NOT persisted into the service config.")
			fmt.Println("Configure LINK_PING_ECHO_SECRET_OLD in the service environment instead.")
		}
		if *flLogFile == "" {
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

// program implements service.Interface for kardianos/service.
type program struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	// svc is the lifecycle-event logger Start() received (nil");
	// anonymous foreground runs); the sink watcher writes log-sink
	// failures there so they reach the Windows event log even when the
	// log file itself is dead.
	svc eventlogSink
	// logSink wraps the -log-file writer (nil without -log-file) so
	// runtime write failures become visible; see logsink.go.
	logSink *countedWriter
	// testServeMetrics, when set (tests only), replaces startMetricsServer
	// in run(): the test owns the *http.Server handle so it can kill the
	// listener mid-run and observe the fatal path deterministically.
	// Production leaves it nil; nil selects the real binder.
	testServeMetrics func() (*http.Server, <-chan struct{}, error)
}

// Start is called by the service framework to begin execution.
// The WaitGroup Add happens here — before the goroutine starts — so
// Stop can never race it (the framework calls Stop only after Start
// has returned).
func (p *program) Start(sysLog eventlogSink) error {
	p.svc = sysLog
	// Lifecycle events go to the system logger (Windows event log under
	// the SCM): the only channel a fleet operator sees without access to
	// -log-file. Best-effort — file logging stays the primary sink.
	if sysLog != nil {
		sysLog.Info(fmt.Sprintf("link_ping_prometheus service starting (version %s)", version))
	}
	// pi-lens-ignore: go-context-background-handler
	p.ctx, p.cancel = context.WithCancel(context.Background())
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		if err := p.run(); err != nil {
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

// svcStopDeadline bounds program.Stop's drain wait. A var so the
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
func (p *program) Stop(_ eventlogSink) error {
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
		// The drain missed the deadline, but this is an OPERATOR-requested
		// stop, not a crash: returning an error makes kardianos report
		// STOPPED with a service-specific exit code, which the SCM counts
		// as a FAILURE and answers with the OnFailure restart ladder — the
		// service the operator just stopped comes back up mid-maintenance.
		// The process exits either way; clean-stop classification is the
		// honest one. (The os.Exit(1) path in Start is the deliberate
		// opposite: a genuine run failure WANTS the restart to fire.)
		slog.Error("Service stop deadline exceeded")
		return nil
	}
}

// svcTraceMarker records a service-path diagnostic (windows e2e triage aid
// under the SCM where stderr is dead). It emits through slog at Info: the
// handler is fixed at LevelInfo, so Debug markers were invisible in the
// service log the e2e dumps on failure. The configured handler still owns the
// format: the previous raw "svc-trace[...]" line written straight into
// -log-file broke -json-logs parsing (the file is then a mix of JSON records
// and bare text) on every foreground run too. Only the -svc paths emit at
// all; a plain foreground run has no service to trace. The marker text is
// what the Windows e2e triage reads out of the log, so keep the
// "svc-trace[...]" shape in the message.
func svcTraceMarker(tag string) {
	if *flSvc == "" {
		return
	}
	slog.Info(fmt.Sprintf("svc-trace[%s]", tag))
}

// readyToProbe reports whether a running agent can actually do its job, i.e.
// /readyz's notion of readiness as opposed to /healthz's liveness.
// SocketAgeSeconds is nonzero only while the target currently holds a socket:
// the dial-retry path publishes 0 and a failed re-dial resets it, so this is
// "can probe right now", not "has ever probed". An agent stuck resolving DNS or
// blocked by a firewall is alive but useless, and an orchestrator must see that.
// Reads the registry in place (see StatusRegistry.AnyReady) rather than
