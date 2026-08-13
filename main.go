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
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"sync"
	"syscall"
	"time"

	"link_ping_prometheus/internal/prober"

	"github.com/kardianos/service"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// CLI flags.
var (
	flMode     = flag.String("mode", "server", "Mode: server, client, both")
	flListen   = flag.String("listen", ":4000", "Server: Listen address")
	flAllow    = flag.String("allow", "", "Server: Comma-separated client IP allowlist (fail-closed: required in server/both mode)")
	flTarget   = flag.String("target", "", "Client: Single target address")
	flTargets  = flag.String("targets", "", "Client: JSON file path with targets")
	flMetrics  = flag.String("metrics", ":2112", "Metrics: Listen address")
	flSvc      = flag.String("svc", "", "Service: install, uninstall, start, stop, run")
	flJSONLogs = flag.Bool("json-logs", false, "Log in JSON format")

	flAdaptive     = flag.Bool("adaptive", true, "Client: Use adaptive timeout based on link quality (RFC 6298)")
	flBaseInterval = flag.Duration("interval", 500*time.Millisecond, "Client: Probe interval")
	flBaseTimeout  = flag.Duration("timeout", 1*time.Second, "Client: Base/Initial timeout")
	flSource       = flag.String("source", "", "Source label applied to all metrics, e.g. local datacenter (sydney-dc)")

	flMetricsBasicAuthUser = flag.String("metrics-user", "", "Metrics: Basic auth username (empty disables auth; env LINK_PING_METRICS_USER)")
	flMetricsBasicAuthPass = flag.String("metrics-pass", "", "Metrics: Basic auth password (env LINK_PING_METRICS_PASS; prefer env over CLI to avoid ps exposure)")
	flMetricsTLSCert       = flag.String("metrics-tls-cert", "", "Metrics: TLS certificate file (requires -metrics-tls-key)")
	flMetricsTLSKey        = flag.String("metrics-tls-key", "", "Metrics: TLS private key file (requires -metrics-tls-cert)")
)

func main() {
	flag.Parse()
	// Bound the Go heap so long-running RSS stays flat even during
	// /metrics scrape or probe bursts. The standard GOMEMLIMIT env var
	// (with units) overrides this default. 64MB is ample for the largest
	// supported config (1000 targets) and keeps the agent lightweight.
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(64 << 20)
	}
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	if *flJSONLogs {
		slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, opts)))
	} else {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, opts)))
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
	return prober.Config{
		Source:       *flSource,
		Targets:      targets,
		Adaptive:     *flAdaptive,
		BaseInterval: *flBaseInterval,
		BaseTimeout:  *flBaseTimeout,
	}, nil
}

// resolveMetricsAuth combines the CLI flags with the LINK_PING_METRICS_USER /
// LINK_PING_METRICS_PASS environment variables (flags win). Username and
// password must be configured as a pair: user-only would otherwise enable
// auth with an empty password.
func resolveMetricsAuth() (string, string, error) {
	user, pass := *flMetricsBasicAuthUser, *flMetricsBasicAuthPass
	if user == "" {
		user = os.Getenv("LINK_PING_METRICS_USER")
	}
	if pass == "" {
		pass = os.Getenv("LINK_PING_METRICS_PASS")
	}
	if (user == "") != (pass == "") {
		return "", "", errors.New("metrics basic auth requires both username and password (-metrics-user/-metrics-pass or LINK_PING_METRICS_USER/LINK_PING_METRICS_PASS)")
	}
	return user, pass, nil
}

// handleService manages the Windows service lifecycle via the
// kardianos/service package. It reconstructs CLI arguments at install
// time, excluding -svc itself and sensitive flags (-metrics-user,
// -metrics-pass).
func handleService(action string) {
	svcConfig := &service.Config{
		Name:        "link_ping_prometheus",
		DisplayName: "Link Ping Prometheus",
		Description: "Monitoring agent for TCP Echo latency.",
		Arguments:   []string{},
	}

	if action == "install" {
		exePath, err := os.Executable()
		if err != nil {
			slog.Error("Failed to get executable path", "err", err)
			os.Exit(1)
		}
		var args []string
		// The two auth flags are stripped here (with -svc) so credentials
		// are never persisted into the service configuration; they must be
		// configured as a pair via LINK_PING_METRICS_USER/PASS.
		flag.Visit(func(f *flag.Flag) {
			if f.Name != "svc" && f.Name != "metrics-user" && f.Name != "metrics-pass" {
				args = append(args, fmt.Sprintf("-%s=%s", f.Name, f.Value.String()))
			}
		})
		args = append(args, "-svc=run")
		svcConfig.Arguments = args
		svcConfig.Executable = exePath

		if *flMetricsBasicAuthUser != "" || *flMetricsBasicAuthPass != "" {
			fmt.Println("WARNING: -metrics-user/-metrics-pass are NOT persisted into the service configuration.")
			fmt.Println("Configure LINK_PING_METRICS_USER/LINK_PING_METRICS_PASS in the service environment instead.")
		}
	}

	// pi-lens-ignore: go-context-background-handler
	prg := &program{ctx: context.Background()}

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
		slog.Error("Unknown action", "action", action)
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
	// pi-lens-ignore: go-context-background-handler
	p.ctx, p.cancel = context.WithCancel(context.Background())
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		if err := p.run(); err != nil {
			slog.Error("Service run error", "err", err)
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
	p.wg.Wait()
	return nil
}

// run initialises metrics, starts the Prometheus HTTP server, and
// dispatches to the selected mode (server, client, or both).
func (p *program) run() error {
	prober.InitMetrics()

	user, pass, err := resolveMetricsAuth()
	if err != nil {
		return err
	}
	cert, key := *flMetricsTLSCert, *flMetricsTLSKey
	if (cert == "") != (key == "") {
		return errors.New("-metrics-tls-cert and -metrics-tls-key must be set together")
	}
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

	// Fail-closed client allowlist: the echo responder refuses to run
	// without an explicit -allow list, so spoofed/unauthorised sources
	// can neither reflect datagrams nor grow metric label cardinality.
	allow, err := prober.ParseAllowlist(*flAllow)
	if err != nil {
		return err
	}
	if mode := *flMode; (mode == "server" || mode == "both") && len(allow) == 0 {
		return errors.New("server mode requires -allow (comma-separated client IP allowlist); fail-closed")
	}

	// Capture flag values before spawning the goroutine: it may outlive
	// flag mutation by tests or shutdown code.
	metricsAddr := *flMetrics
	go func() {
		mx := http.NewServeMux()
		mx.Handle("/metrics", prober.MetricsAuth(user, pass, promhttp.Handler()))
		slog.Info("Starting metrics server", "addr", metricsAddr, "tls", cert != "", "auth", user != "")
		srv := &http.Server{
			Addr:         metricsAddr,
			Handler:      mx,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  60 * time.Second,
		}

		go func() {
			<-p.ctx.Done()
			// pi-lens-ignore: go-context-background-handler
			shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			srv.Shutdown(shutCtx)
		}()

		var serveErr error
		if cert != "" {
			serveErr = srv.ListenAndServeTLS(cert, key)
		} else {
			serveErr = srv.ListenAndServe()
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			slog.Error("Metrics server error", "err", serveErr)
		}
	}()

	mode := *flMode
	switch mode {
	case "server":
		return prober.RunServer(p.ctx, *flListen, *flSource, allow)
	case "client":
		return prober.RunClient(p.ctx, cfg)
	case "both":
		// Local WaitGroup: Add is sequenced before the goroutine starts
		// and Wait runs in the same goroutine, so no Add/Wait race.
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := prober.RunServer(p.ctx, *flListen, *flSource, allow); err != nil {
				slog.Error("Server error", "err", err)
			}
		}()
		clientErr := prober.RunClient(p.ctx, cfg)
		wg.Wait()
		return clientErr
	default:
		return fmt.Errorf("unknown mode: %s", mode)
	}
}
