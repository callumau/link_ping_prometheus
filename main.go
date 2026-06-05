// Command tcp_ping_prometheus is a TCP echo probing agent that exposes
// Prometheus metrics for latency, packet loss, and jitter.
//
// It operates in three modes:
//   - server: runs a TCP echo responder that validates a magic header.
//   - client: dials targets and sends periodic probes, recording RTT.
//   - both: runs server and client simultaneously.
//
// Adaptive RTO (RFC 6298) adjusts timeouts based on measured link
// quality when -adaptive is enabled (default).
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"tcp_ping_prometheus/internal/prober"

	"github.com/kardianos/service"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// CLI flags.
var (
	flMode     = flag.String("mode", "server", "Mode: server, client, both")
	flListen   = flag.String("listen", ":4000", "Server: Listen address")
	flTarget   = flag.String("target", "", "Client: Single target address")
	flTargets  = flag.String("targets", "", "Client: JSON file path with targets")
	flMetrics  = flag.String("metrics", ":2112", "Metrics: Listen address")
	flSvc      = flag.String("svc", "", "Service: install, uninstall, start, stop, run")
	flJSONLogs = flag.Bool("json-logs", false, "Log in JSON format")

	flAdaptive     = flag.Bool("adaptive", true, "Client: Use adaptive timeout/interval based on link quality")
	flBaseInterval = flag.Duration("interval", 500*time.Millisecond, "Client: Base probe interval (min interval if adaptive)")
	flBaseTimeout  = flag.Duration("timeout", 1*time.Second, "Client: Base/Initial timeout")

	flMetricsBasicAuthUser = flag.String("metrics-user", "", "Metrics: Basic auth username (empty disables auth)")
	flMetricsBasicAuthPass = flag.String("metrics-pass", "", "Metrics: Basic auth password")

	// sensitiveFlags prevents secrets from being persisted in the service
	// configuration during install.
	sensitiveFlags = map[string]bool{
		"metrics-pass": true,
	}
)

func main() {
	flag.Parse()
	setupLogger(*flJSONLogs)

	if *flSvc != "" {
		handleService(*flSvc)
		return
	}

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

// setupLogger configures the default slog logger with text or JSON output.
func setupLogger(jsonFormat bool) {
	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}
	var handler slog.Handler
	if jsonFormat {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}
	slog.SetDefault(slog.New(handler))
}

// buildConfig resolves CLI flags into a prober.Config. It handles single
// (-target) and multi-target (-targets) modes. On failure it logs and exits.
func buildConfig() prober.Config {
	var targets []prober.Target
	if *flTargets != "" {
		var err error
		targets, err = prober.LoadTargets(*flTargets)
		if err != nil {
			slog.Error("Failed to load targets", "err", err)
			os.Exit(1)
		}
	} else if *flTarget != "" {
		if err := prober.ValidateTarget(*flTarget); err != nil {
			slog.Error("Invalid target", "err", err)
			os.Exit(1)
		}
		targets = []prober.Target{{Name: "default", Address: *flTarget}}
	}
	return prober.Config{
		Targets:      targets,
		Adaptive:     *flAdaptive,
		BaseInterval: *flBaseInterval,
		BaseTimeout:  *flBaseTimeout,
	}
}

// handleService manages the Windows service lifecycle via the
// kardianos/service package. It reconstructs CLI arguments at install
// time, excluding -svc itself and sensitive flags (-metrics-pass).
func handleService(action string) {
	svcConfig := &service.Config{
		Name:        "tcp_ping_prometheus",
		DisplayName: "TCP Ping Prometheus",
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
		flag.Visit(func(f *flag.Flag) {
			if f.Name != "svc" && !sensitiveFlags[f.Name] {
				args = append(args, fmt.Sprintf("-%s=%s", f.Name, f.Value.String()))
			}
		})
		args = append(args, "-svc=run")
		svcConfig.Arguments = args
		svcConfig.Executable = exePath
	}

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
func (p *program) Start(s service.Service) error {
	p.ctx, p.cancel = context.WithCancel(context.Background())
	go func() {
		if err := p.run(); err != nil {
			slog.Error("Service run error", "err", err)
		}
	}()
	return nil
}

// Stop is called by the service framework to shut down gracefully.
// It cancels the context and waits for all goroutines to finish.
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

	go func() {
		mx := http.NewServeMux()
		mx.Handle("/metrics", prober.MetricsAuth(*flMetricsBasicAuthUser, *flMetricsBasicAuthPass, promhttp.Handler()))
		slog.Info("Starting metrics server", "addr", *flMetrics)
		srv := &http.Server{
			Addr:         *flMetrics,
			Handler:      mx,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  60 * time.Second,
		}

		go func() {
			<-p.ctx.Done()
			srv.Shutdown(context.Background())
		}()

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Metrics server error", "err", err)
		}
	}()

	mode := *flMode
	switch mode {
	case "server":
		return prober.RunServer(p.ctx, *flListen)
	case "client":
		cfg := buildConfig()
		return prober.RunClient(p.ctx, cfg)
	case "both":
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			if err := prober.RunServer(p.ctx, *flListen); err != nil {
				slog.Error("Server error", "err", err)
			}
		}()
		cfg := buildConfig()
		clientErr := prober.RunClient(p.ctx, cfg)
		p.wg.Wait()
		return clientErr
	default:
		return fmt.Errorf("unknown mode: %s", mode)
	}
}
