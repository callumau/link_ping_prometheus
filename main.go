// Command link_ping_prometheus is a UDP echo probing agent that exposes
// Prometheus metrics for latency, packet loss, and jitter.
//
// It operates in three modes:
//   - server: runs a UDP echo responder that validates a magic header.
//   - client: sends periodic probes to targets, recording RTT and loss.
//   - both: runs server and client simultaneously.
//
// Adaptive RTO (RFC 6298) adjusts timeouts based on measured link
// quality when -adaptive is enabled (default). UDP has no
// retransmission, so the loss ratio is true network loss.
package main

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime/debug"

	"link_ping_prometheus/internal/config"
	"link_ping_prometheus/internal/logging"
	"link_ping_prometheus/internal/service"
)

// version is injected at link time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	flag.Parse()
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(128 << 20)
	}
	f := config.Default
	if *f.LogMaxSize < 0 || *f.LogMaxBackups < 0 || *f.LogMaxAge < 0 {
		fmt.Fprintln(os.Stderr, "log rotation flags must be >= 0")
		os.Exit(1)
	}
	if err := config.ValidateScavengeInterval(*f.MemScavenge); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := config.ValidateLogRotationFlags(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	logW := io.Writer(os.Stdout)
	var logRepaired bool
	var logSink *logging.CountedWriter
	if *f.LogFile != "" && (*f.Svc == "" || *f.Svc == "run") {
		var fileSink io.Writer
		if *f.LogMaxSize == 0 {
			file, _, repaired, err := logging.OpenFile(*f.LogFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "open log file %q: %v\n", *f.LogFile, err)
				os.Exit(1)
			}
			defer file.Close()
			logRepaired = repaired
			fileSink = file
		} else {
			rot, repaired, err := logging.NewRotatorChecked(*f.LogFile, *f.LogMaxSize, *f.LogMaxBackups, *f.LogMaxAge)
			if err != nil {
				fmt.Fprintf(os.Stderr, "open log file %q: %v\n", *f.LogFile, err)
				os.Exit(1)
			}
			defer rot.Close()
			logRepaired = repaired
			fileSink = rot
		}
		// Wrap only the file sink before MultiWriter (stdout may be invalid under SCM).
		logSink = logging.NewCountedWriter(fileSink)
		logW = io.MultiWriter(logSink, os.Stdout)
	}

	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	if *f.JSONLogs {
		slog.SetDefault(slog.New(slog.NewJSONHandler(logW, opts)))
	} else {
		slog.SetDefault(slog.New(slog.NewTextHandler(logW, opts)))
	}
	if logRepaired {
		slog.Warn("Log file had wider permissions; repaired to 0600", "path", *f.LogFile)
	}

	service.TraceMarker("main-post-logsetup")
	service.TraceMarker("main-pre-svc")
	if *f.Svc != "" {
		service.Handle(*f.Svc, version, logSink)
		return
	}

	if err := service.NewProgram(version, logSink).RunForeground(); err != nil {
		slog.Error("Program exited with error", "err", err)
		os.Exit(1)
	}
}
