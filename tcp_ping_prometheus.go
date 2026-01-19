package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/kardianos/service"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// ==========================================
// Constants & Configuration
// ==========================================

const (
	payloadSize = 16 // 8 bytes seq + 8 bytes timestamp
	// Default adaptive constants (RFC 6298 inspired)
	defaultAlpha  = 0.125
	defaultBeta   = 0.25
	defaultMinRTO = 100 * time.Millisecond
	defaultMaxRTO = 3 * time.Second
)

var (
	// CLI Flags
	flMode     = flag.String("mode", "server", "Mode: server, client, both")
	flListen   = flag.String("listen", ":4000", "Server: Listen address")
	flTarget   = flag.String("target", "", "Client: Single target address")
	flTargets  = flag.String("targets", "", "Client: JSON file path with targets")
	flMetrics  = flag.String("metrics", ":2112", "Metrics: Listen address")
	flSvc      = flag.String("svc", "", "Service: install, uninstall, start, stop, run")
	flJSONLogs = flag.Bool("json-logs", false, "Log in JSON format")

	// Adaptive flags
	flAdaptive     = flag.Bool("adaptive", true, "Client: Use adaptive timeout/interval based on link quality")
	flBaseInterval = flag.Duration("interval", 500*time.Millisecond, "Client: Base probe interval (min interval if adaptive)")
	flBaseTimeout  = flag.Duration("timeout", 1*time.Second, "Client: Base/Initial timeout")
)

// ==========================================
// Metrics
// ==========================================

var (
	metricSent = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tcp_echo_sent_total",
		Help: "Total echo requests sent (attempts).",
	}, []string{"target", "address"})
	metricRecv = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tcp_echo_received_total",
		Help: "Total echo responses received.",
	}, []string{"target", "address"})
	metricTimeout = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tcp_echo_timeouts_total",
		Help: "Total echo requests that timed out.",
	}, []string{"target", "address"})
	metricDrop = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tcp_echo_dropped_total",
		Help: "Total connections dropped/failed.",
	}, []string{"target", "address"})
	metricRTT = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "tcp_echo_rtt_seconds",
		Help:    "Round-trip time in seconds.",
		Buckets: prometheus.ExponentialBuckets(0.0005, 2, 14), // 500us to ~8s
	}, []string{"target", "address"})
	metricLastRTT = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "tcp_echo_last_rtt_seconds",
		Help: "Most recent RTT in seconds.",
	}, []string{"target", "address"})
	metricUp = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "tcp_echo_connected",
		Help: "1 if currently connected, 0 otherwise.",
	}, []string{"target", "address"})
	// Estimate metrics
	metricRTO = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "tcp_echo_estimated_timeout_seconds",
		Help: "Current adaptive timeout (RTO) being used.",
	}, []string{"target", "address"})
)

var registerOnce sync.Once

func initMetrics() {
	registerOnce.Do(func() {
		prometheus.MustRegister(metricSent, metricRecv, metricTimeout, metricDrop, metricRTT, metricLastRTT, metricUp, metricRTO)
	})
}

// ==========================================
// Main Entry
// ==========================================

func main() {
	flag.Parse()
	setupLogger(*flJSONLogs)

	// If service command
	if *flSvc != "" {
		handleService(*flSvc)
		return
	}

	// Normal run
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

// ==========================================
// Service Wrappers
// ==========================================

func handleService(action string) {
	svcConfig := &service.Config{
		Name:        "tcp_ping_prometheus",
		DisplayName: "TCP Ping Prometheus",
		Description: "Monitoring agent for TCP Echo latency.",
		Arguments:   []string{}, // We'll reconstruct args during install
	}

	// Helper to reconstruct arguments for install.
	// Note: simplified. Production apps might copy os.Args or be smarter.
	if action == "install" {
		exePath, _ := os.Executable()
		// Reconstruct flags based on current execution
		var args []string
		flag.Visit(func(f *flag.Flag) {
			if f.Name != "svc" {
				args = append(args, fmt.Sprintf("-%s=%s", f.Name, f.Value.String()))
			}
		})
		args = append(args, "-svc=run")
		svcConfig.Arguments = args
		svcConfig.Executable = exePath
	}

	prg := &program{ctx: context.Background()} // Placeholder context, will be replaced in Start

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

// program implements service.Interface
type program struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func (p *program) Start(s service.Service) error {
	p.ctx, p.cancel = context.WithCancel(context.Background())
	go func() {
		if err := p.run(); err != nil {
			slog.Error("Service run error", "err", err)
		}
	}()
	return nil
}

func (p *program) Stop(s service.Service) error {
	if p.cancel != nil {
		p.cancel()
	}
	p.wg.Wait()
	return nil
}

func (p *program) run() error {
	initMetrics()

	// Start Metrics Server
	go func() {
		mx := http.NewServeMux()
		mx.Handle("/metrics", promhttp.Handler())
		slog.Info("Starting metrics server", "addr", *flMetrics)
		srv := &http.Server{Addr: *flMetrics, Handler: mx}

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
		return runServer(p.ctx, *flListen)
	case "client":
		return runClient(p.ctx)
	case "both":
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			runServer(p.ctx, *flListen)
		}()
		return runClient(p.ctx)
	default:
		return fmt.Errorf("unknown mode: %s", mode)
	}
}

// ==========================================
// Server Logic
// ==========================================

func runServer(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	slog.Info("Echo server listening", "addr", addr)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil // shutdown
			}
			slog.Warn("Accept error", "err", err)
			continue
		}

		go handleServerConn(ctx, conn)
	}
}

func handleServerConn(ctx context.Context, c net.Conn) {
	defer c.Close()
	// Optionally set keepalive
	if tcp, ok := c.(*net.TCPConn); ok {
		tcp.SetKeepAlive(true)
		tcp.SetKeepAlivePeriod(30 * time.Second)
	}

	buf := make([]byte, payloadSize)
	for {
		// Set a reasonable read deadline to invoke cleanup of dead idle connections
		c.SetReadDeadline(time.Now().Add(60 * time.Second))

		if _, err := io.ReadFull(c, buf); err != nil {
			// Normal EOF or timeout
			return
		}

		// Echo back immediately
		c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write(buf); err != nil {
			return
		}
	}
}

// ==========================================
// Client Logic
// ==========================================

type Target struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

func runClient(ctx context.Context) error {
	var targets []Target
	var err error

	// Load targets
	if *flTargets != "" {
		targets, err = loadTargets(*flTargets)
		if err != nil {
			return err
		}
	} else if *flTarget != "" {
		targets = []Target{{Name: "default", Address: *flTarget}}
	} else {
		return errors.New("no targets specified (use -target or -targets)")
	}

	return startProbing(ctx, targets)
}

func loadTargets(path string) ([]Target, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read targets file: %w", err)
	}
	var targets []Target
	if err := json.Unmarshal(data, &targets); err != nil {
		return nil, fmt.Errorf("parse targets json: %w", err)
	}
	return targets, nil
}

func startProbing(ctx context.Context, targets []Target) error {
	slog.Info("Starting probing", "targets_count", len(targets), "adaptive", *flAdaptive)

	var wg sync.WaitGroup
	for _, t := range targets {
		wg.Add(1)
		go func(tg Target) {
			defer wg.Done()
			probeTarget(ctx, tg)
		}(t)
	}
	wg.Wait()
	return nil
}

type AdaptiveStats struct {
	srtt   float64 // smoothed RTT in seconds
	rttvar float64 // RTT variation in seconds
	rto    float64 // Retransmission Timeout (current timeout)
}

func newAdaptiveStats() *AdaptiveStats {
	// Initialize with defaults
	return &AdaptiveStats{
		srtt:   0.0,
		rttvar: 0.0,
		rto:    (*flBaseTimeout).Seconds(),
	}
}

// update calculates new RTO using RFC 6298 logic
func (a *AdaptiveStats) update(rttSeconds float64) {
	if a.srtt == 0 {
		// First measurement
		a.srtt = rttSeconds
		a.rttvar = rttSeconds / 2
	} else {
		// RTTVAR = (1 - beta) * RTTVAR + beta * |SRTT - R|
		a.rttvar = (1-defaultBeta)*a.rttvar + defaultBeta*math.Abs(a.srtt-rttSeconds)
		// SRTT = (1 - alpha) * SRTT + alpha * R
		a.srtt = (1-defaultAlpha)*a.srtt + defaultAlpha*rttSeconds
	}
	// RTO = SRTT + 4 * RTTVAR
	a.rto = a.srtt + 4*a.rttvar
}

func (a *AdaptiveStats) currentRTO() time.Duration {
	// Clamp RTO
	val := a.rto
	min := defaultMinRTO.Seconds()
	max := defaultMaxRTO.Seconds()

	if val < min {
		val = min
	}
	if val > max {
		val = max
	}
	return time.Duration(val * float64(time.Second))
}

func probeTarget(ctx context.Context, t Target) {
	logger := slog.With("target", t.Name, "address", t.Address)

	// Recover from panics to keep other probes alive
	defer func() {
		if r := recover(); r != nil {
			logger.Error("Panic in probe loop", "panic", r)
		}
	}()

	adaptive := newAdaptiveStats()

	// Helper to get timeout
	getTimeout := func() time.Duration {
		if *flAdaptive {
			return adaptive.currentRTO()
		}
		return *flBaseTimeout
	}

	// Helper to get interval
	getInterval := func() time.Duration {
		if *flAdaptive {
			// Interval is max(base, 1.5 * RTO) to prevent saturation if link is extremely slow
			// But usually interval > RTT is enough.
			// Let's stick to BaseInterval unless RTO is huge?
			// The user said "auto interval based on link".
			// A simple logic: Interval should be >= Timeout to avoid pileup
			rto := adaptive.currentRTO()
			if *flBaseInterval < rto {
				return rto
			}
			return *flBaseInterval
		}
		return *flBaseInterval
	}

	// Connection loop
	for {
		if ctx.Err() != nil {
			return
		}

		conn, err := net.DialTimeout("tcp", t.Address, 5*time.Second)
		if err != nil {
			metricDrop.WithLabelValues(t.Name, t.Address).Inc()
			// Treat connection failure as a lost packet for "packet loss" calculations
			metricTimeout.WithLabelValues(t.Name, t.Address).Inc()
			metricSent.WithLabelValues(t.Name, t.Address).Inc()
			metricUp.WithLabelValues(t.Name, t.Address).Set(0)

			// Backoff on connection failure
			logger.Warn("Connect failed", "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second): // Fixed connect retry backoff
				continue
			}
		}

		logger.Info("Connected")
		metricUp.WithLabelValues(t.Name, t.Address).Set(1)

		if tcp, ok := conn.(*net.TCPConn); ok {
			tcp.SetNoDelay(true)
		}

		// Probe Loop
		err = runEchoLoop(ctx, conn, t, adaptive, getTimeout, getInterval, logger)
		conn.Close()
		metricUp.WithLabelValues(t.Name, t.Address).Set(0)

		if err != nil {
			logger.Warn("Connection lost", "err", err)
		}

		// Wait a bit before reconnecting if not canceled
		select {
		case <-ctx.Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func runEchoLoop(
	ctx context.Context,
	conn net.Conn,
	t Target,
	stats *AdaptiveStats,
	getTimeout func() time.Duration,
	getInterval func() time.Duration,
	logger *slog.Logger,
) error {

	// Channels for coordinating the reader goroutine
	type response struct {
		seq  uint64
		recv time.Time
	}

	// 100 buffered to handle bursts/jitter without blocking reader
	respCh := make(chan response, 100)
	errCh := make(chan error, 1)

	// Ensure we shut down reader
	readerCtx, cancelReader := context.WithCancel(ctx)
	defer cancelReader()

	// Start Reader
	go func() {
		defer close(errCh)
		buf := make([]byte, payloadSize)
		for {
			if readerCtx.Err() != nil {
				return
			}
			// Important: Reader needs a deadline too, otherwise it hangs forever on broken link
			// We update this deadline based on expected activity?
			// Actually, just set a loose deadline relative to MAX timeout + Buffer
			// Or update it per ping? Updating per ping is safer.
			// But we don't know the timeout here easily without locking.
			// We'll trust the writer loop to kill the specific connection if it times out
			// Here we just wait. If writer closes conn, we error.

			// We can set a deadline of "Forever" -> relying on conn.Close(),
			// OR we set a deadline of e.g. 10s and loop.
			conn.SetReadDeadline(time.Now().Add(10 * time.Second))

			_, err := io.ReadFull(conn, buf)
			if err != nil {
				// If error, send to errCh.
				// Do not close errCh here, let defer handle it, but we need to ensure main loop sees it.
				// Actually proper pattern: send err, then return.
				// Filter timeout errors if we just haven't received anything but link might be idle?
				// But we are pinging constantly.
				// If we timeout here, it means we haven't received ANY data for 10s.
				if errors.Is(err, os.ErrDeadlineExceeded) {
					// Check if we should actually be receiving?
					// For now, treat as error to force reconnect
				}
				select {
				case errCh <- err:
				case <-readerCtx.Done():
				}
				return
			}

			seq := binary.LittleEndian.Uint64(buf[0:8])
			// logger.Info("Debug: Reader received", "seq", seq)

			select {
			case respCh <- response{seq: seq, recv: time.Now()}:
			case <-readerCtx.Done():
				return
			}
		}
	}()

	seq := uint64(0)
	buf := make([]byte, payloadSize)

	// Map of pending requests: seq -> sendTime
	pending := make(map[uint64]time.Time)

	// Ensure any pending packets at exit are counted as timeouts
	defer func() {
		count := float64(len(pending))
		if count > 0 {
			// logger.Info("Cleaning up pending packets as timeouts", "count", count)
			metricTimeout.WithLabelValues(t.Name, t.Address).Add(count)
		}
	}()

	for {
		interval := getInterval()
		timeout := getTimeout()

		metricRTO.WithLabelValues(t.Name, t.Address).Set(timeout.Seconds())

		// TICKER: wait for next interval
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err, ok := <-errCh:
			if !ok {
				return errors.New("reader closed unexpectedly")
			}
			return err
		case <-time.After(interval):
			// Proceed to send
		}

		// 1. Read Responses (non-blocking drain)
	Drain:
		for {
			select {
			case resp := <-respCh:
				sentTime, ok := pending[resp.seq]
				if ok {
					rtt := resp.recv.Sub(sentTime)
					delete(pending, resp.seq)

					rttSec := rtt.Seconds()
					// logger.Info("Debug: Recv matched", "seq", resp.seq, "rtt", rttSec)

					metricRecv.WithLabelValues(t.Name, t.Address).Inc()
					metricRTT.WithLabelValues(t.Name, t.Address).Observe(rttSec)
					metricLastRTT.WithLabelValues(t.Name, t.Address).Set(rttSec)

					// Update adaptive stats
					if *flAdaptive {
						stats.update(rttSec)
					}
				} else {
					// logger.Info("Debug: Recv unmatched (duplicate or timed out)", "seq", resp.seq)
				}
			default:
				break Drain
			}
		}

		// 2. Check for Timeouts in pending
		now := time.Now()
		for s, sentTime := range pending {
			if now.Sub(sentTime) > timeout {
				// logger.Info("Debug: Timeout", "seq", s, "elapsed", now.Sub(sentTime))
				metricTimeout.WithLabelValues(t.Name, t.Address).Inc()
				delete(pending, s)
				// Note: We don't necessarily kill the connection on a single packet loss,
				// but TCP will handle retransmissions.
				// The higher level logic deems this a "timeout" for metrics.
			}
		}

		// 3. Send Ping
		seq++
		binary.LittleEndian.PutUint64(buf[0:8], seq)
		binary.LittleEndian.PutUint64(buf[8:16], uint64(now.UnixNano()))

		// logger.Info("Debug: Sending", "seq", seq)
		conn.SetWriteDeadline(now.Add(timeout))
		if _, err := conn.Write(buf); err != nil {
			return err // reconnect on write failure
		}

		pending[seq] = now
		metricSent.WithLabelValues(t.Name, t.Address).Inc()
	}
}

// ==========================================
// Logging Setup
// ==========================================

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
