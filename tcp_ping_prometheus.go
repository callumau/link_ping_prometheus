package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/kardianos/service"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Wire format constants.
const (
	payloadSize = 16 // 8 bytes seq + 8 bytes timestamp
)

// Target represents a remote endpoint to probe.
type Target struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

var (
	// Prometheus metrics.
	sentCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tcp_echo_sent_total",
		Help: "Number of echo requests sent.",
	}, []string{"target"})
	recvCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tcp_echo_received_total",
		Help: "Number of echo responses received.",
	}, []string{"target"})
	timeoutCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tcp_echo_timeouts_total",
		Help: "Number of echo requests that timed out (treated as loss).",
	}, []string{"target"})
	connectsCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tcp_echo_connects_total",
		Help: "Number of TCP connect attempts (successful).",
	}, []string{"target"})
	connectedGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "tcp_echo_connected",
		Help: "1 if the client is currently connected to the server, else 0.",
	}, []string{"target"})
	upGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "tcp_echo_up",
		Help: "Exporter health indicator (1 = up).",
	})
	rttHistogram = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "tcp_echo_rtt_seconds",
		Help:    "Round-trip latency measured over the TCP echo path.",
		Buckets: prometheus.ExponentialBuckets(0.0001, 2, 15), // 100µs .. ~2s
	}, []string{"target"})
	lastRttGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "tcp_echo_last_rtt_seconds",
		Help: "Last observed RTT in seconds.",
	}, []string{"target"})
	lossPercentGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "tcp_echo_loss_percent",
		Help: "Echo loss percentage over the sliding window (timeouts considered loss).",
	}, []string{"target"})
)

func init() {
	prometheus.MustRegister(
		sentCounter,
		recvCounter,
		timeoutCounter,
		connectsCounter,
		connectedGauge,
		upGauge,
		rttHistogram,
		lastRttGauge,
		lossPercentGauge,
	)
	upGauge.Set(1)
}

// lossTracker maintains a circular buffer of recent probe outcomes to calculate loss percentage.
type lossTracker struct {
	mu     sync.Mutex
	buf    []bool // Circular buffer: true = success, false = failure.
	idx    int    // Current insertion index.
	filled bool   // Whether the buffer has been filled at least once.
	name   string // Target name for metrics.
}

func newLossTracker(size int, name string) *lossTracker {
	if size < 1 {
		size = 1
	}
	return &lossTracker{
		buf:  make([]bool, size),
		name: name,
	}
}

// record records the outcome of a probe and updates the loss percentage gauge.
func (lt *lossTracker) record(success bool) {
	lt.mu.Lock()
	defer lt.mu.Unlock()

	lt.buf[lt.idx] = success
	lt.idx = (lt.idx + 1) % len(lt.buf)
	if lt.idx == 0 {
		lt.filled = true
	}

	// Update gauge immediately.
	lossPercentGauge.WithLabelValues(lt.name).Set(lt.computeLossPercent())
}

// computeLossPercent returns the percentage of failures in the current window.
// It assumes the lock is held by the caller if called internally, but sticking to
// keeping the calculation simple within record or locking here.
// Since we call it from record which holds the lock, we'll inline the logic there or separate it.
// To satisfy the refactoring plan (simpler), we merge the logic or keep it as a helper.
func (lt *lossTracker) computeLossPercent() float64 {
	count := len(lt.buf)
	if !lt.filled {
		count = lt.idx
		if count == 0 {
			return 0
		}
	}

	failures := 0
	for i := 0; i < count; i++ {
		if !lt.buf[i] {
			failures++
		}
	}
	return 100.0 * float64(failures) / float64(count)
}

// loadTargets reads the target list from a JSON file.
func loadTargets(path string) ([]Target, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var targets []Target
	if err := json.Unmarshal(data, &targets); err != nil {
		return nil, err
	}
	return targets, nil
}

func main() {
	mode := flag.String("mode", "server", "server, client or both")
	listenAddr := flag.String("listen", ":4000", "TCP address to listen on (server)")
	targetAddr := flag.String("target", ":4000", "TCP address to connect to (client)")
	targetsFlag := flag.String("targets", "", "JSON file with list of targets (client)")
	metricsAddr := flag.String("metrics", ":2112", "HTTP address for Prometheus /metrics")
	interval := flag.Duration("interval", 200*time.Millisecond, "Client: probe interval")
	timeout := flag.Duration("timeout", 800*time.Millisecond, "Client: per-probe timeout (considered loss)")
	window := flag.Int("window", 100, "Client: sliding window size for loss percentage")
	svcAction := flag.String("svc", "", "service action: install | uninstall | start | stop | run")
	flag.Parse()

	// Initial target setup.
	var targets []Target
	if *targetsFlag != "" {
		var err error
		targets, err = loadTargets(*targetsFlag)
		if err != nil {
			log.Fatalf("Error loading targets: %v", err)
		}
	} else {
		targets = []Target{{Name: "default", Address: *targetAddr}}
	}

	// Service management instructions.
	if *svcAction != "" {
		runServiceAction(*svcAction, *mode, *listenAddr, *metricsAddr, *targetsFlag, *targetAddr, *interval, *timeout, *window, targets)
		return
	}

	// Standard run (foreground).
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := runApp(ctx, *mode, *listenAddr, targets, *metricsAddr, *interval, *timeout, *window); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatalf("Error: %v", err)
	}
}

// runServiceAction handles the service lifecycle actions (install, start, etc.).
func runServiceAction(action, mode, listenAddr, metricsAddr, targetsFlag, targetAddr string, interval, timeout time.Duration, window int, targets []Target) {
	svcConfig := &service.Config{
		Name:        "tcp_ping_prometheus",
		DisplayName: "TCP Ping Prometheus",
		Description: "TCP echo probe exporter with Prometheus metrics.",
	}

	if action == "install" {
		args := []string{
			"-svc", "run",
			"-mode", mode,
			"-listen", listenAddr,
			"-metrics", metricsAddr,
			"-interval", interval.String(),
			"-timeout", timeout.String(),
			"-window", strconv.Itoa(window),
		}
		if targetsFlag != "" {
			args = append(args, "-targets", targetsFlag)
		} else {
			args = append(args, "-target", targetAddr)
		}
		svcConfig.Arguments = args
	}

	prg := &program{
		mode:        mode,
		metricsAddr: metricsAddr,
		interval:    interval,
		timeout:     timeout,
		window:      window,
		serverAddr:  listenAddr,
		targets:     targets,
	}

	svc, err := service.New(prg, svcConfig)
	if err != nil {
		log.Fatalf("Service setup error: %v", err)
	}

	switch action {
	case "install":
		if err := svc.Install(); err != nil {
			log.Fatalf("Service install failed: %v", err)
		}
		log.Println("Service installed")
	case "uninstall":
		if err := svc.Uninstall(); err != nil {
			log.Fatalf("Service uninstall failed: %v", err)
		}
		log.Println("Service uninstalled")
	case "start":
		if err := svc.Start(); err != nil {
			log.Fatalf("Service start failed: %v", err)
		}
		log.Println("Service started")
	case "stop":
		if err := svc.Stop(); err != nil {
			log.Fatalf("Service stop failed: %v", err)
		}
		log.Println("Service stopped")
	case "run":
		if err := svc.Run(); err != nil {
			log.Fatalf("Service run error: %v", err)
		}
	default:
		log.Fatalf("Unknown service action: %s", action)
	}
}

// program implements service.Interface.
type program struct {
	mode        string
	serverAddr  string
	targets     []Target
	metricsAddr string
	interval    time.Duration
	timeout     time.Duration
	window      int

	ctx    context.Context
	cancel context.CancelFunc
	done   sync.WaitGroup
}

func (p *program) Start(s service.Service) error {
	p.ctx, p.cancel = context.WithCancel(context.Background())
	p.done.Add(1)
	go func() {
		defer p.done.Done()
		if err := runApp(p.ctx, p.mode, p.serverAddr, p.targets, p.metricsAddr, p.interval, p.timeout, p.window); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("Service run error: %v", err)
		}
	}()
	return nil
}

func (p *program) Stop(s service.Service) error {
	if p.cancel != nil {
		p.cancel()
	}
	p.done.Wait()
	return nil
}

// runApp initializes the metrics server and starts the main application logic (server/client).
func runApp(ctx context.Context, mode, serverAddr string, targets []Target, metricsAddr string, interval, timeout time.Duration, window int) error {
	// Start metrics server.
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	httpSrv := &http.Server{Addr: metricsAddr, Handler: mux}

	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("Metrics server error: %v", err)
		}
	}()

	var err error
	switch mode {
	case "server":
		err = runServer(ctx, serverAddr)
	case "client":
		err = runClients(ctx, targets, interval, timeout, window)
	case "both":
		// Run server in a goroutine, client in main blocking.
		serverErrCh := make(chan error, 1)
		go func() {
			serverErrCh <- runServer(ctx, serverAddr)
		}()

		if clientErr := runClients(ctx, targets, interval, timeout, window); clientErr != nil && !errors.Is(clientErr, context.Canceled) {
			err = clientErr
		}

		// If client finishes (e.g. error or ctx done), check if server had error.
		select {
		case sErr := <-serverErrCh:
			if sErr != nil && !errors.Is(sErr, context.Canceled) {
				if err == nil {
					err = sErr
				} else {
					err = fmt.Errorf("client: %v, server: %v", err, sErr)
				}
			}
		default:
		}
	default:
		err = fmt.Errorf("unknown mode: %s", mode)
	}

	// Shutdown metrics server.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)

	return err
}

// runServer runs the TCP echo server.
func runServer(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	log.Printf("Echo server listening on %s", addr)
	defer ln.Close()

	var wg sync.WaitGroup

	// Monitor context cancellation to close listener.
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		// Check context before accepting.
		if ctx.Err() != nil {
			break
		}

		conn, err := ln.Accept()
		if err != nil {
			// Check if it's a closed network connection due to context cancellation.
			if ctx.Err() != nil {
				break
			}
			log.Printf("Accept error: %v", err)
			continue
		}

		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			defer c.Close()
			handleConnection(ctx, c)
		}(conn)
	}

	wg.Wait()
	return nil
}

// handleConnection echoes data back to the client.
func handleConnection(ctx context.Context, c net.Conn) {
	if tcpConn, ok := c.(*net.TCPConn); ok {
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	// Use a buffer with the exact payload size for simplicity, or 64 to be safe.
	buf := make([]byte, payloadSize)
	for {
		if ctx.Err() != nil {
			return
		}

		// Set read deadline to ensure we don't block forever if client disappears.
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		// Use io.ReadFull for guaranteed full payload reading.
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}

		// Echo back.
		_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write(buf); err != nil {
			return
		}
	}
}

// runClients starts probe loops for all targets.
func runClients(ctx context.Context, targets []Target, interval, timeout time.Duration, window int) error {
	if len(targets) == 0 {
		return nil
	}

	gCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	errCh := make(chan error, len(targets))

	for _, t := range targets {
		wg.Add(1)
		go func(target Target) {
			defer wg.Done()
			if err := runClientProbe(gCtx, target.Name, target.Address, interval, timeout, window); err != nil {
				errCh <- fmt.Errorf("%s: %w", target.Name, err)
			}
		}(t)
	}

	// Wait for all to finish or context cancellation.
	// Since runClientProbe only returns on fatal error or context cancel,
	// we just wait.
	wg.Wait()
	close(errCh)

	// Return the first error if any.
	for err := range errCh {
		if err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
	}
	return nil
}

// runClientProbe manages the connection and probing loop for a single target.
func runClientProbe(ctx context.Context, name, addr string, interval, timeout time.Duration, window int) error {
	log.Printf("Client probing %s (%s) every %s", name, addr, interval)

	// Track packet loss.
	lTracker := newLossTracker(window, name)
	var seq uint64

	// Retry loop for connection.
	backoff := 500 * time.Millisecond
	maxBackoff := 5 * time.Second

	for ctx.Err() == nil {
		conn, err := dial(addr)
		if err != nil {
			log.Printf("Dial error %s: %v", name, err)

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}

			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}

		// Connected. Reset backoff.
		backoff = 500 * time.Millisecond
		connectsCounter.WithLabelValues(name).Inc()
		connectedGauge.WithLabelValues(name).Set(1)

		err = probeLoop(ctx, conn, interval, timeout, &seq, lTracker, name)

		connectedGauge.WithLabelValues(name).Set(0)
		_ = conn.Close()

		if err != nil {
			// standard log if dropped
			if ctx.Err() == nil {
				log.Printf("Connection dropped %s: %v", name, err)
			}
		}
	}
	return ctx.Err()
}

// probeLoop sends echoes and processes responses.
func probeLoop(ctx context.Context, conn net.Conn, interval, timeout time.Duration, seq *uint64, lt *lossTracker, name string) error {
	// Channels for responses and errors from the reader goroutine.
	type response struct {
		seq  uint64
		recv time.Time
	}
	respCh := make(chan response, 64)
	readErrCh := make(chan error, 1)

	// Reader goroutine.
	go func() {
		buf := make([]byte, payloadSize)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(timeout + 500*time.Millisecond)) // slightly looser deadline for reading
			_, err := io.ReadFull(conn, buf)
			if err != nil {
				readErrCh <- err
				return
			}

			// Parse response.
			seqNum := binary.LittleEndian.Uint64(buf[0:8])
			select {
			case respCh <- response{seq: seqNum, recv: time.Now()}:
			case <-ctx.Done():
				return
			}
		}
	}()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Map to track sent times: seq -> sentTime
	outstanding := make(map[uint64]time.Time)
	sendBuf := make([]byte, payloadSize)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case err := <-readErrCh:
			return err

		case resp := <-respCh:
			sentTime, ok := outstanding[resp.seq]
			if !ok {
				// Old or unknown sequence number. Ignore.
				continue
			}
			delete(outstanding, resp.seq)

			rtt := resp.recv.Sub(sentTime)
			if rtt > timeout {
				// Late response. Count as success for connectivity but maybe log?
				// For now, treat as success.
				lt.record(true)
			} else {
				recvCounter.WithLabelValues(name).Inc()
				lastRttGauge.WithLabelValues(name).Set(rtt.Seconds())
				rttHistogram.WithLabelValues(name).Observe(rtt.Seconds())
				lt.record(true)
			}

		case <-ticker.C:
			// Prune timed-out requests from map and count as loss.
			now := time.Now()
			for s, t := range outstanding {
				if now.Sub(t) > timeout {
					delete(outstanding, s)
					lt.record(false)
					timeoutCounter.WithLabelValues(name).Inc()
				}
			}

			// Send new probe.
			nextSeq := *seq + 1
			*seq = nextSeq

			binary.LittleEndian.PutUint64(sendBuf[0:8], nextSeq)
			binary.LittleEndian.PutUint64(sendBuf[8:16], uint64(now.UnixNano()))

			_ = conn.SetWriteDeadline(now.Add(timeout))
			if _, err := conn.Write(sendBuf); err != nil {
				lt.record(false)
				timeoutCounter.WithLabelValues(name).Inc()
				return err
			}

			outstanding[nextSeq] = now
			sentCounter.WithLabelValues(name).Inc()
		}
	}
}

// dial helper with shorter timeout and NODELAY.
func dial(addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	if tcpConn, ok := c.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
	}
	return c, nil
}
