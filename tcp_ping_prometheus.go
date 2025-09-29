package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/kardianos/service"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

/*
tcp_ping_prometheus.go

A small TCP "echo" probe with Prometheus metrics.

Wire format for each probe/echo is 16 bytes:
- bytes [0:8)   = sequence number (uint64, little-endian)
- bytes [8:16)  = sent timestamp (int64 unix-nanoseconds, little-endian)

Modes:
- server: accept TCP connections and echo back 16-byte payloads unchanged.
- client: repeatedly connect and send probes; measure RTT based on echoed payload.

This file contains:
- Prometheus metric definitions and registration
- A sliding-window loss tracker (lossTracker)
- runServer: TCP echo server
- runClient: client that maintains a connection and probes the server
- pump: handles send/receive/timeout bookkeeping on an established connection
*/

var (
	// Prometheus metrics (names kept the same as original)
	sentCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "tcp_echo_sent_total",
		Help: "Number of echo requests sent.",
	})
	recvCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "tcp_echo_received_total",
		Help: "Number of echo responses received.",
	})
	timeoutCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "tcp_echo_timeouts_total",
		Help: "Number of echo requests that timed out (treated as loss).",
	})
	connectsCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "tcp_echo_connects_total",
		Help: "Number of TCP connect attempts (successful).",
	})
	connectedGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "tcp_echo_connected",
		Help: "1 if the client is currently connected to the server, else 0.",
	})
	upGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "tcp_echo_up",
		Help: "Exporter health indicator (1 = up).",
	})
	rttHistogram = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "tcp_echo_rtt_seconds",
		Help:    "Round-trip latency measured over the TCP echo path.",
		Buckets: prometheus.ExponentialBuckets(0.0001, 1.8, 20), // 100µs .. ~6s
	})
	lastRttGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "tcp_echo_last_rtt_seconds",
		Help: "Last observed RTT in seconds.",
	})
	lossPercentGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "tcp_echo_loss_percent",
		Help: "Echo loss percentage over the sliding window (timeouts considered loss).",
	})
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
	// Mark exporter as up unless init fails later.
	upGauge.Set(1)
}

// lossTracker maintains a fixed-size circular buffer of recent probe outcomes.
// true indicates success, false indicates loss. It exposes a method to compute
// the current loss percentage for a sliding window and updates the loss gauge.
type lossTracker struct {
	mu     sync.Mutex
	buf    []bool // circular buffer of outcomes
	idx    int    // next write index
	filled bool   // true once we've wrapped at least once
}

func newLossTracker(size int) *lossTracker {
	if size < 1 {
		size = 1
	}
	return &lossTracker{buf: make([]bool, size)}
}

// record appends an outcome (true=success, false=loss) and updates the Prometheus gauge.
func (lt *lossTracker) record(ok bool) {
	lt.mu.Lock()
	lt.buf[lt.idx] = ok
	lt.idx = (lt.idx + 1) % len(lt.buf)
	if lt.idx == 0 {
		lt.filled = true
	}
	currentLoss := lt.computeLossPercentLocked()
	lt.mu.Unlock()

	// update Prometheus metric outside of the locked region in case Set blocks
	lossPercentGauge.Set(currentLoss)
}

// computeLossPercentLocked calculates loss percent. Caller must hold lt.mu.
func (lt *lossTracker) computeLossPercentLocked() float64 {
	total := len(lt.buf)
	if !lt.filled {
		total = lt.idx
		if total == 0 {
			return 0
		}
	}
	fail := 0
	for i := 0; i < total; i++ {
		if !lt.buf[i] {
			fail++
		}
	}
	return 100.0 * float64(fail) / float64(total)
}

// To preserve the same CLI behaviour as before, main constructs the HTTP metrics
// server, parses flags, and dispatches to the server or client mode.
func main() {
	mode := flag.String("mode", "server", "server, client or both")
	listenAddr := flag.String("listen", ":4000", "TCP address to listen on (server)")
	targetAddr := flag.String("target", ":4000", "TCP address to connect to (client)")
	metricsAddr := flag.String("metrics", ":2112", "HTTP address for Prometheus /metrics")
	interval := flag.Duration("interval", 200*time.Millisecond, "Client: probe interval")
	timeout := flag.Duration("timeout", 800*time.Millisecond, "Client: per-probe timeout (considered loss)")
	window := flag.Int("window", 100, "Client: sliding window size for loss percentage")
	// Service control flag: install/uninstall/start/stop/run
	svcAction := flag.String("svc", "", "service action: install | uninstall | start | stop | run")
	flag.Parse()

	// resolved addresses
	serverAddr := *listenAddr
	clientAddr := *targetAddr

	// If a service action was requested, use kardianos/service to handle it.
	if *svcAction != "" {
		svcConfig := &service.Config{
			Name:        "tcp_ping_prometheus",
			DisplayName: "TCP Ping Prometheus",
			Description: "TCP echo probe exporter with Prometheus metrics.",
		}
		prg := &program{
			mode:        *mode,
			metricsAddr: *metricsAddr,
			interval:    *interval,
			timeout:     *timeout,
			window:      *window,
			// set resolved addresses
			serverAddr: serverAddr,
			clientAddr: clientAddr,
		}
		svc, err := service.New(prg, svcConfig)
		if err != nil {
			log.Fatalf("service setup error: %v", err)
		}
		// On Windows, some actions map differently; control supports install/uninstall/start/stop.
		switch *svcAction {
		case "install":
			if err := svc.Install(); err != nil {
				log.Fatalf("service install failed: %v", err)
			}
			log.Printf("service installed")
			return
		case "uninstall":
			if err := svc.Uninstall(); err != nil {
				log.Fatalf("service uninstall failed: %v", err)
			}
			log.Printf("service uninstalled")
			return
		case "start":
			if err := svc.Start(); err != nil {
				log.Fatalf("service start failed: %v", err)
			}
			log.Printf("service started")
			return
		case "stop":
			if err := svc.Stop(); err != nil {
				log.Fatalf("service stop failed: %v", err)
			}
			log.Printf("service stopped")
			return
		case "run":
			// Run blocks and uses the program's Start/Stop to manage lifecycle.
			if runtime.GOOS == "windows" {
				// On Windows, run should call Run to attach to the service manager.
				if err := svc.Run(); err != nil {
					log.Fatalf("service run error: %v", err)
				}
				return
			}
			// On Linux, running as a service via Run works as well; Run will call Start.
			if err := svc.Run(); err != nil {
				log.Fatalf("service run error: %v", err)
			}
			return
		default:
			log.Fatalf("unknown svc action: %s", *svcAction)
		}
	}

	// Normal foreground execution
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := runApp(ctx, *mode, serverAddr, clientAddr, *metricsAddr, *interval, *timeout, *window); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatalf("error: %v", err)
	}
}

// program implements service.Interface for kardianos/service.
type program struct {
	// configuration captured at creation-time
	mode string
	// retained for compatibility in this patch but no longer used directly
	tcpAddr     string
	serverAddr  string
	clientAddr  string
	metricsAddr string
	interval    time.Duration
	timeout     time.Duration
	window      int

	ctx    context.Context
	cancel context.CancelFunc
	done   sync.WaitGroup
}

func (p *program) Start(s service.Service) error {
	// Start should not block. Launch the run in a goroutine.
	p.ctx, p.cancel = context.WithCancel(context.Background())
	p.done.Add(1)
	go func() {
		defer p.done.Done()
		// use resolved server/client addrs
		if err := runApp(p.ctx, p.mode, p.serverAddr, p.clientAddr, p.metricsAddr, p.interval, p.timeout, p.window); err != nil && !errors.Is(err, context.Canceled) {
			// Log errors; service manager will see exit code.
			log.Printf("service run error: %v", err)
		}
	}()
	return nil
}

func (p *program) Stop(s service.Service) error {
	// Stop should signal the goroutine to stop and wait for it.
	if p.cancel != nil {
		p.cancel()
	}
	p.done.Wait()
	return nil
}

// runApp contains the previous main logic that starts the metrics server and
// dispatches to server/client/both modes. This is reused for normal and service runs.
func runApp(ctx context.Context, mode, serverAddr, clientAddr, metricsAddr string, interval, timeout time.Duration, window int) error {
	// Start HTTP metrics endpoint
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	httpSrv := &http.Server{Addr: metricsAddr, Handler: mux}
	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("metrics server error: %v", err)
		}
	}()

	// Graceful shutdown on ctx cancellation is handled by callers.
	switch mode {
	case "server":
		if err := runServer(ctx, serverAddr); err != nil {
			return fmt.Errorf("server error: %w", err)
		}
	case "client":
		if err := runClient(ctx, clientAddr, interval, timeout, window); err != nil {
			return fmt.Errorf("client error: %w", err)
		}
	case "both":
		serverErrCh := make(chan error, 1)
		go func() {
			serverErrCh <- runServer(ctx, serverAddr)
		}()

		if err := runClient(ctx, clientAddr, interval, timeout, window); err != nil && !errors.Is(err, context.Canceled) {
			return fmt.Errorf("client error: %w", err)
		}

		if serr := <-serverErrCh; serr != nil && !errors.Is(serr, context.Canceled) {
			return fmt.Errorf("server error: %w", serr)
		}
	default:
		return fmt.Errorf("unknown mode: %s", mode)
	}

	// Shutdown metrics server gracefully
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	return nil
}

// runServer runs a simple TCP echo server. It accepts connections and echoes
// back any 16-byte payload unchanged. The server periodically times out Accept
// to allow checking the context for shutdown.
func runServer(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	log.Printf("echo server listening on %s", addr)
	defer ln.Close()

	var wg sync.WaitGroup
	for {
		// set a deadline so we can break out when context is canceled
		ln.(*net.TCPListener).SetDeadline(time.Now().Add(1 * time.Second))
		conn, err := ln.Accept()
		if err != nil {
			// handle timeout from SetDeadline
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if ctx.Err() != nil {
					break
				}
				continue
			}
			log.Printf("accept error: %v", err)
			continue
		}

		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			defer c.Close()
			// Try to set keep-alive for long-lived connections; ignore errors.
			if tcpConn, ok := c.(*net.TCPConn); ok {
				_ = tcpConn.SetKeepAlive(true)
				_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
			}

			reader := bufio.NewReaderSize(c, 64)
			buf := make([]byte, 16)
			for {
				if ctx.Err() != nil {
					return
				}
				// Make read deadline not too long so we can also detect ctx cancellation.
				c.SetReadDeadline(time.Now().Add(30 * time.Second))
				_, err := ioReadFull(reader, buf)
				if err != nil {
					if ne, ok := err.(net.Error); ok && ne.Timeout() {
						continue // idle
					}
					return
				}
				// Echo payload back unchanged; error breaks loop.
				c.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if _, err := c.Write(buf); err != nil {
					return
				}
			}
		}(conn)
	}

	wg.Wait()
	return nil
}

// runClient repeatedly connects to addr and probes via pump. On connection loss
// it reconnects with exponential backoff (capped).
func runClient(ctx context.Context, addr string, interval, timeout time.Duration, window int) error {
	log.Printf("client probing %s every %s (timeout %s)", addr, interval, timeout)
	lTracker := newLossTracker(window)
	var seq uint64

	retryDelay := 500 * time.Millisecond
	for ctx.Err() == nil {
		conn, err := dial(addr)
		if err != nil {
			log.Printf("dial error: %v", err)
			time.Sleep(retryDelay)
			retryDelay = minDuration(retryDelay*2, 5*time.Second)
			continue
		}
		retryDelay = 500 * time.Millisecond
		connectsCounter.Inc()
		connectedGauge.Set(1)

		if err := pump(ctx, conn, interval, timeout, &seq, lTracker); err != nil {
			connectedGauge.Set(0)
			conn.Close()
			if ctx.Err() == nil {
				log.Printf("connection dropped: %v", err)
			}
		}
	}
	return ctx.Err()
}

// pump manages the probe send/receive loop for a single established connection.
// It spawns a reader goroutine that pushes received responses into respCh
// and the main loop sends probes on a ticker and expires outstanding probes.
func pump(ctx context.Context, conn net.Conn, interval, timeout time.Duration, seq *uint64, lt *lossTracker) error {
	defer conn.Close()
	writer := bufio.NewWriterSize(conn, 64)
	reader := bufio.NewReaderSize(conn, 64)

	type response struct {
		seq  uint64
		when time.Time
	}
	respCh := make(chan response, 128)
	errCh := make(chan error, 1)

	// outstanding maps sequence -> send time for matching responses and timeout checks.
	var mu sync.Mutex
	outstanding := make(map[uint64]time.Time)

	// allocate reusable buffers to avoid per-iteration GC pressure
	readerBuf := make([]byte, 16)
	payloadBuf := make([]byte, 16)

	// Reader goroutine: continuously read 16-byte echoes and forward seq+receive-time.
	go func() {
		for {
			_ = conn.SetReadDeadline(time.Now().Add(timeout))
			_, err := ioReadFull(reader, readerBuf)
			if err != nil {
				// treat timeout as non-fatal; other errors are reported to pump
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				select {
				case errCh <- err:
				default:
				}
				return
			}
			seqNum := binary.LittleEndian.Uint64(readerBuf[0:8])
			select {
			case respCh <- response{seq: seqNum, when: time.Now()}:
			case <-ctx.Done():
				return
			}
		}
	}()

	sendTicker := time.NewTicker(interval)
	defer sendTicker.Stop()

	// perform cleanup every N sends to avoid scanning map on every tick
	const cleanupEvery = 5
	sendCounter := 0

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errCh:
			// non-temporary reader error -> terminate connection
			return err
		case r := <-respCh:
			// match response to outstanding sends
			mu.Lock()
			sendTime, ok := outstanding[r.seq]
			if ok {
				delete(outstanding, r.seq)
			}
			// Also expire any other timed-out entries opportunistically
			now := time.Now()
			var expired []uint64
			for s, t := range outstanding {
				if now.Sub(t) > timeout {
					expired = append(expired, s)
				}
			}
			for _, s := range expired {
				delete(outstanding, s)
			}
			mu.Unlock()

			// account for expirations as losses
			for range expired {
				lt.record(false)
				timeoutCounter.Inc()
			}

			if !ok {
				// Unknown or stale reply; ignore
				continue
			}
			rtt := r.when.Sub(sendTime)
			if rtt < 0 {
				rtt = 0
			}
			// If reply arrived after the configured timeout, treat it as late:
			// consider the probe successful for loss stats but do not record RTT.
			if rtt > timeout {
				lt.record(true)
				continue
			}
			recvCounter.Inc()
			lastRttGauge.Set(rtt.Seconds())
			rttHistogram.Observe(rtt.Seconds())
			lt.record(true)
		case <-sendTicker.C:
			// prepare and send next probe (reuse payloadBuf)
			nextSeq := (*seq) + 1
			now := time.Now()
			binary.LittleEndian.PutUint64(payloadBuf[0:8], nextSeq)
			binary.LittleEndian.PutUint64(payloadBuf[8:16], uint64(now.UnixNano()))

			_ = conn.SetWriteDeadline(time.Now().Add(timeout))
			if _, err := writer.Write(payloadBuf); err != nil {
				// write failed: mark this probe lost and decide whether to continue or abort
				lt.record(false)
				timeoutCounter.Inc()
				// if temporary (including timeout), continue; otherwise return to reconnect
				if ne, ok := err.(net.Error); ok && (ne.Timeout() || ne.Temporary()) {
					// still increment seq so sequence numbers remain monotonic
					*seq = nextSeq
					sentCounter.Inc()
					continue
				}
				return err
			}
			if err := writer.Flush(); err != nil {
				lt.record(false)
				timeoutCounter.Inc()
				if ne, ok := err.(net.Error); ok && (ne.Timeout() || ne.Temporary()) {
					*seq = nextSeq
					sentCounter.Inc()
					continue
				}
				return err
			}

			// commit seq and track outstanding send time
			*seq = nextSeq
			sentCounter.Inc()
			mu.Lock()
			outstanding[nextSeq] = now
			// do periodic cleanup every cleanupEvery sends to expire old outstanding entries
			sendCounter++
			if sendCounter >= cleanupEvery {
				sendCounter = 0
				now2 := time.Now()
				var expired []uint64
				for s, t := range outstanding {
					if now2.Sub(t) > timeout {
						expired = append(expired, s)
					}
				}
				for _, s := range expired {
					delete(outstanding, s)
				}
				mu.Unlock()
				for range expired {
					lt.record(false)
					timeoutCounter.Inc()
				}
			} else {
				mu.Unlock()
			}
		}
	}
}

// dial connects to addr with a short timeout and enables TCP_NODELAY.
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

// ioReadFull reads len(buf) bytes from a bufio.Reader. It's similar to io.ReadFull
// but specialised to work with bufio.Reader to avoid an import and be efficient.
func ioReadFull(r *bufio.Reader, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := r.Read(buf[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
