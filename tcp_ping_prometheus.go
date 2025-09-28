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
	"sync"
	"syscall"
	"time"

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
	mode := flag.String("mode", "server", "server or client")
	tcpAddr := flag.String("tcp", ":4000", "TCP address to listen on (server) or connect to (client)")
	metricsAddr := flag.String("metrics", ":2112", "HTTP address for Prometheus /metrics")
	interval := flag.Duration("interval", 200*time.Millisecond, "Client: probe interval")
	timeout := flag.Duration("timeout", 800*time.Millisecond, "Client: per-probe timeout (considered loss)")
	window := flag.Int("window", 100, "Client: sliding window size for loss percentage")
	flag.Parse()

	// Start HTTP metrics endpoint
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	httpSrv := &http.Server{Addr: *metricsAddr, Handler: mux}
	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("metrics server error: %v", err)
		}
	}()

	// Graceful shutdown on SIGINT/SIGTERM
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch *mode {
	case "server":
		if err := runServer(ctx, *tcpAddr); err != nil {
			log.Fatalf("server error: %v", err)
		}
	case "client":
		if err := runClient(ctx, *tcpAddr, *interval, *timeout, *window); err != nil {
			log.Fatalf("client error: %v", err)
		}
	default:
		log.Fatalf("unknown mode: %s", *mode)
	}

	// Shutdown metrics server gracefully
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
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

	// Reader goroutine: continuously read 16-byte echoes and forward seq+receive-time.
	go func() {
		buf := make([]byte, 16)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(timeout))
			_, err := ioReadFull(reader, buf)
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
			seqNum := binary.LittleEndian.Uint64(buf[0:8])
			select {
			case respCh <- response{seq: seqNum, when: time.Now()}:
			case <-ctx.Done():
				return
			}
		}
	}()

	sendTicker := time.NewTicker(interval)
	defer sendTicker.Stop()
	cleanupTicker := time.NewTicker(50 * time.Millisecond)
	defer cleanupTicker.Stop()

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
			mu.Unlock()
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
			// prepare and send next probe
			nextSeq := (*seq) + 1
			now := time.Now()
			payload := make([]byte, 16)
			binary.LittleEndian.PutUint64(payload[0:8], nextSeq)
			binary.LittleEndian.PutUint64(payload[8:16], uint64(now.UnixNano()))

			_ = conn.SetWriteDeadline(time.Now().Add(timeout))
			if _, err := writer.Write(payload); err != nil {
				// write failed: mark this probe lost and decide whether to continue or abort
				lt.record(false)
				timeoutCounter.Inc()
				// if temporary (including timeout), continue; otherwise return to reconnect
				if ne, ok := err.(net.Error); ok && (ne.Timeout() || ne.Temporary()) {
					continue
				}
				return err
			}
			if err := writer.Flush(); err != nil {
				lt.record(false)
				timeoutCounter.Inc()
				if ne, ok := err.(net.Error); ok && (ne.Timeout() || ne.Temporary()) {
					continue
				}
				return err
			}

			// commit seq and track outstanding send time
			*seq = nextSeq
			sentCounter.Inc()
			mu.Lock()
			outstanding[nextSeq] = now
			mu.Unlock()
		case <-cleanupTicker.C:
			// expire outstanding entries older than timeout -> record as lost
			now := time.Now()
			var expired []uint64
			mu.Lock()
			for s, t := range outstanding {
				if now.Sub(t) > timeout {
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
