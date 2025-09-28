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

// wire format: 16 bytes
// [0:8)  = seq (uint64, LE)
// [8:16) = sent_unix_nano (int64, LE)

var (
	// metrics
	sentTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "tcp_echo_sent_total",
		Help: "Number of echo requests sent.",
	})
	recvTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "tcp_echo_received_total",
		Help: "Number of echo responses received.",
	})
	timeoutTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "tcp_echo_timeouts_total",
		Help: "Number of echo requests that timed out (treated as loss).",
	})
	connectsTotal = prometheus.NewCounter(prometheus.CounterOpts{
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
	rttHist = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "tcp_echo_rtt_seconds",
		Help:    "Round-trip latency measured over the TCP echo path.",
		Buckets: prometheus.ExponentialBuckets(0.0001, 1.8, 20), // 100µs .. ~6s TODO: FIX TIMING
	})
	lastRTTGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "tcp_echo_last_rtt_seconds",
		Help: "Last observed RTT in seconds.",
	})
	lossGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "tcp_echo_loss_percent",
		Help: "Echo loss percentage over the sliding window (timeouts considered loss).",
	})
)

func init() {
	prometheus.MustRegister(sentTotal, recvTotal, timeoutTotal, connectsTotal, connectedGauge, upGauge, rttHist, lastRTTGauge, lossGauge)
	upGauge.Set(1)
}

// lossTracker keeps a rolling window of outcomes.
type lossTracker struct {
	mu     sync.Mutex
	buf    []bool // true = success, false = loss
	idx    int
	filled bool
}

func newLossTracker(n int) *lossTracker {
	if n < 1 {
		n = 1
	}
	return &lossTracker{buf: make([]bool, n)}
}

func (lt *lossTracker) record(ok bool) {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	lt.buf[lt.idx] = ok
	lt.idx = (lt.idx + 1) % len(lt.buf)
	if lt.idx == 0 {
		lt.filled = true
	}
	lossGauge.Set(lt.lossPercent())
}

func (lt *lossTracker) lossPercent() float64 {
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

func main() {
	mode := flag.String("mode", "server", "server or client")
	tcpAddr := flag.String("tcp", ":4000", "TCP address to listen on (server) or connect to (client)")
	metricsAddr := flag.String("metrics", ":2112", "HTTP address for Prometheus /metrics")
	interval := flag.Duration("interval", 200*time.Millisecond, "Client: probe interval")
	timeout := flag.Duration("timeout", 800*time.Millisecond, "Client: per-probe timeout (considered loss)")
	window := flag.Int("window", 100, "Client: sliding window size for loss percentage")
	flag.Parse()

	// HTTP metrics server
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	httpSrv := &http.Server{Addr: *metricsAddr, Handler: mux}
	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("metrics server error: %v", err)
		}
	}()

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

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
}

func runServer(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	log.Printf("echo server listening on %s", addr)
	defer ln.Close()

	var wg sync.WaitGroup
	for {
		ln.(*net.TCPListener).SetDeadline(time.Now().Add(1 * time.Second))
		conn, err := ln.Accept()
		if err != nil {
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
			_ = c.(*net.TCPConn).SetKeepAlive(true)
			_ = c.(*net.TCPConn).SetKeepAlivePeriod(30 * time.Second)
			reader := bufio.NewReaderSize(c, 64)
			buf := make([]byte, 16)
			for {
				if ctx.Err() != nil {
					return
				}
				c.SetReadDeadline(time.Now().Add(30 * time.Second))
				_, err := ioReadFull(reader, buf)
				if err != nil {
					if ne, ok := err.(net.Error); ok && ne.Timeout() {
						continue // idle
					}
					return
				}
				// echo back exactly
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

func runClient(ctx context.Context, addr string, interval, timeout time.Duration, window int) error {
	log.Printf("client probing %s every %s (timeout %s)", addr, interval, timeout)
	lt := newLossTracker(window)
	var seq uint64

	retryDelay := 500 * time.Millisecond
	for ctx.Err() == nil {
		c, err := dial(addr)
		if err != nil {
			log.Printf("dial error: %v", err)
			time.Sleep(retryDelay)
			retryDelay = minDuration(retryDelay*2, 5*time.Second)
			continue
		}
		retryDelay = 500 * time.Millisecond
		connectsTotal.Inc()
		connectedGauge.Set(1)

		if err := pump(ctx, c, interval, timeout, &seq, lt); err != nil {
			connectedGauge.Set(0)
			c.Close()
			if ctx.Err() == nil {
				log.Printf("connection dropped: %v", err)
			}
		}
	}
	return ctx.Err()
}

func pump(ctx context.Context, c net.Conn, interval, timeout time.Duration, seq *uint64, lt *lossTracker) error {
	defer c.Close()
	writer := bufio.NewWriterSize(c, 64)
	reader := bufio.NewReaderSize(c, 64)

	// Channels for reader goroutine
	type resp struct {
		seq  uint64
		when time.Time
	}
	respCh := make(chan resp, 128)
	errCh := make(chan error, 1)

	// outstanding sends
	var mu sync.Mutex
	outstanding := make(map[uint64]time.Time)

	// start reader goroutine that continuously reads 16-byte echoes
	go func() {
		buf := make([]byte, 16)
		for {
			_ = c.SetReadDeadline(time.Now().Add(timeout))
			_, err := ioReadFull(reader, buf)
			if err != nil {
				// treat timeout as non-fatal; other errors are reported
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				select {
				case errCh <- err:
				default:
				}
				return
			}
			seq := binary.LittleEndian.Uint64(buf[0:8])
			select {
			case respCh <- resp{seq: seq, when: time.Now()}:
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
			// reader reported a non-temporary error -> connection broken
			return err
		case r := <-respCh:
			// match response to outstanding
			mu.Lock()
			st, ok := outstanding[r.seq]
			if ok {
				delete(outstanding, r.seq)
			}
			mu.Unlock()
			if !ok {
				// stale / unknown reply -> ignore
				continue
			}
			rtt := r.when.Sub(st)
			if rtt < 0 {
				rtt = 0
			}
			// if reply arrived after timeout, flip prior timeout to success but don't record RTT histogram
			if rtt > timeout {
				lt.record(true)
				continue
			}
			recvTotal.Inc()
			lastRTTGauge.Set(rtt.Seconds())
			rttHist.Observe(rtt.Seconds())
			lt.record(true)
		case <-sendTicker.C:
			// prepare and send next probe
			cand := (*seq) + 1
			now := time.Now()
			payload := make([]byte, 16)
			binary.LittleEndian.PutUint64(payload[0:8], cand)
			binary.LittleEndian.PutUint64(payload[8:16], uint64(now.UnixNano()))

			_ = c.SetWriteDeadline(time.Now().Add(timeout))
			if _, err := writer.Write(payload); err != nil {
				// write failed: mark this probe lost and decide whether to continue or abort
				lt.record(false)
				timeoutTotal.Inc()
				// if temporary (including timeout), continue; otherwise return to let caller reconnect
				if ne, ok := err.(net.Error); ok && (ne.Timeout() || ne.Temporary()) {
					continue
				}
				return err
			}
			if err := writer.Flush(); err != nil {
				lt.record(false)
				timeoutTotal.Inc()
				if ne, ok := err.(net.Error); ok && (ne.Timeout() || ne.Temporary()) {
					continue
				}
				return err
			}

			// commit seq and track outstanding
			*seq = cand
			sentTotal.Inc()
			mu.Lock()
			outstanding[cand] = now
			mu.Unlock()
		case <-cleanupTicker.C:
			// expire outstanding entries older than timeout -> consider them lost
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
				timeoutTotal.Inc()
			}
		}
	}
}

func dial(addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	_ = c.(*net.TCPConn).SetNoDelay(true)
	return c, nil
}

func ioReadFull(r *bufio.Reader, buf []byte) (int, error) {
	// optimized read full into fixed buffer
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

// --- Prometheus example queries ---
// rate(tcp_echo_timeouts_total[5m])
// histogram_quantile(0.99, rate(tcp_echo_rtt_seconds_bucket[5m]))
// avg_over_time(tcp_echo_loss_percent[5m])

// Build & Run:
//  go mod init example.com/tcp-echo-metrics
//  go mod tidy
//  go build -o tcp-echo-metrics .
//  # terminal 1 (server)
//  ./tcp-echo-metrics -mode=server -tcp=":4000" -metrics=":2112"
//  # terminal 2 (client)
//  ./tcp-echo-metrics -mode=client -tcp="127.0.0.1:4000" -interval=200ms -timeout=800ms -metrics=":2113"
//  # scrape http://localhost:2113/metrics
