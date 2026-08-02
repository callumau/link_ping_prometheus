package prober

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"
)

const (
	// MaxConnsGlobal caps total concurrent echo connections.
	MaxConnsGlobal = 1000
	// DefaultReadTimeout is the per-connection idle read deadline.
	// Clients probing at an interval >= readTimeout will be disconnected
	// for idleness, so the client interval should stay well below this.
	DefaultReadTimeout = 10 * time.Second
)

// MaxConnsPerIP caps concurrent echo connections from a single remote IP.
// A variable (not a constant) so tests can lower it.
var MaxConnsPerIP = 128

// RunServer starts a TCP echo listener on addr. Each accepted connection
// is handled in its own goroutine. The server enforces a maximum of
// MaxConnsGlobal concurrent connections and MaxConnsPerIP per remote IP;
// excess connections are immediately closed. Blocks until ctx is
// cancelled, then closes the listener and all open connections.
func RunServer(ctx context.Context, addr string, readTimeout time.Duration) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	slog.Info("Echo server listening", "addr", addr, "read_timeout", readTimeout)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	return ServeListener(ctx, ln, readTimeout)
}

// ServeListener accepts connections on ln and handles each in a
// goroutine. Limits: MaxConnsGlobal total, MaxConnsPerIP per remote IP.
// Transient accept errors back off exponentially (10ms..1s) instead of
// hot-looping. On ctx cancellation all tracked connections are closed
// and ServeListener waits (bounded by 5s) for every handler goroutine
// to finish before returning. Blocks until ctx is cancelled or ln is
// closed.
func ServeListener(ctx context.Context, ln net.Listener, readTimeout time.Duration) error {
	if readTimeout <= 0 {
		readTimeout = DefaultReadTimeout
	}
	sem := make(chan struct{}, MaxConnsGlobal)

	var mu sync.Mutex
	openConns := make(map[net.Conn]struct{})
	perIP := make(map[string]int)
	var handlers sync.WaitGroup

	// Force-close all open connections on shutdown so handleConn
	// goroutines exit promptly instead of lingering until readTimeout.
	// Connections are collected under the lock and closed outside it:
	// Close may block on platform cleanup and must never hold the lock
	// the handlers' deferred cleanup needs. The listener is closed too:
	// Accept blocks until it errors, so ctx cancellation alone would
	// never let the accept loop exit.
	go func() {
		<-ctx.Done()
		ln.Close()
		mu.Lock()
		conns := make([]net.Conn, 0, len(openConns))
		for c := range openConns {
			conns = append(conns, c)
		}
		mu.Unlock()
		for _, c := range conns {
			c.Close()
		}
	}()

	backoff := 10 * time.Millisecond
loop:
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break loop
			}
			slog.Warn("Accept error", "err", err, "backoff", backoff)
			select {
			case <-ctx.Done():
				break loop
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > time.Second {
				backoff = time.Second
			}
			continue
		}
		backoff = 10 * time.Millisecond

		ip, _, err := net.SplitHostPort(conn.RemoteAddr().String())
		if err != nil {
			conn.Close()
			continue
		}

		mu.Lock()
		if perIP[ip] >= MaxConnsPerIP {
			mu.Unlock()
			conn.Close()
			slog.Warn("Per-IP connection limit reached", "remote", conn.RemoteAddr())
			continue
		}
		select {
		case sem <- struct{}{}:
		default:
			mu.Unlock()
			conn.Close()
			slog.Warn("Connection limit reached", "remote", conn.RemoteAddr())
			continue
		}
		perIP[ip]++
		openConns[conn] = struct{}{}
		mu.Unlock()

		handlers.Add(1)
		go func(c net.Conn, remoteIP string) {
			defer handlers.Done()
			defer func() {
				mu.Lock()
				delete(openConns, c)
				perIP[remoteIP]--
				if perIP[remoteIP] == 0 {
					delete(perIP, remoteIP)
				}
				mu.Unlock()
				<-sem
			}()
			handleConn(c, readTimeout)
		}(conn, ip)
	}

	waitForHandlers(&handlers)
	return nil
}

// waitForHandlers blocks until all connection handler goroutines have
// finished, with a bounded timeout so shutdown can never hang.
func waitForHandlers(handlers *sync.WaitGroup) {
	done := make(chan struct{})
	go func() {
		handlers.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		slog.Warn("Timed out waiting for connection handlers to finish")
	}
}

// handleConn services a single TCP echo connection. It reads 24-byte
// probes, validates the magic header, and echoes the payload back.
// Valid probes increment ServerProbesReceivedTotal so network-level loss
// can be measured independently of the client (TCP retransmission hides
// lost segments from the client's sent/timeout counters).
// Connections that send invalid data or exceed deadlines are closed.
func handleConn(c net.Conn, readTimeout time.Duration) {
	defer c.Close()
	if tcp, ok := c.(*net.TCPConn); ok {
		tcp.SetKeepAlive(true)
		tcp.SetKeepAlivePeriod(30 * time.Second)
	}

	bp := bufPool.Get().(*[]byte)
	defer bufPool.Put(bp)
	buf := *bp

	for {
		c.SetReadDeadline(time.Now().Add(readTimeout))

		if _, err := io.ReadFull(c, buf); err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrDeadlineExceeded) {
				slog.Debug("Server read error", "addr", c.RemoteAddr(), "err", err)
			}
			return
		}

		if string(buf[0:8]) != MagicBytes {
			slog.Warn("Invalid magic header", "addr", c.RemoteAddr())
			return
		}

		ServerProbesReceivedTotal.Inc()

		c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write(buf); err != nil {
			return
		}
	}
}
