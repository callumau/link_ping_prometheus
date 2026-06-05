package prober

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"time"
)

// RunServer starts a TCP echo listener on addr. Each accepted connection
// is handled in its own goroutine. The server enforces a maximum of 1000
// concurrent connections; excess connections are immediately closed.
// Blocks until ctx is cancelled.
func RunServer(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	slog.Info("Echo server listening", "addr", addr)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	return ServeListener(ctx, ln)
}

// ServeListener accepts connections on ln and handles each in a
// goroutine. A semaphore limits concurrent connections to 1000.
// Blocks until ctx is cancelled or ln is closed.
func ServeListener(ctx context.Context, ln net.Listener) error {
	sem := make(chan struct{}, 1000)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			slog.Warn("Accept error", "err", err)
			continue
		}
		select {
		case sem <- struct{}{}:
		default:
			conn.Close()
			slog.Warn("Connection limit reached", "remote", conn.RemoteAddr())
			continue
		}
		go func(c net.Conn) {
			defer func() { <-sem }()
			handleConn(c)
		}(conn)
	}
}

// handleConn services a single TCP echo connection. It reads 24-byte
// probes, validates the magic header, and echoes the payload back.
// Connections that send invalid data or exceed deadlines are closed.
func handleConn(c net.Conn) {
	defer c.Close()
	if tcp, ok := c.(*net.TCPConn); ok {
		tcp.SetKeepAlive(true)
		tcp.SetKeepAlivePeriod(30 * time.Second)
	}

	bp := bufPool.Get().(*[]byte)
	defer bufPool.Put(bp)
	buf := *bp

	for {
		c.SetReadDeadline(time.Now().Add(10 * time.Second))

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

		c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write(buf); err != nil {
			return
		}
	}
}
