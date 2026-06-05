package prober

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"
)

// Target identifies a single probe destination.
type Target struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

// LoadTargets reads and validates a JSON file containing an array of
// Target objects. Each target address is verified via ValidateTarget.
// The file must be ≤ MaxTargetsFileSize (1 MB) and contain ≤ MaxTargetsCount
// (1000) entries.
func LoadTargets(path string) ([]Target, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("read targets file: %w", err)
	}
	if info.Size() > MaxTargetsFileSize {
		return nil, fmt.Errorf("targets file too large: %d bytes (max %d)", info.Size(), MaxTargetsFileSize)
	}
	if info.Mode().IsDir() {
		return nil, fmt.Errorf("targets path is a directory, not a file")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read targets file: %w", err)
	}
	var targets []Target
	if err := json.Unmarshal(data, &targets); err != nil {
		return nil, fmt.Errorf("parse targets json: %w", err)
	}
	if len(targets) > MaxTargetsCount {
		return nil, fmt.Errorf("too many targets: %d (max %d)", len(targets), MaxTargetsCount)
	}
	for i, t := range targets {
		if err := ValidateTarget(t.Address); err != nil {
			return nil, fmt.Errorf("target %d (%q): %w", i, t.Name, err)
		}
	}
	return targets, nil
}

// RunClient starts probe loops for every target in cfg.Targets. Each
// target is probed in its own goroutine. Blocks until ctx is cancelled
// or all targets permanently fail.
func RunClient(ctx context.Context, cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}

	if len(cfg.Targets) > 1 {
		slog.Warn("Multiple targets with address label - high cardinality if addresses vary widely")
	}

	return startProbing(ctx, cfg)
}

// startProbing launches a probe goroutine for each target and waits
// for all to finish.
func startProbing(ctx context.Context, cfg Config) error {
	slog.Info("Starting probing", "targets_count", len(cfg.Targets), "adaptive", cfg.Adaptive)

	SeedMetrics(cfg.Targets)

	var wg sync.WaitGroup
	for _, t := range cfg.Targets {
		wg.Add(1)
		go func(tg Target) {
			defer wg.Done()
			probeTarget(ctx, tg, cfg)
		}(t)
	}
	wg.Wait()
	return nil
}

// probeTarget manages the connection lifecycle for a single target.
// On connection failure it backs off 2 seconds; on disconnect it
// waits 500 ms before reconnecting. A panic recovery keeps other
// targets alive.
func probeTarget(ctx context.Context, t Target, cfg Config) {
	logger := slog.With("target", t.Name, "address", t.Address)

	defer func() {
		if r := recover(); r != nil {
			logger.Error("Panic in probe loop", "panic", r)
		}
	}()

	adaptive := NewAdaptiveStats(cfg.BaseTimeout)

	getTimeout := func() time.Duration {
		if cfg.Adaptive {
			return adaptive.CurrentRTO()
		}
		return cfg.BaseTimeout
	}

	getInterval := func() time.Duration {
		return cfg.BaseInterval
	}

	for {
		if ctx.Err() != nil {
			return
		}

		conn, err := net.DialTimeout("tcp", t.Address, 5*time.Second)
		if err != nil {
			DropTotal.WithLabelValues(t.Name, t.Address).Inc()
			TimeoutTotal.WithLabelValues(t.Name, t.Address).Inc()
			SentTotal.WithLabelValues(t.Name, t.Address).Inc()
			Connected.WithLabelValues(t.Name, t.Address).Set(0)

			logger.Warn("Connect failed", "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
				continue
			}
		}

		logger.Info("Connected")
		Connected.WithLabelValues(t.Name, t.Address).Set(1)

		if tcp, ok := conn.(*net.TCPConn); ok {
			tcp.SetNoDelay(true)
		}

		err = runEchoLoop(ctx, conn, t, cfg, adaptive, getTimeout, getInterval, logger)
		Connected.WithLabelValues(t.Name, t.Address).Set(0)

		if err != nil {
			logger.Warn("Connection lost", "err", err)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// resetTimer safely stops and resets a time.Timer. It handles the
// race where a timer fires between Stop and Reset by draining the
// channel when Stop returns false.
func resetTimer(t *time.Timer, d time.Duration) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	t.Reset(d)
}

// runEchoLoop is the core probe loop for a single connection.
//
// At each interval it:
//  1. Drains buffered responses from the reader goroutine and matches
//     them against pending sequence numbers.
//  2. Checks for timeouts among in-flight probes.
//  3. Sends a new probe with the next sequence number.
//
// The reader goroutine reads 24-byte responses with a 500 ms deadline
// that also serves as a periodic context-cancellation check. On context
// cancellation the connection is closed immediately via deferred close,
// which unblocks the reader.
func runEchoLoop(
	ctx context.Context,
	conn net.Conn,
	t Target,
	cfg Config,
	stats *AdaptiveStats,
	getTimeout func() time.Duration,
	getInterval func() time.Duration,
	logger *slog.Logger,
) error {

	type response struct {
		seq  uint64
		recv time.Time
	}

	respCh := make(chan response, 100)
	errCh := make(chan error, 1)

	readerCtx, cancelReader := context.WithCancel(ctx)
	defer cancelReader()
	defer conn.Close()

	go func() {
		defer close(errCh)
		bp := bufPool.Get().(*[]byte)
		defer bufPool.Put(bp)
		buf := *bp
		for {
			if readerCtx.Err() != nil {
				return
			}
			conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))

			_, err := io.ReadFull(conn, buf)
			if err != nil {
				if errors.Is(err, os.ErrDeadlineExceeded) {
					continue
				}
				if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
					select {
					case errCh <- err:
					case <-readerCtx.Done():
					}
				}
				return
			}

			if string(buf[0:8]) != MagicBytes {
				continue
			}

			seq := binary.LittleEndian.Uint64(buf[8:16])

			select {
			case respCh <- response{seq: seq, recv: time.Now()}:
			case <-readerCtx.Done():
				return
			}
		}
	}()

	seq := uint64(0)
	bp := bufPool.Get().(*[]byte)
	defer bufPool.Put(bp)
	buf := *bp

	pending := make(map[uint64]time.Time)

	defer func() {
		count := float64(len(pending))
		if count > 0 {
			TimeoutTotal.WithLabelValues(t.Name, t.Address).Add(count)
		}
	}()

	intervalTimer := time.NewTimer(0)
	defer intervalTimer.Stop()

	for {
		interval := getInterval()
		timeout := getTimeout()

		RTOEstimate.WithLabelValues(t.Name, t.Address).Set(timeout.Seconds())

		resetTimer(intervalTimer, interval)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case err, ok := <-errCh:
			if !ok {
				return errors.New("reader closed unexpectedly")
			}
			return err
		case <-intervalTimer.C:
		}

	Drain:
		for {
			select {
			case resp := <-respCh:
				sentTime, ok := pending[resp.seq]
				if ok {
					rtt := resp.recv.Sub(sentTime)
					delete(pending, resp.seq)

					rttSec := rtt.Seconds()

					ReceivedTotal.WithLabelValues(t.Name, t.Address).Inc()
					RTTSeconds.WithLabelValues(t.Name, t.Address).Observe(rttSec)
					RTTSecondsRecent.WithLabelValues(t.Name, t.Address).Observe(rttSec)
					LastRTTSeconds.WithLabelValues(t.Name, t.Address).Set(rttSec)

					if cfg.Adaptive {
						stats.Update(rttSec)
					}
				}
			default:
				break Drain
			}
		}

		now := time.Now()
		var timeoutOccurred bool
		if len(pending) > 0 {
			for s, sentTime := range pending {
				if now.Sub(sentTime) > timeout {
					TimeoutTotal.WithLabelValues(t.Name, t.Address).Inc()
					delete(pending, s)
					timeoutOccurred = true
				}
			}
		}

		if timeoutOccurred && cfg.Adaptive {
			stats.Backoff()
		}

		seq++
		copy(buf[0:8], MagicBytes)
		binary.LittleEndian.PutUint64(buf[8:16], seq)
		binary.LittleEndian.PutUint64(buf[16:24], uint64(now.UnixNano()))

		conn.SetWriteDeadline(now.Add(timeout))
		if _, err := conn.Write(buf); err != nil {
			return err
		}

		pending[seq] = time.Now()
		SentTotal.WithLabelValues(t.Name, t.Address).Inc()
	}
}
