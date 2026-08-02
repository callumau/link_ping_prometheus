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
// (1000) entries. Target names must be unique: they are Prometheus label
// values, and duplicates would produce ambiguous metric series.
func LoadTargets(path string) ([]Target, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("read targets file: %w", err)
	}
	if info.Mode().IsDir() {
		return nil, fmt.Errorf("targets path is a directory, not a file")
	}
	if info.Size() > MaxTargetsFileSize {
		return nil, fmt.Errorf("targets file too large: %d bytes (max %d)", info.Size(), MaxTargetsFileSize)
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
	seen := make(map[string]struct{}, len(targets))
	for i, t := range targets {
		if err := ValidateTarget(t.Address); err != nil {
			return nil, fmt.Errorf("target %d (%q): %w", i, t.Name, err)
		}
		if err := ValidateTargetName(t.Name); err != nil {
			return nil, fmt.Errorf("target %d: %w", i, err)
		}
		if _, dup := seen[t.Name]; dup {
			return nil, fmt.Errorf("target %d: duplicate name %q", i, t.Name)
		}
		seen[t.Name] = struct{}{}
	}
	return targets, nil
}

// RunClient starts probe loops for every target in cfg.Targets. Each
// target is probed in its own goroutine. Blocks until ctx is cancelled.
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

// dialTarget opens a TCP connection, honouring ctx cancellation so
// shutdown is not blocked by an in-flight dial.
func dialTarget(ctx context.Context, address string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 5 * time.Second}
	return d.DialContext(ctx, "tcp", address)
}

// probeTarget manages the connection lifecycle for a single target.
// Dial failures back off 2 seconds; lost connections wait 500 ms before
// reconnecting. A panic in the echo loop is recovered and treated as a
// connection loss — the target keeps being probed.
func probeTarget(ctx context.Context, t Target, cfg Config) {
	logger := slog.With("target", t.Name, "address", t.Address)

	stats := NewAdaptiveStats(cfg.BaseTimeout)

	for {
		if ctx.Err() != nil {
			return
		}

		conn, err := dialTarget(ctx, t.Address)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			ConnectFailures.WithLabelValues(t.Name, t.Address).Inc()
			LinkUp.WithLabelValues(t.Name, t.Address).Set(0)
			logger.Warn("Connect failed", "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
				continue
			}
		}

		logger.Info("Connected")
		LinkUp.WithLabelValues(t.Name, t.Address).Set(1)

		if tcp, ok := conn.(*net.TCPConn); ok {
			tcp.SetNoDelay(true)
		}

		err = runEchoLoop(ctx, conn, t, cfg, stats, logger)
		LinkUp.WithLabelValues(t.Name, t.Address).Set(0)

		if err != nil {
			ConnectionsDropped.WithLabelValues(t.Name, t.Address).Inc()
			logger.Warn("Connection lost", "err", err)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// runEchoLoopGuarded recovers panics from runEchoLoop so a single
// target's failure can never kill its probe loop (or the process).
// A panic is converted to an error, which the caller treats as a
// connection drop followed by a reconnect.
func runEchoLoopGuarded(ctx context.Context, conn net.Conn, t Target, cfg Config, stats *AdaptiveStats, logger *slog.Logger) (err error) {
	defer func() {
		if r := recover(); r != nil {
			logger.Error("Panic in echo loop; reconnecting", "panic", r)
			err = fmt.Errorf("panic in echo loop: %v", r)
		}
	}()
	return runEchoLoop(ctx, conn, t, cfg, stats, logger)
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
//     them against pending sequence numbers. The echoed timestamp must
//     exactly equal the timestamp written into the request payload;
//     mismatches (corruption, replay, spoofing) are ignored and the
//     probe is left to time out as a loss.
//  2. Checks for timeouts among in-flight probes.
//  3. Sends a new probe with the next sequence number.
//
// The reader goroutine reads 24-byte responses with a 500 ms deadline
// that also serves as a periodic context-cancellation check. On context
// cancellation the connection is closed immediately via deferred close,
// which unblocks the reader.
//
// A nil return means clean context cancellation; in-flight probes are
// NOT counted as timeouts in that case. Any non-nil return (reader
// error, write error, panic via the recover in the deferred flush)
// flushes in-flight probes to ProbesTimedOut because the connection state
// is no longer trustworthy. Responses that already arrived before the
// failure are matched and counted as received first.
//
// A panic is recovered here so a single target's failure can never kill
// its probe loop (or the process); it is converted to an error, which
// the caller treats as a connection drop followed by a reconnect.
func runEchoLoop(
	ctx context.Context,
	conn net.Conn,
	t Target,
	cfg Config,
	stats *AdaptiveStats,
	logger *slog.Logger,
) (retErr error) {

	type response struct {
		seq  uint64
		ts   uint64
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
			ts := binary.LittleEndian.Uint64(buf[16:24])

			select {
			case respCh <- response{seq: seq, ts: ts, recv: time.Now()}:
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
		if r := recover(); r != nil {
			logger.Error("Panic in echo loop; reconnecting", "panic", r)
			retErr = fmt.Errorf("panic in echo loop: %v", r)
		}
		if retErr == nil {
			return
		}
		// Drain responses that already arrived so they count as received,
		// not as timeouts caused by the connection failure.
		for {
			select {
			case resp := <-respCh:
				sentTime, ok := pending[resp.seq]
				if !ok {
					continue
				}
				if resp.ts != uint64(sentTime.UnixNano()) {
					continue
				}
				delete(pending, resp.seq)
				ProbesReceived.WithLabelValues(t.Name, t.Address).Inc()
			default:
				if count := float64(len(pending)); count > 0 {
					ProbesTimedOut.WithLabelValues(t.Name, t.Address).Add(count)
				}
				return
			}
		}
	}()

	intervalTimer := time.NewTimer(0)
	defer intervalTimer.Stop()

	for {
		interval := cfg.BaseInterval
		timeout := cfg.BaseTimeout
		if cfg.Adaptive {
			timeout = stats.CurrentRTO()
		}

		RTOEstimate.WithLabelValues(t.Name, t.Address).Set(timeout.Seconds())

		resetTimer(intervalTimer, interval)

		select {
		case <-ctx.Done():
			return nil
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
				if !ok {
					continue
				}
				if resp.ts != uint64(sentTime.UnixNano()) {
					// Echoed payload does not match what we sent:
					// corruption, replay, or spoofing. Leave the probe
					// pending so it is counted as a loss on timeout.
					logger.Debug("Rejected response with mismatched timestamp", "seq", resp.seq)
					continue
				}
				delete(pending, resp.seq)

				rttSec := resp.recv.Sub(sentTime).Seconds()

				ProbesReceived.WithLabelValues(t.Name, t.Address).Inc()
				RTTRecent.WithLabelValues(t.Name, t.Address).Observe(rttSec)
				LastRTT.WithLabelValues(t.Name, t.Address).Set(rttSec)

				if cfg.Adaptive {
					stats.Update(rttSec)
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
					ProbesTimedOut.WithLabelValues(t.Name, t.Address).Inc()
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

		pending[seq] = now
		ProbesSent.WithLabelValues(t.Name, t.Address).Inc()
	}
}
