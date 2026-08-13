package prober

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"os"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
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

	// pi-lens-ignore: go-path-traversal
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
	if err := validateTargets(targets); err != nil {
		return nil, fmt.Errorf("invalid targets: %w", err)
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

	slog.Info("Starting probing", "targets_count", len(cfg.Targets), "adaptive", cfg.Adaptive)

	SeedMetrics(cfg.Source, cfg.Targets)

	var wg sync.WaitGroup
	for _, t := range cfg.Targets {
		wg.Add(1)
		// pi-lens-ignore: go-goroutine-loop-capture
		go func(tg Target) {
			defer wg.Done()
			probeTarget(ctx, tg, cfg)
		}(t)
	}
	wg.Wait()
	return nil
}

// targetMetrics holds pre-resolved Prometheus metric handles for one
// target. Resolving each handle once avoids the label hash + map lookup
// (and its mutex) on every probe event — the hottest path in the prober.
// The handles stay valid for the lifetime of the probe loop.
type targetMetrics struct {
	sent     prometheus.Counter
	timedOut prometheus.Counter
	inflight prometheus.Gauge
	rtt      prometheus.Observer
	jitter   prometheus.Gauge
	linkUp   prometheus.Gauge
	rto      prometheus.Gauge
}

// newTargetMetrics resolves (and thereby creates) the metric series for
// a single target and returns direct handles to them.
func newTargetMetrics(source string, t Target) targetMetrics {
	return targetMetrics{
		sent:     ProbesSent.WithLabelValues(source, t.Name, t.Address),
		timedOut: ProbesTimedOut.WithLabelValues(source, t.Name, t.Address),
		inflight: ProbesInflight.WithLabelValues(source, t.Name, t.Address),
		rtt:      RTTSeconds.WithLabelValues(source, t.Name, t.Address),
		jitter:   JitterSeconds.WithLabelValues(source, t.Name, t.Address),
		linkUp:   LinkUp.WithLabelValues(source, t.Name, t.Address),
		rto:      RTOEstimate.WithLabelValues(source, t.Name, t.Address),
	}
}

// probeTarget runs the UDP probe loop for a single target until ctx is
// cancelled. There is no connection lifecycle: datagrams sent into a dead
// link vanish and time out naturally, so the loss ratio reads ~100%
// during an outage without any fabricated counters.
func probeTarget(ctx context.Context, t Target, cfg Config) {
	logger := slog.With("target", t.Name, "address", t.Address)
	stats := NewAdaptiveStats(cfg.BaseTimeout)
	m := newTargetMetrics(cfg.Source, t)

	m.linkUp.Set(0)
	for {
		// A connected UDP socket lets the kernel filter responses to
		// the server's address and gives plain Read/Write semantics.
		conn, err := net.Dial("udp", t.Address)
		if err != nil {
			// DialUDP only fails on malformed addresses, already
			// rejected by Config.Validate.
			logger.Error("Failed to open UDP socket", "err", err)
			return
		}

		// runEchoLoop recovers panics and returns them as errors; a
		// panic is per-event corruption, not a link condition, so the
		// target keeps probing rather than dying with frozen series
		// (stale counters make loss rate() queries go NaN). RTO state
		// and link_up survive the restart; the pause bounds a
		// panic-storm cycle.
		err = runEchoLoop(ctx, conn, cfg, stats, m, logger)
		if err == nil || ctx.Err() != nil {
			return // clean context cancellation
		}
		logger.Error("Echo loop panicked; restarting probe loop", "err", err)
		// pi-lens-ignore: go-time-sleep-test
		time.Sleep(time.Second)
	}
}

// runEchoLoop is the core UDP probe loop for a single target.
//
// At each interval it:
//  1. Drains buffered responses and matches them against pending sequence
//     numbers. The echoed timestamp must exactly equal the timestamp
//     written into the request payload; mismatches (corruption, replay,
//     spoofing) are ignored and the probe is left to time out as a loss.
//  2. Checks for timeouts among in-flight probes.
//  3. Sends a new probe with the next sequence number.
//
// The reader goroutine reads 24-byte datagrams with a 500 ms read
// deadline that also serves as a periodic context-cancellation check.
// On context cancellation the connection is closed via deferred close,
// which unblocks the reader.
//
// A nil return means clean context cancellation; in-flight probes are
// NOT counted as timeouts in that case. Any panic is recovered here so a
// single target's failure can never kill its probe loop (or the process).
//
// Loss is exact: UDP has no retransmission, so a probe without an echo
// pi-lens-ignore: typos, typos:unknown
// within the RTO is genuinely lost on the wire.
func runEchoLoop(
	ctx context.Context,
	conn net.Conn,
	cfg Config,
	stats *AdaptiveStats,
	m targetMetrics,
	logger *slog.Logger,
) (retErr error) {

	type response struct {
		seq  uint64
		ts   uint64
		recv time.Time
	}

	respCh := make(chan response, 100)

	// done unblocks the reader when the loop exits via panic recovery:
	// conn.Close() frees a reader blocked on the socket, but a reader
	// blocked pushing into a full respCh would otherwise leak until the
	// process exits.
	done := make(chan struct{})
	defer close(done)

	defer conn.Close()

	go func() {
		buf := make([]byte, PayloadSize)
		for {
			if ctx.Err() != nil {
				return
			}
			if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
				// Socket is gone; the loop cannot recover a deadline.
				logger.Debug("set read deadline failed", "err", err)
				return
			}

			n, err := conn.Read(buf)
			if err != nil {
				if os.IsTimeout(err) {
					continue
				}
				if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
					return
				}
				// ICMP port-unreachable and similar are not fatal for a
				// datagram socket: the probe times out naturally.
				logger.Debug("UDP read error", "err", err)
				continue
			}
			if n != PayloadSize {
				continue
			}
			if string(buf[0:8]) != MagicBytes {
				continue
			}

			seq := binary.LittleEndian.Uint64(buf[8:16])
			ts := binary.LittleEndian.Uint64(buf[16:24])

			select {
			case respCh <- response{seq: seq, ts: ts, recv: time.Now()}:
			case <-ctx.Done():
				return
			case <-done:
				return
			}
		}
	}()

	seq := uint64(0)
	buf := make([]byte, PayloadSize)

	pending := make(map[uint64]time.Time)
	// consecutiveMisses counts probes that timed out back-to-back. The
	// link counts as down only after 3 consecutive missed probes, so a
	// single lost probe or brief stall does not flap link_up.
	consecutiveMisses := 0
	// RFC 3550 jitter state (smoothed RTT delta). A gap in sequence
	// numbers — any timed-out probe — resets the estimate, so recovery
	// never feeds an artificial spike into it.
	var jitter, prevRTT float64
	var prevSeq uint64
	havePrev := false

	defer func() {
		if r := recover(); r != nil {
			logger.Error("Panic in echo loop; continuing", "panic", r)
			retErr = fmt.Errorf("panic in echo loop: %v", r)
		}
		// Probes still in flight die with the loop on cancellation
		// without counting as timeouts, but must leave the gauge.
		inflight := m.inflight
		if n := float64(len(pending)); n > 0 {
			inflight.Sub(n)
		}
	}()

	intervalTimer := time.NewTimer(0)
	defer intervalTimer.Stop()

	for {
		interval := cfg.BaseInterval
		timeout := cfg.BaseTimeout
		if cfg.Adaptive {
			// pi-lens-ignore: typos, typos:unknown
			timeout = stats.CurrentRTO()
		}

		// pi-lens-ignore: typos, typos:unknown
		m.rto.Set(timeout.Seconds())

		// Stop may race a firing timer; when Stop returns false the
		// channel is drained so Reset starts clean.
		if !intervalTimer.Stop() {
			select {
			case <-intervalTimer.C:
			default:
			}
		}
		intervalTimer.Reset(interval)

		select {
		// pi-lens-ignore: waitgroup-done-scope
		case <-ctx.Done():
			return nil
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
				m.inflight.Dec()

				rttSec := resp.recv.Sub(sentTime).Seconds()

				m.rtt.Observe(rttSec)

				// Jitter over consecutive RTT samples (RFC 3550 §6.4.1):
				// J += (|D(i-1,i)| - J)/16. Any gap in sequence numbers
				// starts the estimate over, keeping post-outage recovery
				// from spiking the gauge. The comparison uses the
				// response's own sequence number: the loop's seq is the
				// last-sent probe, so with multiple probes in flight
				// (interval < RTO) it would mislabel every response after
				// the first in a drain as a gap and pin jitter at 0.
				if havePrev && resp.seq == prevSeq+1 {
					jitter += (math.Abs(rttSec-prevRTT) - jitter) / 16
				} else {
					jitter = 0
				}
				prevRTT, prevSeq, havePrev = rttSec, resp.seq, true
				m.jitter.Set(jitter)

				if cfg.Adaptive {
					// pi-lens-ignore: gorm-n-plus-one
					stats.Update(rttSec)
				}
				consecutiveMisses = 0
				m.linkUp.Set(1)
			default:
				break Drain
			}
		}

		now := time.Now()
		var timeoutOccurred bool
		if len(pending) > 0 {
			for s, sentTime := range pending {
				if now.Sub(sentTime) > timeout {
					m.timedOut.Inc()
					m.inflight.Dec()
					delete(pending, s)
					timeoutOccurred = true
					consecutiveMisses++
				}
			}
		}

		if timeoutOccurred && cfg.Adaptive {
			stats.Backoff()
		}

		// Down after LinkUpMissThreshold consecutive probes without an
		// echo. A single lost probe or brief stall does not flap the
		// state (enterprise health-check convention).
		if consecutiveMisses >= LinkUpMissThreshold {
			m.linkUp.Set(0)
		}

		seq++
		copy(buf[0:8], MagicBytes)
		binary.LittleEndian.PutUint64(buf[8:16], seq)
		binary.LittleEndian.PutUint64(buf[16:24], uint64(now.UnixNano()))

		// Register the probe as in-flight before sending: any matching
		// response or timeout must decrement it, so a stuck link shows
		// up as a growing gauge instead of a silent stall.
		m.inflight.Inc()
		if nw, err := conn.Write(buf); err != nil {
			// Datagram never left the socket; undo the in-flight
			// increment and try again next interval.
			m.inflight.Dec()
			logger.Debug("UDP write error", "bytes", nw, "err", err)
			continue
		}

		pending[seq] = now
		m.sent.Inc()
	}
}
