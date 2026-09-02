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
	Name     string        `json:"name"`
	Address  string        `json:"address"`
	Interval time.Duration `json:"interval,omitempty"`
	Timeout  time.Duration `json:"timeout,omitempty"`
}

// MarshalJSON encodes Interval/Timeout as duration strings (e.g. "500ms")
// when non-zero, omitting them otherwise so the global config is used.
func (t Target) MarshalJSON() ([]byte, error) {
	type out struct {
		Name     string  `json:"name"`
		Address  string  `json:"address"`
		Interval *string `json:"interval,omitempty"`
		Timeout  *string `json:"timeout,omitempty"`
	}
	o := out{Name: t.Name, Address: t.Address}
	if t.Interval != 0 {
		s := t.Interval.String()
		o.Interval = &s
	}
	if t.Timeout != 0 {
		s := t.Timeout.String()
		o.Timeout = &s
	}
	return json.Marshal(o)
}

// UnmarshalJSON decodes Interval/Timeout from duration strings (e.g. "500ms")
// when present; absent or empty means use global (0). Numbers are rejected
// to avoid ambiguity (use string "500ms").
func (t *Target) UnmarshalJSON(data []byte) error {
	type raw struct {
		Name     string          `json:"name"`
		Address  string          `json:"address"`
		Interval json.RawMessage `json:"interval"`
		Timeout  json.RawMessage `json:"timeout"`
	}
	var r raw
	if err := json.Unmarshal(data, &r); err != nil {
		return err
	}
	t.Name = r.Name
	t.Address = r.Address
	t.Interval = 0
	t.Timeout = 0
	if len(r.Interval) != 0 && string(r.Interval) != "null" {
		var s string
		if err := json.Unmarshal(r.Interval, &s); err != nil {
			return fmt.Errorf("interval must be a duration string like \"500ms\": %w", err)
		}
		if s != "" {
			d, err := time.ParseDuration(s)
			if err != nil {
				return fmt.Errorf("invalid interval %q: %w", s, err)
			}
			t.Interval = d
		}
	}
	if len(r.Timeout) != 0 && string(r.Timeout) != "null" {
		var s string
		if err := json.Unmarshal(r.Timeout, &s); err != nil {
			return fmt.Errorf("timeout must be a duration string like \"1s\": %w", err)
		}
		if s != "" {
			d, err := time.ParseDuration(s)
			if err != nil {
				return fmt.Errorf("invalid timeout %q: %w", s, err)
			}
			t.Timeout = d
		}
	}
	return nil
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
	if len(data) > MaxTargetsFileSize {
		return nil, fmt.Errorf("targets file too large after read: %d bytes (max %d)", len(data), MaxTargetsFileSize)
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

	if !cfg.Adaptive && cfg.BaseTimeout < 200*time.Millisecond {
		slog.Warn("Fixed timeout below 200ms with adaptive disabled; short timeouts cause spurious loss on moderate-RTT links",
			"timeout", cfg.BaseTimeout, "adaptive", cfg.Adaptive, "fix", "enable -adaptive or increase -timeout to >=200ms")
	}
	if cfg.BaseInterval >= cfg.BaseTimeout {
		slog.Warn("Probe interval >= timeout; probes will queue and loss will read artificially high",
			"interval", cfg.BaseInterval, "timeout", cfg.BaseTimeout, "fix", "set -interval < -timeout (e.g. interval 500ms, timeout 1s)")
	}
	effectiveReconnect := ReconnectInterval
	if cfg.ReconnectInterval != 0 {
		effectiveReconnect = cfg.ReconnectInterval
	}
	if effectiveReconnect != 0 && effectiveReconnect < cfg.BaseInterval {
		slog.Warn("Reconnect interval < probe interval; reconnect will be delayed until next probe",
			"reconnect_interval", effectiveReconnect, "interval", cfg.BaseInterval)
	}
	// Per-target interval/timeout warnings (0 means use global, already validated >0 when set).
	for _, tg := range cfg.Targets {
		effInterval := cfg.BaseInterval
		if tg.Interval != 0 {
			effInterval = tg.Interval
		}
		effTimeout := cfg.BaseTimeout
		if tg.Timeout != 0 {
			effTimeout = tg.Timeout
		}
		if effInterval >= effTimeout {
			slog.Warn("Per-target interval >= timeout; probes will queue",
				"target", tg.Name, "interval", effInterval, "timeout", effTimeout)
		}
	}

	// Warn when this client's probe rate would exceed the echo server's
	// per-IP cap: the server silently drops over-cap probes, which the
	// client would read as artificial packet loss.
	if pps := float64(len(cfg.Targets)) / cfg.BaseInterval.Seconds(); pps > float64(MaxPktsPerIP) {
		slog.Warn("Probe rate exceeds the server per-IP echo cap; probes will be dropped and loss will read artificially high",
			"expected_pkts_per_sec", pps, "server_cap_per_ip", MaxPktsPerIP,
			"fix", "raise MaxPktsPerIP on the server or reduce targets/interval")
	}

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

// maxConsecutiveWriteFails bounds how many successive local send errors
// are treated as transient before the target is marked down (link_up=0)
// at Error level — a frozen link_up while nothing is being probed is the
// worst failure mode for a monitor.
const maxConsecutiveWriteFails = 3

// errReconnect is a sentinel returned by runEchoLoop to request a socket
// re-dial (DNS re-resolution) once ReconnectInterval has elapsed. It is
// not a panic and is returned only when no probes are in flight.
var errReconnect = errors.New("periodic reconnect")

// dialUDP dials a UDP socket. Kept as a package variable so tests can
// substitute a failing dialer to exercise the dial-retry path
// deterministically, without a flaky DNS dependency.
var dialUDP = func(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

// probeLoopState carries per-target state that must survive socket
// re-dials (periodic DNS re-resolution): jitter, link_up miss counting,
// and the sequence counter. seq lives here so it stays monotonic across
// reconnects — the reconnect only happens with an empty pending set, so
// the next sequence is naturally prev+1 and the RFC 3550 gap check does
// not spuriously reset jitter.
type probeLoopState struct {
	seq               uint64
	consecutiveMisses int
	jitter            float64
	prevRTT           float64
	prevSeq           uint64
	havePrev          bool
}

// probeTarget runs the UDP probe loop for a single target until ctx is
// cancelled. There is no connection lifecycle: datagrams sent into a dead
// link vanish and time out naturally, so the loss ratio reads ~100%
// during an outage without any fabricated counters. The loop does re-dial
// periodically (only when idle) so a target hostname that changes IP via
// DNS is re-resolved, and a dial failure — including a transient DNS
// outage at startup — is retried rather than killing the target.
func probeTarget(ctx context.Context, t Target, cfg Config) {
	// Per-target overrides: Interval/Timeout 0 means use global.
	effectiveCfg := cfg
	if t.Interval != 0 {
		effectiveCfg.BaseInterval = t.Interval
	}
	if t.Timeout != 0 {
		effectiveCfg.BaseTimeout = t.Timeout
	}
	logger := slog.With("target", t.Name, "address", t.Address)
	stats := NewAdaptiveStats(effectiveCfg.BaseTimeout)
	m := newTargetMetrics(cfg.Source, t)
	state := &probeLoopState{}
	cfg = effectiveCfg

	m.linkUp.Set(0)
	for {
		// A connected UDP socket lets the kernel filter responses to
		// the server's address and gives plain Read/Write semantics.
		conn, err := dialUDP(ctx, "udp", t.Address)
		if err != nil {
			// Dial fails on DNS resolution failure as well as malformed
			// addresses (already rejected by Config.Validate). Retry: a
			// transient lookup failure must not strand the target with
			// frozen metric series.
			logger.Error("Failed to open UDP socket; retrying", "err", err)
			// While the dial-retry loop runs, no probes are in flight and
			// consecutiveMisses cannot advance, so a re-established session
			// would keep showing a stale link_up=1 across a prolonged
			// DNS/interface outage. Probing is structurally impossible here.
			m.linkUp.Set(0)
			t := time.NewTimer(time.Second)
			select {
			// pi-lens-ignore: waitgroup-done-scope
			case <-ctx.Done():
				if !t.Stop() {
					<-t.C
				}
				return
			case <-t.C:
			}
			continue
		}

		// runEchoLoop recovers panics and returns them as errors; a
		// panic is per-event corruption, not a link condition, so the
		// target keeps probing rather than dying with frozen series
		// (stale counters make loss rate() queries go NaN). RTO state,
		// link_up and jitter survive the restart; the pause bounds a
		// panic-storm cycle.
		err = runEchoLoop(ctx, conn, cfg, stats, m, state, logger)
		if err == nil || ctx.Err() != nil {
			return // clean context cancellation
		}
		if errors.Is(err, errReconnect) {
			// Periodic re-dial to re-resolve DNS; not an error.
			continue
		}
		logger.Error("Echo loop panicked; restarting probe loop", "err", err)
		t := time.NewTimer(time.Second)
		select {
		// pi-lens-ignore: waitgroup-done-scope
		case <-ctx.Done():
			if !t.Stop() {
				<-t.C
			}
			return
		case <-t.C:
		}
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
	state *probeLoopState,
	logger *slog.Logger,
) (retErr error) {

	type response struct {
		seq  uint64
		ts   uint64
		recv time.Time
	}

	// respCh buffers in-flight responses between the reader and the drain.
	// Size scales with expected max inflight (timeout/interval) so aggressive
	// intervals (e.g. 10ms/3s => 300) do not stall the reader. Clamped 100..1000.
	bufSize := 100
	if cfg.BaseInterval > 0 {
		n := int(cfg.BaseTimeout/cfg.BaseInterval) + 20
		if n > bufSize {
			bufSize = n
		}
		if bufSize > 1000 {
			bufSize = 1000
		}
	}
	respCh := make(chan response, bufSize)

	// done unblocks the reader when the loop exits via panic recovery:
	// conn.Close() frees a reader blocked on the socket, but a reader
	// blocked pushing into a full respCh would otherwise leak until the
	// process exits.
	done := make(chan struct{})
	defer close(done)

	defer conn.Close()

	go func() {
		// Read into a buffer larger than the payload so an oversized
		// datagram is not silently truncated to PayloadSize by the kernel
		// and mistaken for a valid probe (Read truncates to the buffer).
		buf := make([]byte, MaxDatagramSize)
		deadlineFails := 0
		for {
			if ctx.Err() != nil {
				return
			}
			if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
				// A deadline that cannot be set means the socket is unusable;
				// bail out instead of hot-spinning on a guaranteed error. The
				// periodic reconnect re-creates the reader.
				deadlineFails++
				if deadlineFails >= 3 {
					logger.Error("SetReadDeadline persistently failing; stopping reader", "err", err)
					return
				}
				continue
			}
			deadlineFails = 0

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
			expectedSize := PayloadSize
			if cfg.EchoSecret != "" {
				expectedSize = PayloadSizeWithHMAC
			}
			if n != expectedSize {
				continue
			}
			if string(buf[0:8]) != MagicBytes {
				continue
			}

			seq := binary.LittleEndian.Uint64(buf[8:16])
			ts := binary.LittleEndian.Uint64(buf[16:24])
			if cfg.EchoSecret != "" {
				if !validHMAC(cfg.EchoSecret, seq, ts, buf[24:32]) {
					continue
				}
			}

			select {
			case respCh <- response{seq: seq, ts: ts, recv: time.Now()}:
			case <-ctx.Done():
				return
			case <-done:
				return
			}
		}
	}()

	var warnedSlowRTT bool
	writeFails := 0
	payloadSize := PayloadSize
	if cfg.EchoSecret != "" {
		payloadSize = PayloadSizeWithHMAC
	}
	buf := make([]byte, payloadSize)
	pending := make(map[uint64]time.Time)
	pendingHighWater := 0
	// started bounds the socket lifetime: once ReconnectInterval has
	// elapsed and no probes are in flight, the loop returns errReconnect
	// so the caller re-dials and re-resolves DNS.
	started := time.Now()

	defer func() {
		if r := recover(); r != nil {
			logger.Error("Panic in echo loop; continuing", "panic", r)
			retErr = fmt.Errorf("panic in echo loop: %v", r)
			// Abandoned probes can never match on this socket, so they
			// are losses, not silent drops: count them as timed out so
			// sent = rtt_count + timed_out + inflight keeps balancing
			// across the restart (same treatment as the reconnect flush).
			m.timedOut.Add(float64(len(pending)))
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

				// With a fixed (non-adaptive) timeout, a true RTT above the
				// timeout makes every probe read as loss — indistinguishable
				// from a dead link. Warn once so the operator can tell them
				// apart; adaptive RTO tracks the real RTT instead.
				if !cfg.Adaptive && !warnedSlowRTT && rttSec > cfg.BaseTimeout.Seconds() {
					warnedSlowRTT = true
					logger.Warn("Observed RTT exceeds fixed timeout; such probes all read as loss",
						"rtt_seconds", rttSec, "timeout", cfg.BaseTimeout.String(),
						"fix", "enable adaptive RTO or raise -timeout")
				}

				m.rtt.Observe(rttSec)

				// Jitter over consecutive RTT samples (RFC 3550 §6.4.1):
				// J += (|D(i-1,i)| - J)/16. Any gap in sequence numbers
				// starts the estimate over, keeping post-outage recovery
				// from spiking the gauge. The comparison uses the
				// response's own sequence number: the loop's seq is the
				// last-sent probe, so with multiple probes in flight
				// (interval < RTO) it would mislabel every response after
				// the first in a drain as a gap and pin jitter at 0.
				if state.havePrev && resp.seq == state.prevSeq+1 {
					state.jitter += (math.Abs(rttSec-state.prevRTT) - state.jitter) / 16
				} else {
					state.jitter = 0
				}
				state.prevRTT, state.prevSeq, state.havePrev = rttSec, resp.seq, true
				m.jitter.Set(state.jitter)

				if cfg.Adaptive {
					// pi-lens-ignore: gorm-n-plus-one
					stats.Update(rttSec)
				}
				state.consecutiveMisses = 0
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
					state.consecutiveMisses++
				}
			}
		}

		if timeoutOccurred && cfg.Adaptive {
			stats.Backoff()
		}

		// S6: shrink pending map after stall to avoid retaining high-water capacity for lifetime of runEchoLoop (5m). Only reallocates when map was large (>512) and has now drained.
		if len(pending) > pendingHighWater {
			pendingHighWater = len(pending)
		} else if len(pending) == 0 && pendingHighWater > 512 {
			pending = make(map[uint64]time.Time)
			pendingHighWater = 0
		}

		// Down after LinkUpMissThreshold consecutive probes without an
		// echo. A single lost probe or brief stall does not flap the
		// state (enterprise health-check convention).
		if state.consecutiveMisses >= LinkUpMissThreshold {
			m.linkUp.Set(0)
		}

		// Reconnect to re-resolve DNS once the socket has lived long
		// enough. Normally the pending set is empty here, but when the
		// probe interval is shorter than the RTO (interval < RTO) probes
		// are perpetually in flight and pending never drains, which
		// would otherwise starve re-resolution forever and strand a
		// target on a stale IP after a DNS change. In-flight probes can
		// no longer receive their echo once this socket closes, so they
		// are counted as timed out to preserve the
		// sent/rtt/timedout/inflight balance. They deliberately do NOT
		// count toward link_up misses (consecutiveMisses): they were cut
		// short by the socket swap, not lost on the wire.
		reconnectInterval := ReconnectInterval
		if cfg.ReconnectInterval != 0 {
			reconnectInterval = cfg.ReconnectInterval
		}
		if reconnectInterval != 0 && time.Since(started) >= reconnectInterval {
			for s := range pending {
				m.timedOut.Inc()
				m.inflight.Dec()
				delete(pending, s)
			}
			return errReconnect
		}

		// Reserve, but do not yet consume, the sequence number: a failed
		// write never put the datagram on the wire, so burning its seq
		// would look like a loss to the RFC 3550 gap check and spuriously
		// reset the jitter estimate. Consume it only after a successful
		// write.
		seq := state.seq + 1
		copy(buf[0:8], MagicBytes)
		binary.LittleEndian.PutUint64(buf[8:16], seq)
		ts := uint64(now.UnixNano())
		binary.LittleEndian.PutUint64(buf[16:24], ts)
		if cfg.EchoSecret != "" {
			h := computeHMAC(cfg.EchoSecret, seq, ts)
			copy(buf[24:32], h[:])
		}

		// Send first, then register: registering in-flight only after a
		// successful write means a failed or panicking write can never
		// orphan a gauge increment (every pending entry has exactly one
		// matching inflight unit, so any exit-path flush balances).
		if _, err := conn.Write(buf); err != nil {
			writeFails++
			if writeFails == maxConsecutiveWriteFails {
				// Sustained local write failures mean nothing is being
				// probed while consecutiveMisses stays frozen — the worst
				// failure mode is link_up stuck at 1. Escalate once at
				// Error (Debug is invisible at default verbosity) and
				// reflect reality in the gauge.
				logger.Error("Persistent UDP write failures; marking link down",
					"consecutive_failures", writeFails, "err", err)
				m.linkUp.Set(0)
			}
			continue
		}
		writeFails = 0
		state.seq = seq

		pending[state.seq] = now
		m.inflight.Inc()
		m.sent.Inc()
	}
}
