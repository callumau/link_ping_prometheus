package prober

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// targetMetrics holds pre-resolved Prometheus metric handles for one
// target. Resolving each handle once avoids the label hash + map lookup
// (and its mutex) on every probe event — the hottest path in the prober.
// The handles stay valid for the lifetime of the probe loop.
type targetMetrics struct {
	sent      prometheus.Counter
	sendErr   prometheus.Counter
	throttled prometheus.Counter
	corrupted prometheus.Counter
	timedOut  prometheus.Counter
	inflight  prometheus.Gauge
	rtt       prometheus.Observer
	jitter    prometheus.Gauge
	linkUp    prometheus.Gauge
	rto       prometheus.Gauge
	srtt      prometheus.Gauge
	// MTU sweep handles (separate counter namespace; see mtu.go).
	mtuSent prometheus.Counter
	mtuLost prometheus.Counter
	pathMTU prometheus.Gauge
	// Internal-error handles, pre-resolved with their reason so the failure
	// paths do not pay a label lookup (and never race the vec mutex).
	internalPanic      prometheus.Counter
	internalReaderDead prometheus.Counter
	internalDialRetry  prometheus.Counter
	// name/addr label the /status snapshot; status receives it (nil-safe).
	name   string
	addr   string
	status *StatusRegistry
}

// newTargetMetrics resolves (and thereby creates) the metric series for
// a single target and returns direct handles to them.
func newTargetMetrics(source string, t Target) targetMetrics {
	return targetMetrics{
		sent:               ProbesSent.WithLabelValues(source, t.Name, t.Address),
		sendErr:            SendErrors.WithLabelValues(source, t.Name, t.Address),
		throttled:          ProbesThrottled.WithLabelValues(source, t.Name, t.Address),
		corrupted:          CorruptedProbes.WithLabelValues(source, t.Name, t.Address),
		timedOut:           ProbesTimedOut.WithLabelValues(source, t.Name, t.Address),
		inflight:           ProbesInflight.WithLabelValues(source, t.Name, t.Address),
		rtt:                RTTSeconds.WithLabelValues(source, t.Name, t.Address),
		jitter:             JitterSeconds.WithLabelValues(source, t.Name, t.Address),
		linkUp:             LinkUp.WithLabelValues(source, t.Name, t.Address),
		rto:                RTOEstimate.WithLabelValues(source, t.Name, t.Address),
		srtt:               SRTTSeconds.WithLabelValues(source, t.Name, t.Address),
		mtuSent:            MTUProbesSent.WithLabelValues(source, t.Name, t.Address),
		mtuLost:            MTUProbesLost.WithLabelValues(source, t.Name, t.Address),
		pathMTU:            PathMTUBytes.WithLabelValues(source, t.Name, t.Address),
		internalPanic:      ProberInternalErrors.WithLabelValues(source, t.Name, t.Address, "panic"),
		internalReaderDead: ProberInternalErrors.WithLabelValues(source, t.Name, t.Address, "reader_dead"),
		internalDialRetry:  ProberInternalErrors.WithLabelValues(source, t.Name, t.Address, "dial_retry"),
		name:               t.Name,
		addr:               t.Address,
	}
}

// emitTargetStatus writes the /status snapshot for one target. It is the
// single definition of the snapshot shape, shared by runEchoLoop's
// per-interval refresh and the link_up transitions that happen OUTSIDE that
// refresh (persistent write failures, reader death, panic restart). Without
// the out-of-band emissions /status reports link_up:true for up to a full
// interval after the gauge already dropped to 0 — the frozen-green failure
// mode, surfaced at /status instead of in Prometheus. Nil-safe: the
// registry's Update is nil-receiver-safe.
func emitTargetStatus(m targetMetrics, state *probeLoopState, stats *AdaptiveStats, rto time.Duration, sendFailures, pending int) {
	// SocketAge is meaningless before the first dial (zero time.Time) and
	// LastEchoAge is -1 until the first matched echo.
	socketAge := 0.0
	if !state.socketStart.IsZero() {
		socketAge = time.Since(state.socketStart).Seconds()
	}
	lastEchoAge := -1.0
	if !state.lastEcho.IsZero() {
		lastEchoAge = time.Since(state.lastEcho).Seconds()
	}
	m.status.Update(TargetStatus{
		Name:               m.name,
		Address:            m.addr,
		LinkUp:             state.linkUp,
		SendFailures:       sendFailures,
		Pending:            pending,
		ConsecutiveMisses:  state.consecutiveMisses,
		RTOSeconds:         rto.Seconds(),
		JitterSeconds:      state.jitter,
		SRTTSeconds:        stats.SRTT().Seconds(),
		LastSeq:            state.seq,
		SocketAgeSeconds:   socketAge,
		PathMTUBytes:       int(state.pathMTU.Load()),
		LastEchoAgeSeconds: lastEchoAge,
	})
}

// deleteTargetSeries withdraws every client-side series for a target that
// was REMOVED from the targets file. Registration in a Prometheus vec is
// permanent: staleness only kicks in once a series DISAPPEARS from a
// scrape, and a still-registered series keeps being exported at its last
// value — a decommissioned target would export link_up=1 forever. Deleting
// is the only way to actually withdraw it. A CHANGED target (same name,
// new address/interval/timeout) keeps its series: it is still the same
// monitored endpoint, so the counters must stay continuous.
func deleteTargetSeries(source string, t Target) {
	labels := prometheus.Labels{"source": source, "target": t.Name, "address": t.Address}
	ProbesSent.DeletePartialMatch(labels)
	SendErrors.DeletePartialMatch(labels)
	ProbesThrottled.DeletePartialMatch(labels)
	CorruptedProbes.DeletePartialMatch(labels)
	ProberInternalErrors.DeletePartialMatch(labels)
	ProbesTimedOut.DeletePartialMatch(labels)
	ProbesInflight.DeletePartialMatch(labels)
	RTTSeconds.DeletePartialMatch(labels)
	JitterSeconds.DeletePartialMatch(labels)
	LinkUp.DeletePartialMatch(labels)
	RTOEstimate.DeletePartialMatch(labels)
	SRTTSeconds.DeletePartialMatch(labels)
	MTUProbesSent.DeletePartialMatch(labels)
	MTUProbesLost.DeletePartialMatch(labels)
	PathMTUBytes.DeletePartialMatch(labels)
}

// responseBufferCapacity computes respCh's buffer size for one probe
// loop. A var-free function so tests can pin the sizing rule: the static
// pair is clamped 100..maxPendingWindow, and -adaptive pins the channel
// to maxPendingWindow because the applied RTO (floor max(200ms, 2*SRTT))
// can legitimately hold the full window in flight.
func responseBufferCapacity(cfg Config) int {
	if cfg.Adaptive {
		return maxPendingWindow
	}
	bufSize := 100
	if cfg.BaseInterval > 0 {
		n := int(cfg.BaseTimeout/cfg.BaseInterval) + 20
		if n > bufSize {
			bufSize = n
		}
		if bufSize > maxPendingWindow {
			bufSize = maxPendingWindow
		}
	}
	return bufSize
}

// sleepCtx sleeps d, returning false when ctx is cancelled first. Shared
// by the three probeTarget retry pauses (dial failure, reader death,
// panic restart), which were three copies of the same bounded timer
// select.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// stopDrain resets a timer and drains a possibly-queued tick so Reset
// starts clean (Go's Reset contract), used by the probe ticker and the MTU
// sweep timer.
func stopDrain(t *time.Timer) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
}

// maxConsecutiveWriteFails bounds how many successive local send errors
// are treated as transient before the target is marked down (link_up=0)
// at Error level — a frozen link_up while nothing is being probed is the
// worst failure mode for a monitor.
const maxConsecutiveWriteFails = 3

// maxConsecutiveReadFails bounds successive UNEXPECTED socket Read errors in
// the reader goroutine. ICMP-derived errors are classified out (see
// isPeerUnreachable) because a down peer is a normal monitoring condition;
// what remains is a genuinely misbehaving socket, which must not spin the
// reader at Debug level forever — the reader exits and the main loop re-dials.
const maxConsecutiveReadFails = 10

// isPeerUnreachable reports whether err is an ICMP-derived peer/path failure
// rather than a local socket failure. On a connected UDP socket these arrive
// as ECONNREFUSED (Linux port-unreachable), ECONNRESET (Windows reports the
// same condition this way) or EHOSTUNREACH/ENETUNREACH (a router replied with
// unreachable). The probe times out naturally and must keep its reader.
//
// The errno set is per-platform (peerUnreachableErrnos, in the
// unreachable_*.go files): Windows reports raw winsock codes, so a single
// cross-platform list built from the portable syscall constants would compile
// everywhere and never match there.
func isPeerUnreachable(err error) bool {
	for _, target := range peerUnreachableErrnos {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

// errReconnect is a sentinel returned by runEchoLoop to request a socket
// re-dial (DNS re-resolution) once ReconnectInterval has elapsed. It is
// not a panic and is returned only when no probes are in flight.
var errReconnect = errors.New("periodic reconnect")

// errReaderDead is returned by runEchoLoop when its reader goroutine has
// died: with nobody reading the socket every probe is a guaranteed
// timeout, so the caller re-dials immediately instead of probing a socket
// whose responses are silently discarded.
var errReaderDead = errors.New("UDP reader stopped")

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
	// linkUp mirrors the link_up gauge for the /status snapshot (set at
	// the same sites as the gauge); socketStart is the current socket's
	// dial time for the age readout. lastEcho is the receive time of the
	// most recent matched echo (main loop goroutine only).
	linkUp      bool
	socketStart time.Time
	lastEcho    time.Time
	// pathMTU is written by the MTU sweep goroutine and read by the main
	// loop for the /status snapshot; atomic because of the two goroutines.
	pathMTU atomic.Int64
	// rtoNs is the timeout the main loop is currently applying, in
	// nanoseconds, published for the MTU sweep's probe deadline (see
	// mtuDeadline): the sweep must wait as long as the main loop does, or an
	// adaptive link whose RTT exceeds the configured -timeout could never
	// discover anything. Atomic for the same two-goroutine reason.
	rtoNs atomic.Int64
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
	m.status = cfg.Status
	state := &probeLoopState{}
	cfg = effectiveCfg
	if cfg.MTUSweep > 0 {
		// Own socket and counter namespace: MTU probing stays outside the
		// main loss balance entirely. The sweep goroutine is TRACKED: the
		// deferred join below keeps probeTarget from returning before the
		// sweep has wound down, so stop()'s bounded join and the
		// straggler/shutdown joins cover it too. With the sliced read
		// arms in readEcho (mtuReadArm) the sweep exits within one arm
		// (~500ms) of cancellation, so the join cannot stall a reload.
		// Previously the sweep was fire-and-forget and could outlive its
		// loop by a full applied RTO — duplicated DF probes and a stale
		// link_path_mtu_bytes overwrite on a kept-series restart.
		sweepDone := make(chan struct{})
		go func() {
			defer close(sweepDone)
			runMTUSweep(ctx, t, cfg, m, state, logger)
		}()
		defer func() {
			// Only reached while the loop is exiting for restart/shutdown;
			// the sweep holds its own ctx copy and its reads are sliced,
			// so this wait is bounded by mtuReadArm plus socket close.
			<-sweepDone
		}()
	}
	// Throttle dial-failure logging: first failure logs immediately, then
	// at most once per minute (a DNS outage retries every second).
	var lastDialLog time.Time

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
			// While the dial-retry loop runs, no probes are in flight and
			// consecutiveMisses cannot advance, so a re-established session
			// would keep showing a stale link_up=1 across a prolonged
			// DNS/interface outage. Probing is structurally impossible here.
			m.linkUp.Set(0)
			state.linkUp = false
			m.internalDialRetry.Inc()
			// Record the stuck-dialing state so /status shows targets that
			// cannot even open a socket (DNS outage, firewall). Carry the MTU
			// and last-echo age too so /status agrees with the gauges instead
			// of rendering 0/-1 unknowns while the agent keeps retrying.
			// Zero socketStart so the snapshot renders age 0 (not-ready)
			// for the whole retry pause, then reuse the single snapshot
			// shape shared with the reader-dead and panic paths.
			state.socketStart = time.Time{}
			emitTargetStatus(m, state, stats, stats.CurrentRTO(), 0, 0)
			// A DNS outage retries every second; log the first failure
			// immediately, then at most once per minute so an Error-level
			// message does not flood the log for the duration of the outage.
			// During shutdown ctx is cancelled and the failure is expected:
			// do not report it as an error.
			if ctx.Err() == nil && (lastDialLog.IsZero() || time.Since(lastDialLog) >= time.Minute) {
				logger.Error("Failed to open UDP socket; retrying", "err", err)
				lastDialLog = time.Now()
			}
			if !sleepCtx(ctx, time.Second) {
				return
			}
			continue
		}

		state.socketStart = time.Now()

		// Optional QoS marking: apply per socket so a periodic re-dial
		// re-marks it too. Best effort — a failure only warns.
		if cfg.DSCP > 0 {
			if err := setDSCP(conn, cfg.DSCP, conn.RemoteAddr()); err != nil {
				logger.Warn("Failed to mark probes with DSCP; probes continue unmarked", "dscp", cfg.DSCP, "err", err)
			} else {
				logger.Info("Probe DSCP marking enabled", "dscp", cfg.DSCP)
			}
		}

		// runEchoLoop recovers panics and returns them as errors; a
		// panic is per-event corruption, not a link condition, so the
		// target keeps probing rather than dying with frozen series
		// (stale counters make loss rate() queries go NaN). RTO state and
		// jitter survive the restart; link_up is dropped to 0 while the
		// restart pause leaves nothing probing. The pause bounds a
		// panic-storm cycle.
		err = runEchoLoop(ctx, conn, cfg, stats, m, state, logger)
		if err == nil || ctx.Err() != nil {
			return // clean context cancellation
		}
		if errors.Is(err, errReconnect) {
			// Periodic re-dial to re-resolve DNS; not an error.
			continue
		}
		if errors.Is(err, errReaderDead) {
			// Re-dial at once, but bound the retry: a socket that kills its
			// reader immediately (persistent SetReadDeadline failures) would
			// otherwise spin dial -> reader-death with no pause. The internal
			// error counter already recorded the event; throttle the log like
			// the dial failures.
			if ctx.Err() == nil && (lastDialLog.IsZero() || time.Since(lastDialLog) >= time.Minute) {
				logger.Error("UDP reader stopped; re-dialing socket")
				lastDialLog = time.Now()
			}
			if !sleepCtx(ctx, time.Second) {
				return
			}
			continue
		}
		logger.Error("Echo loop panicked; restarting probe loop", "err", err)
		m.internalPanic.Inc()
		// A panic-restart means nothing is being probed during the pause:
		// keep link_up honest (the next matched echo restores it) rather
		// than freezing a healthy-looking 1 across repeated restarts.
		m.linkUp.Set(0)
		state.linkUp = false
		// Re-emit /status now that link_up dropped: the per-interval snapshot
		// lives inside runEchoLoop, which just exited, so without this /status
		// would keep reporting link_up:true through the restart pause. Also
		// zero socketStart so /readyz does not stay ready during the pause.
		state.socketStart = time.Time{}
		emitTargetStatus(m, state, stats, stats.CurrentRTO(), 0, 0)
		if !sleepCtx(ctx, time.Second) {
			return
		}
	}
}

// rttSeconds computes one RTT sample from a matched send/receive pair, returning
// ok=false if timestamps are out of order. Uses monotonic time.Time.Sub (or
// Windows QPC when available to avoid interrupt-time quantization).
func rttSeconds(sentAt, recvAt time.Time, sentQPC, recvQPC uint64) (float64, bool) {
	if sentQPC != 0 && recvQPC != 0 && recvQPC >= sentQPC {
		return qpcSeconds(recvQPC - sentQPC), true
	}
	delta := recvAt.Sub(sentAt)
	if delta < 0 {
		return 0, false
	}
	return delta.Seconds(), true
}

// probeExpired reports whether an in-flight probe has exceeded its timeout.
// A sentAt in the future is defensively treated as expired so entries can never get stuck.
// Strictly greater: a probe at exact timeout retires on the next tick.
func probeExpired(now, sentAt time.Time, timeout time.Duration) bool {
	if now.Before(sentAt) {
		return true
	}
	return now.Sub(sentAt) > timeout
}

type response struct {
	seq uint64
	ts  uint64
	// recvAt is the receive instant as a time.Time, NOT UnixNano: the
	// monotonic reading it carries is what makes the RTT subtraction
	// immune to a wall-clock step (a `date`/NTP jump or a VM snapshot
	// restore while a probe is in flight produced a NEGATIVE sample —
	// link_rtt_seconds_sum went backwards and AdaptiveStats went
	// negative, collapsing the RTO floor).
	recvAt time.Time
	// recvQPC is the same instant on the high-resolution Windows counter
	// (0 when unavailable); the wall clock alone is interrupt-time
	// quantized there, which computed sub-quantum RTTs as exactly 0.
	recvQPC   uint64
	corrupted bool
}

// sentStamp carries the send-time markers for one in-flight probe:
// sentAt is the instant the RTT and the timeout sweep use (it carries the
// monotonic reading, so a wall-clock step cannot move it), sentNS is the
// wire timestamp the echo must byte-equal, and qpc is the same instant on
// the Windows high-resolution counter.
type sentStamp struct {
	sentAt time.Time
	sentNS int64
	qpc    uint64
}

type echoLoop struct {
	ctx    context.Context
	conn   net.Conn
	cfg    Config
	stats  *AdaptiveStats
	m      targetMetrics
	state  *probeLoopState
	logger *slog.Logger

	respCh     chan response
	done       chan struct{}
	readerDone chan struct{}
	loopDone   chan struct{}

	pending          map[uint64]sentStamp
	pendingHighWater int
	writeFails       int
	warnedWriteDown  bool
	warnedThrottle   bool
	warnedSlowRTT    bool
	mac              *probeMACer
	buf              []byte
	started          time.Time
	expectedSize     int
}

func newEchoLoop(
	ctx context.Context,
	conn net.Conn,
	cfg Config,
	stats *AdaptiveStats,
	m targetMetrics,
	state *probeLoopState,
	logger *slog.Logger,
) *echoLoop {
	expectedSize := probeHeaderSize(cfg.EchoSecret) + cfg.Payload
	var mac *probeMACer
	if cfg.EchoSecret != "" {
		mac = newProbeMACer(cfg.EchoSecret)
	}
	return &echoLoop{
		ctx:          ctx,
		conn:         conn,
		cfg:          cfg,
		stats:        stats,
		m:            m,
		state:        state,
		logger:       logger,
		respCh:       make(chan response, responseBufferCapacity(cfg)),
		done:         make(chan struct{}),
		readerDone:   make(chan struct{}),
		loopDone:     make(chan struct{}),
		pending:      make(map[uint64]sentStamp),
		mac:          mac,
		buf:          make([]byte, expectedSize),
		started:      time.Now(),
		expectedSize: expectedSize,
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
// within the RTO is genuinely lost on the wire.
func runEchoLoop(
	ctx context.Context,
	conn net.Conn,
	cfg Config,
	stats *AdaptiveStats,
	m targetMetrics,
	state *probeLoopState,
	logger *slog.Logger,
) error {
	return newEchoLoop(ctx, conn, cfg, stats, m, state, logger).run()
}

func (l *echoLoop) run() (retErr error) {
	// loopDone stops the cancel-watcher goroutine on normal exit; closing
	// conn on ctx.Done() unblocks a stalled conn.Write immediately.
	go func() {
		select {
		case <-l.ctx.Done():
			_ = l.conn.Close()
		case <-l.loopDone:
		}
	}()

	go l.runReader()
	defer l.cleanup(&retErr)

	// Monotonic schedule: the tick period must be the probe interval, not
	// interval + this loop's own work (drain, timeout sweep, frame build,
	// write), which is material at 1-10ms intervals. `next` is the absolute
	// deadline of the next probe; the timer waits the remaining time to it.
	// Starting at now keeps the first probe immediate (the pre-existing
	// behavior); the schedule takes over from the second tick.
	intervalTimer := time.NewTimer(0)
	defer intervalTimer.Stop()
	next := time.Now()

	for {
		interval := l.cfg.BaseInterval
		timeout := l.cfg.BaseTimeout
		if l.cfg.Adaptive {
			timeout = l.stats.CurrentRTO()
		}

		l.m.rto.Set(timeout.Seconds())
		// Publish the applied timeout for the MTU sweep's probe deadline (see
		// mtuDeadline): on an adaptive link the RTO can be well above
		// cfg.BaseTimeout, and a sweep that waited only -timeout would fail
		// every DF probe there.
		l.state.rtoNs.Store(int64(timeout))

		// Stop may race a firing timer; when Stop returns false the
		// channel is drained so Reset starts clean.
		stopDrain(intervalTimer)
		delay := time.Until(next)
		if delay < 0 {
			// Fell behind (the loop's work exceeded the interval): skip the
			// missed slots entirely rather than firing a burst of catch-up
			// probes, and resynchronize the schedule to now.
			next = time.Now()
			delay = 0
		}
		intervalTimer.Reset(delay)

		select {
		case <-l.ctx.Done():
			return nil
		case <-l.readerDone:
			return l.handleReaderDead(timeout)
		case <-intervalTimer.C:
		}
		next = next.Add(interval)

		l.drainResponses()
		l.sweepTimeouts(time.Now(), timeout)

		// Refresh the /status snapshot once per interval (nil-safe when
		// no registry is wired). LastEchoAge is -1 until the first echo.
		emitTargetStatus(l.m, l.state, l.stats, timeout, l.writeFails, len(l.pending))

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
		if l.cfg.ReconnectInterval != 0 {
			reconnectInterval = l.cfg.ReconnectInterval
		}
		if reconnectInterval != 0 && time.Since(l.started) >= reconnectInterval {
			// Drain first, like the reader-dead and panic exits: an echo that
			// already reached respCh answered a probe, and charging it as loss
			// would fabricate wire loss on a healthy link.
			l.drainResponses()
			l.flushPending()
			return errReconnect
		}

		l.sendProbe(timeout)
	}
}

func (l *echoLoop) runReader() {
	defer close(l.readerDone)
	// Same panic contract as the echo loop below: a reader panic is
	// per-event corruption, not a link condition. close(readerDone)
	// still fires (deferred above), so the main loop re-dials via the
	// errReaderDead path instead of probing into a void, and the
	// failure is counted and logged at Error rather than vanishing.
	defer func() {
		if r := recover(); r != nil {
			l.logger.Error("Panic in UDP reader; stopping reader", "panic", r)
			l.m.internalPanic.Inc()
		}
	}()
	// Read into a buffer larger than the payload so an oversized
	// datagram is not silently truncated to PayloadSize by the kernel
	// and mistaken for a valid probe (Read truncates to the buffer).
	// Frame shape: constant for this socket's lifetime (depends only
	// on configuration fixed at loop start).
	buf := make([]byte, MaxDatagramSize)
	// Scratch for regenerating the expected payload pattern; reused
	// across packets (single reader goroutine).
	var payloadScratch []byte
	if l.cfg.Payload > 0 {
		payloadScratch = make([]byte, l.cfg.Payload)
	}
	// One reusable HMAC state for the reader goroutine (the send loop
	// has its own; crypto/hmac state is not safe for concurrent use).
	var rMac *probeMACer
	if l.cfg.EchoSecret != "" {
		rMac = newProbeMACer(l.cfg.EchoSecret)
	}
	deadlineFails := 0
	// readFails bounds consecutive non-timeout Read errors: they can be
	// persistent (a dead interface surfaces each poll as an error) and a
	// bare `continue` would busy-spin at Debug level. Reset on any
	// successful read or timeout.
	readFails := 0
	for {
		if l.ctx.Err() != nil {
			return
		}
		if err := l.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			// A deadline that cannot be set means the socket is unusable;
			// bail out instead of hot-spinning on a guaranteed error. The
			// periodic reconnect re-creates the reader.
			deadlineFails++
			if deadlineFails >= 3 {
				l.logger.Error("SetReadDeadline persistently failing; stopping reader", "err", err)
				return
			}
			continue
		}
		deadlineFails = 0

		n, err := l.conn.Read(buf)
		if err != nil {
			if os.IsTimeout(err) {
				readFails = 0
				continue
			}
			if errors.Is(err, net.ErrClosed) || l.ctx.Err() != nil {
				return
			}
			// ICMP-derived errors (port unreachable / host or net
			// unreachable — Windows reports the port case as a reset) are the
			// NORMAL signal that the far end or a hop is down: the probe
			// simply times out. They must not count as reader failures, or a
			// legitimately DOWN target would kill its reader once a second,
			// bump link_prober_internal_errors_total and flood the log with
			// Errors — for a state the monitor is supposed to report calmly.
			if isPeerUnreachable(err) {
				readFails = 0
				l.logger.Debug("UDP read error (peer unreachable); probe will time out", "err", err)
				continue
			}
			// Anything else persistent is unexpected: bound it so the reader
			// cannot spin at Debug level forever.
			readFails++
			if readFails >= maxConsecutiveReadFails {
				l.logger.Error("Persistent UDP read errors; stopping reader",
					"consecutive_failures", readFails, "err", err)
				return
			}
			l.logger.Debug("UDP read error", "err", err)
			continue
		}
		readFails = 0
		// Stamp the receive instant BEFORE any validation: the size,
		// magic and (with -echo-secret) full-frame HMAC gates cost 1-3us
		// of SHA-256, which is material on LAN RTTs and would bias every
		// sample by that amount. Everything after this line is our own
		// filtering, not time on the wire.
		recvAt := time.Now()
		recvQPC, _ := qpcNow()
		if n != l.expectedSize {
			continue
		}
		if string(buf[0:8]) != MagicBytes {
			continue
		}

		seq := binary.LittleEndian.Uint64(buf[8:16])
		ts := binary.LittleEndian.Uint64(buf[16:24])
		if l.cfg.EchoSecret != "" {
			// Verify under the coverage this client SENT with; no
			// fallback is needed or safe: the server echoes buf[:n]
			// unmodified (server.go WriteTo), so an echo can only carry
			// the tag we wrote. A full-frame frame is either echoed
			// intact (the dual-accept server) or never echoes at all —
			// a v0.7 header-only server rejects it before echoing,
			// which is why -hmac-coverage=header remains the documented
			// escape hatch for a v0.7 peer. Zero-payload frames are
			// excluded from the full-frame check because the two
			// coverages coincide byte-for-byte there (pinned by
			// TestHMACCoverageZeroPayloadEquivalence), so the header
			// check is the same check.
			if tagsPayload(l.cfg.HmacCoverage, l.cfg.Payload) {
				if !rMac.verifyFullFrame(buf[:n]) {
					continue
				}
			} else if !rMac.verifyHeader(seq, ts, buf[24:32]) {
				continue
			}
		}
		resp := response{seq: seq, ts: ts, recvAt: recvAt, recvQPC: recvQPC}
		if l.cfg.Payload > 0 {
			// Validate the echoed payload byte-for-byte against the
			// pattern regenerated from the frame's own seq/ts.
			plOff := PayloadSize
			if l.cfg.EchoSecret != "" {
				plOff = PayloadSizeWithHMAC
			}
			fillPayload(payloadScratch, seq, ts)
			resp.corrupted = !bytes.Equal(payloadScratch, buf[plOff:plOff+l.cfg.Payload])
		}

		// Push with PRIORITY over cancellation: this select must not
		// gamble on the random case pick when both the channel and
		// ctx.Done are ready - an echo already parsed (read from the
		// wire) and then dropped here would be swept as a timeout at
		// loop exit (fabricated loss on a probe the link answered).
		// respCh is sized to the pending-window cap, so a non-blocking
		// send has room on every realistic path; the blocking fallback
		// exists only for the pathological full-channel case, where the
		// done/ctx branches still bound the reader (MED-2 audit fix).
		select {
		case l.respCh <- resp:
		default:
			select {
			case l.respCh <- resp:
			case <-l.ctx.Done():
				return
			case <-l.done:
				return
			}
		}
	}
}

// drainResponses consumes every response the reader has already buffered
// and matches them against pending. It is the single definition of the
// drain step, shared by the main loop and the two failure exits (reader
// death, panic restart) so those exits can drain BEFORE flushing the rest
// as loss — otherwise an echo already sitting in respCh would be charged
// as packet loss. Non-blocking: it returns once respCh is empty.
func (l *echoLoop) drainResponses() {
	for {
		select {
		case resp := <-l.respCh:
			st, ok := l.pending[resp.seq]
			if !ok {
				continue
			}
			if resp.ts != uint64(st.sentNS) {
				// Echoed payload does not match what we sent:
				// corruption, replay, or spoofing. Leave the probe
				// pending so it is counted as a loss on timeout.
				l.logger.Debug("Rejected response with mismatched timestamp", "seq", resp.seq)
				continue
			}
			delete(l.pending, resp.seq)
			l.m.inflight.Dec()

			if resp.corrupted {
				// Payload bytes were altered in flight while magic,
				// seq and timestamp survived: data-path corruption,
				// not loss. The balance invariant gains a bucket:
				// sent = rtt + timed_out + corrupted + inflight.
				// The round trip completed, so the link is up; the
				// sample stays out of RTT/jitter/RTO statistics.
				l.m.corrupted.Inc()
				l.state.consecutiveMisses = 0
				if l.writeFails < maxConsecutiveWriteFails {
					l.m.linkUp.Set(1)
					l.state.linkUp = true
				}
				l.state.lastEcho = resp.recvAt
				continue
			}

			// RTT basis: the monotonic delta between the two instants (with the
			// Windows counter pair preferred), never a subtraction of bare
			// UnixNano values — that stripped the monotonic reading, so a
			// wall-clock step while a probe was in flight produced a negative
			// sample: link_rtt_seconds_sum decreased and AdaptiveStats went
			// negative, collapsing the RTO floor.
			rttSec, measurable := rttSeconds(st.sentAt, resp.recvAt, st.qpc, resp.recvQPC)
			if !measurable {
				// The echo claims to predate its own send (a clock step or a
				// mismatched clock pair). Publishing the negative delta would
				// corrupt the histogram sum and the estimator, so publish 0
				// instead: the probe WAS answered, so charging it as loss
				// would fabricate wire loss, and skipping the observation
				// would break the sent = rtt_count + timed_out + inflight
				// balance (link_rtt_seconds_count is the rtt bucket).
				rttSec = 0
			}

			// With a fixed (non-adaptive) timeout, a true RTT above the
			// timeout makes every probe read as loss — indistinguishable
			// from a dead link. Warn once so the operator can tell them
			// apart; adaptive RTO tracks the real RTT instead.
			if !l.cfg.Adaptive && !l.warnedSlowRTT && rttSec > l.cfg.BaseTimeout.Seconds() {
				l.warnedSlowRTT = true
				l.logger.Warn("Observed RTT exceeds fixed timeout; such probes all read as loss",
					"rtt_seconds", rttSec, "timeout", l.cfg.BaseTimeout.String(),
					"fix", "enable adaptive RTO or raise -timeout")
			}

			l.m.rtt.Observe(rttSec)

			// Jitter over consecutive RTT samples (RFC 3550 §6.4.1):
			// J += (|D(i-1,i)| - J)/16. Any gap in sequence numbers
			// starts the estimate over, keeping post-outage recovery
			// from spiking the gauge. The comparison uses the
			// response's own sequence number: the loop's seq is the
			// last-sent probe, so with multiple probes in flight
			// (interval < RTO) it would mislabel every response after
			// the first in a drain as a gap and pin jitter at 0.
			if l.state.havePrev && resp.seq == l.state.prevSeq+1 {
				l.state.jitter += (math.Abs(rttSec-l.state.prevRTT) - l.state.jitter) / 16
			} else {
				l.state.jitter = 0
			}
			l.state.prevRTT, l.state.prevSeq, l.state.havePrev = rttSec, resp.seq, true
			l.m.jitter.Set(l.state.jitter)

			if l.cfg.Adaptive {
				l.stats.Update(rttSec)
				l.m.srtt.Set(l.stats.SRTT().Seconds())
			}
			l.state.consecutiveMisses = 0
			// Re-arm link_up only while local sends are healthy. An echo
			// that lands after the write-failure streak reached the
			// threshold proves the far end was reachable, NOT that this
			// socket can still send: re-arming unconditionally used to
			// freeze link_up at 1 forever, because the down transition
			// below fires once (writeFails keeps growing past the
			// threshold, so an equality test never matches again) and
			// the pending set empties, leaving no misses to count.
			if l.writeFails < maxConsecutiveWriteFails {
				l.m.linkUp.Set(1)
				l.state.linkUp = true
			}
			l.state.lastEcho = resp.recvAt
		default:
			return
		}
	}
}

func (l *echoLoop) sweepTimeouts(now time.Time, timeout time.Duration) {
	var timeoutOccurred bool
	if len(l.pending) > 0 {
		for s, st := range l.pending {
			if probeExpired(now, st.sentAt, timeout) {
				l.m.timedOut.Inc()
				l.m.inflight.Dec()
				delete(l.pending, s)
				timeoutOccurred = true
				l.state.consecutiveMisses++
			}
		}
	}

	if timeoutOccurred && l.cfg.Adaptive {
		l.stats.Backoff()
	}

	// S6: shrink pending map after stall to avoid retaining high-water capacity for lifetime of runEchoLoop (5m). Only reallocates when map was large (>512) and has now drained.
	if len(l.pending) > l.pendingHighWater {
		l.pendingHighWater = len(l.pending)
	} else if len(l.pending) == 0 && l.pendingHighWater > 512 {
		l.pending = make(map[uint64]sentStamp)
		l.pendingHighWater = 0
	}

	// Down after LinkUpMissThreshold consecutive probes without an
	// echo. A single lost probe or brief stall does not flap the
	// state (enterprise health-check convention).
	if l.state.consecutiveMisses >= LinkUpMissThreshold {
		l.m.linkUp.Set(0)
		l.state.linkUp = false
	}
}

func (l *echoLoop) sendProbe(timeout time.Duration) {
	// Enforce maxPendingWindow at the send site too: under -adaptive the 2*SRTT
	// floor is unbounded above. Skipped sends never reach the wire and are
	// counted in link_probes_throttled_total (outside the balance).
	if len(l.pending) >= maxPendingWindow {
		l.m.throttled.Inc()
		if !l.warnedThrottle {
			// Bounded like the write-failure warning: once per
			// sustained-throttle streak, Warn level (Debug is invisible
			// at default verbosity). Reset on the next successful send.
			l.warnedThrottle = true
			l.logger.Warn("Pending window is full; skipping probe sends until probes resolve",
				"pending", len(l.pending), "window", maxPendingWindow)
		}
		return
	}

	// Reserve, but do not yet consume, the sequence number: a failed
	// write never put the datagram on the wire, so burning its seq
	// would look like a loss to the RFC 3550 gap check and spuriously
	// reset the jitter estimate. Consume it only after a successful
	// write.
	//
	// Capture the send time here, NOT the `now` used for the timeout
	// sweep: that timestamp predates the response drain, so using it as
	// sentTime would inflate every RTT by the tick's drain/sweep cost.
	// sentAt carries the monotonic reading (RTT + sweep math); sentNS is
	// the wire nonce the echo must byte-equal.
	sentAt := time.Now()
	sendNS := sentAt.UnixNano()
	sendQPC, _ := qpcNow()
	seq := l.state.seq + 1
	ts := uint64(sendNS)
	// One spelling of the wire layout, shared with the MTU sweep:
	// see buildProbeFrame.
	buildProbeFrame(l.buf, seq, ts, l.cfg.Payload, l.mac, l.cfg.HmacCoverage)

	// Send first, then register: registering in-flight only after a
	// successful write means a failed or panicking write can never
	// orphan a gauge increment (every pending entry has exactly one
	// matching inflight unit, so any exit-path flush balances).
	// The write is deadline-bounded like the MTU sweep's probes (mtu.go):
	// a UDP write can block when the local send buffer is saturated, and a
	// wedged write would otherwise hang this loop — and therefore
	// shutdown/reload — with no way out but SIGKILL.
	writeDeadline := time.Now().Add(timeout)
	if cd, ok := l.ctx.Deadline(); ok && cd.Before(writeDeadline) {
		writeDeadline = cd
	}
	_ = l.conn.SetWriteDeadline(writeDeadline)
	if _, err := l.conn.Write(l.buf); err != nil {
		l.writeFails++
		l.m.sendErr.Inc()
		if l.writeFails >= maxConsecutiveWriteFails {
			if !l.warnedWriteDown {
				// Sustained local write failures mean nothing is being
				// probed while consecutiveMisses stays frozen — the worst
				// failure mode is link_up stuck at 1. Escalate once at
				// Error (Debug is invisible at default verbosity) and
				// reflect reality in the gauge.
				l.warnedWriteDown = true
				l.logger.Error("Persistent UDP write failures; marking link down",
					"consecutive_failures", l.writeFails, "err", err)
			}
			// Idempotent on purpose: unlike the old `==` transition this
			// re-asserts reality on every failing tick, so an echo drained
			// by an earlier stage of this same iteration can never leave
			// the gauge green while no probe can leave the host.
			wasUp := l.state.linkUp
			l.m.linkUp.Set(0)
			l.state.linkUp = false
			if wasUp {
				// Re-emit /status so the dropped link_up is visible immediately
				// rather than up to a full interval later.
				emitTargetStatus(l.m, l.state, l.stats, timeout, l.writeFails, len(l.pending))
			}
		}
		return
	}
	l.writeFails = 0
	l.warnedWriteDown = false
	l.warnedThrottle = false
	l.state.seq = seq

	l.pending[l.state.seq] = sentStamp{sentAt: sentAt, sentNS: sendNS, qpc: sendQPC}
	l.m.inflight.Inc()
	l.m.sent.Inc()
}

// flushPending abandons every in-flight probe as a loss: they can never
// match on this socket, so counting them as timed out keeps the
// sent = rtt + timed_out + inflight balance intact across a re-dial.
// Shared by the reconnect, dead-reader, and panic recovery exits.
func (l *echoLoop) flushPending() {
	if n := len(l.pending); n > 0 {
		l.m.timedOut.Add(float64(n))
		l.m.inflight.Sub(float64(n))
		l.pending = make(map[uint64]sentStamp)
	}
}

func (l *echoLoop) handleReaderDead(timeout time.Duration) error {
	// The reader was the only path that could resolve a probe; with
	// it gone, every in-flight probe is a guaranteed loss and every
	// later send would go unanswered until the next reconnect.
	if l.ctx.Err() != nil {
		return nil // reader torn down by shutdown
	}
	// The counter is incremented here; probeTarget owns the log and the
	// bounded re-dial pause (a persistent reader failure must not spin).
	l.m.internalReaderDead.Inc()
	// Drain echoes the reader delivered before it died: they WERE
	// received, so the flush below must not charge them as loss (or as
	// link-up misses). Deliberately before the miss count.
	l.drainResponses()
	// A reader death is a real measurement failure: the abandoned probes
	// got no echo and can never match on this socket. Count them toward
	// the link-up miss threshold (at least one, even with nothing in
	// flight) so a PERSISTENT read-side failure cannot leave link_up
	// frozen at 1 across re-dial cycles, while a single transient blip
	// costs one miss and does not flap a healthy link. Deliberately
	// unlike the reconnect flush, whose probes were cut short by a
	// planned socket swap rather than lost.
	if n := len(l.pending); n > 0 {
		l.state.consecutiveMisses += n
	} else {
		l.state.consecutiveMisses++
	}
	if l.state.consecutiveMisses >= LinkUpMissThreshold {
		l.m.linkUp.Set(0)
		l.state.linkUp = false
	}
	l.flushPending()
	// The socket that just lost its reader can no longer deliver
	// echoes: zero socketStart so the re-emit below — the snapshot
	// /readyz is built on — reports socket_age_seconds=0 for the whole
	// bounded re-dial pause instead of a stale age from a dead socket.
	l.state.socketStart = time.Time{}
	// Re-emit the snapshot so /status reflects the dropped link_up
	// immediately rather than up to a full interval later.
	emitTargetStatus(l.m, l.state, l.stats, timeout, l.writeFails, len(l.pending))
	return errReaderDead
}

func (l *echoLoop) cleanup(retErr *error) {
	// Close the socket, stop the cancel watcher, and signal `done` FIRST,
	// then give the reader one bounded join before any accounting: the
	// reader can be parked in its send-select (when respCh is full) or
	// mid-parse of an already-read datagram, and closing `done` here
	// (instead of an outer LIFO defer) unblocks it BEFORE <-readerDone
	// and BEFORE drainResponses() runs.
	close(l.loopDone)
	close(l.done)
	_ = l.conn.Close()
	select {
	case <-l.readerDone:
	case <-time.After(mtuReadArm):
	}
	// On panic: drain buffered echoes first, then flush remaining in-flight probes
	// as timedOut and clear pending so the non-shutdown tail below does not double-count.
	if r := recover(); r != nil {
		l.logger.Error("Panic in echo loop; continuing", "panic", r)
		*retErr = fmt.Errorf("panic in echo loop: %v", r)
		l.drainResponses()
		l.flushPending()
	}
	// On process shutdown, only decrement inflight (all series stop exporting).
	// On target restart/reload, drain delivered echoes and count remaining probes
	// as timed out so the sent = rtt + timed_out + inflight balance stays intact.
	if !runClientShuttingDown(l.ctx) {
		l.drainResponses()
		if n := len(l.pending); n > 0 {
			l.m.timedOut.Add(float64(n))
		}
	}
	inflight := l.m.inflight
	if n := float64(len(l.pending)); n > 0 {
		inflight.Sub(n)
	}
}
