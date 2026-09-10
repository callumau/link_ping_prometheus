package prober

import (
	"bytes"
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
	"sync/atomic"
	"syscall"
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
	// per-IP or global cap: the server silently drops over-cap probes,
	// which the client would read as artificial packet loss. The rate sums
	// each target's EFFECTIVE interval (per-target override, else the
	// global) so a target with a short interval is not undercounted.
	var pps float64
	for _, tg := range cfg.Targets {
		interval := cfg.BaseInterval
		if tg.Interval != 0 {
			interval = tg.Interval
		}
		if interval > 0 {
			pps += 1 / interval.Seconds()
		}
	}
	if pps > float64(MaxPktsPerIP) {
		slog.Warn("Probe rate exceeds the server per-IP echo cap; probes will be dropped and loss will read artificially high",
			"expected_pkts_per_sec", pps, "server_cap_per_ip", MaxPktsPerIP,
			"fix", "raise MaxPktsPerIP on the server or reduce targets/interval")
	}
	if pps > float64(MaxPktsGlobal) {
		slog.Warn("Probe rate exceeds the server global echo cap; probes will be dropped and loss will read artificially high",
			"expected_pkts_per_sec", pps, "server_cap_global", MaxPktsGlobal,
			"fix", "raise MaxPktsGlobal on the server or reduce targets/interval")
	}

	SeedMetrics(cfg.Source, cfg.Targets)

	// Supervisor over per-target probe goroutines, keyed by target name
	// so the targets file can be hot-reloaded (SIGHUP, a poll interval,
	// or an injected ReloadSignal — tests) without restarting the
	// process. Restarting is disruptive: socket state zeroes and the
	// Windows service needs manual action.
	type running struct {
		tg     Target
		cancel context.CancelFunc
		done   chan struct{}
	}
	live := make(map[string]running)

	// stragglers holds names whose old probe loop did NOT join within
	// stop's 5s bound. Such a loop may still be alive and still writing
	// that target's series, so a later reload must NOT start a second loop
	// for the name — two loops on one target double-count
	// link_probes_sent_total and break the loss ratio. The set lives at
	// RunClient scope (not inside apply) so it survives across reloads; the
	// cleanup goroutine that finishes the purge removes from it under this
	// mutex.
	stragglers := make(map[string]bool)
	var stragglersMu sync.Mutex

	// markStraggler records name until its timed-out loop exits, then
	// finishes what stop's timeout path could not: withdraws the series
	// (when this was a removal or an address change — purgeSeries) and
	// drops the name so a later reload may start it again. The wait on
	// r.done is bounded: the loop was already cancelled and its own retry
	// waits are at most 1s.
	markStraggler := func(name string, r running, purgeSeries bool) {
		stragglersMu.Lock()
		stragglers[name] = true
		stragglersMu.Unlock()
		go func() {
			<-r.done
			if purgeSeries {
				deleteTargetSeries(cfg.Source, r.tg)
			}
			cfg.Status.Remove(name)
			stragglersMu.Lock()
			delete(stragglers, name)
			stragglersMu.Unlock()
		}()
	}
	isStraggler := func(name string) bool {
		stragglersMu.Lock()
		defer stragglersMu.Unlock()
		return stragglers[name]
	}

	start := func(tg Target) {
		tctx, cancel := context.WithCancel(ctx)
		r := running{tg: tg, cancel: cancel, done: make(chan struct{})}
		live[tg.Name] = r
		go func() {
			defer close(r.done)
			probeTarget(tctx, tg, cfg)
		}()
	}
	// stop cancels a target's loop and joins it with a bound. It returns
	// false when the join timed out (the loop may still be writing that
	// target's series). purge additionally withdraws every metric series so
	// a REMOVED target stops being exported — see deleteTargetSeries.
	stop := func(name string, purge bool) bool {
		r, ok := live[name]
		if !ok {
			return true
		}
		delete(live, name)
		r.cancel()
		// Bounded join: probeTarget exits promptly on cancel (its own
		// retry waits are at most 1s). A slow exit must not block a reload.
		select {
		case <-r.done:
			if purge {
				deleteTargetSeries(cfg.Source, r.tg)
				cfg.Status.Remove(name)
			}
			return true
		case <-time.After(5 * time.Second):
			slog.Warn("Removed target probe loop did not stop within 5s", "target", name)
			return false
		}
	}
	// apply swaps the running set to match targets: removed targets stop and
	// have their series deleted, changed targets restart with the new values
	// (an address change also withdraws the old address's series — a retired IP
	// must not keep exporting a frozen link_up; an interval/timeout change keeps
	// them, still the same endpoint), new targets start fresh. targets must
	// already be validated (LoadTargets and Config.Validate both do).
	apply := func(targets []Target) {
		want := make(map[string]Target, len(targets))
		for _, tg := range targets {
			want[tg.Name] = tg
		}
		for name, r := range live {
			w, ok := want[name]
			if ok && w.Address == r.tg.Address && w.Interval == r.tg.Interval && w.Timeout == r.tg.Timeout {
				continue
			}
			// !ok means the target was removed from the file: purge it.
			if !stop(name, !ok) {
				// The old loop did not join: it may still be alive on the same
				// series, so a replacement must NOT be started for this name
				// (two loops writing one target double-count sent and break the
				// loss ratio). Record it as a straggler and hand the purge to a
				// goroutine that waits for the loop to exit — the timeout path
				// itself must not block a reload forever. purgeSeries mirrors
				// the clean path: withdraw the old series on a removal or an
				// address change, but keep it for an interval/timeout change
				// (still one endpoint, counters must stay continuous).
				slog.Error("Probe loop did not stop in time; leaving target stopped", "target", name)
				ProberInternalErrors.WithLabelValues(cfg.Source, r.tg.Name, r.tg.Address, "stop_timeout").Inc()
				markStraggler(name, r, !ok || r.tg.Address != w.Address)
				continue
			}
			if ok {
				// Same name but a different address is a DIFFERENT endpoint:
				// withdraw the old address's series, or a retired IP keeps
				// exporting its last link_up=1 for the life of the process (the
				// same frozen-green bug the removal purge fixes). An
				// interval/timeout change keeps the series: still one endpoint,
				// so its counters must stay continuous.
				if r.tg.Address != w.Address {
					deleteTargetSeries(cfg.Source, r.tg)
				}
				SeedMetrics(cfg.Source, []Target{w})
				start(w)
			}
		}
		for _, tg := range targets {
			if isStraggler(tg.Name) {
				continue
			}
			if _, ok := live[tg.Name]; !ok {
				SeedMetrics(cfg.Source, []Target{tg})
				start(tg)
			}
		}
	}

	apply(cfg.Targets)

	reload := func() {
		if cfg.TargetsPath == "" {
			slog.Info("Targets reload requested but no -targets file is configured; ignoring")
			return
		}
		targets, err := LoadTargets(cfg.TargetsPath)
		if err != nil {
			// A broken file mid-edit must never take the monitor down:
			// keep probing the previous set.
			slog.Error("Targets reload failed; keeping previous targets", "path", cfg.TargetsPath, "err", err)
			return
		}
		if len(targets) == 0 {
			// Respect the operator's intent (an empty array means "probe
			// nothing"), but name the consequence: this stops ALL probing and
			// purges every target's series, so a truncated or half-written
			// file that happens to parse as [] is loud rather than silent.
			slog.Warn("Targets file is empty; ALL probing stopped and every target's series will be purged",
				"path", cfg.TargetsPath)
		}
		slog.Info("Targets reloaded", "targets_count", len(targets))
		apply(targets)
	}

	if cfg.ReloadSignal == nil && (cfg.ReloadInterval <= 0 || cfg.TargetsPath == "") {
		// No reload path: original behavior — wait for every probe loop.
		for _, r := range live {
			<-r.done
		}
		return nil
	}

	var reloadTick <-chan time.Time
	if cfg.ReloadInterval > 0 && cfg.TargetsPath != "" {
		t := time.NewTicker(cfg.ReloadInterval)
		defer t.Stop()
		reloadTick = t.C
	}
	for {
		select {
		case <-ctx.Done():
			for _, r := range live {
				<-r.done
			}
			return nil
		case <-cfg.ReloadSignal:
			reload()
		case <-reloadTick:
			reload()
		}
	}
}

// targetMetrics holds pre-resolved Prometheus metric handles for one
// target. Resolving each handle once avoids the label hash + map lookup
// (and its mutex) on every probe event — the hottest path in the prober.
// The handles stay valid for the lifetime of the probe loop.
type targetMetrics struct {
	sent      prometheus.Counter
	sendErr   prometheus.Counter
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
// The constants exist for both Unix and Windows in package syscall.
func isPeerUnreachable(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH)
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
		// main loss balance entirely.
		go runMTUSweep(ctx, t, cfg, m, state, logger)
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
			lastEchoAge := -1.0
			if !state.lastEcho.IsZero() {
				lastEchoAge = time.Since(state.lastEcho).Seconds()
			}
			m.status.Update(TargetStatus{
				Name:               t.Name,
				Address:            t.Address,
				ConsecutiveMisses:  state.consecutiveMisses,
				RTOSeconds:         stats.CurrentRTO().Seconds(),
				JitterSeconds:      state.jitter,
				SRTTSeconds:        stats.SRTT().Seconds(),
				LastSeq:            state.seq,
				PathMTUBytes:       int(state.pathMTU.Load()),
				LastEchoAgeSeconds: lastEchoAge,
			})
			// A DNS outage retries every second; log the first failure
			// immediately, then at most once per minute so an Error-level
			// message does not flood the log for the duration of the outage.
			// During shutdown ctx is cancelled and the failure is expected:
			// do not report it as an error.
			if ctx.Err() == nil && (lastDialLog.IsZero() || time.Since(lastDialLog) >= time.Minute) {
				logger.Error("Failed to open UDP socket; retrying", "err", err)
				lastDialLog = time.Now()
			}
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
		logger.Error("Echo loop panicked; restarting probe loop", "err", err)
		m.internalPanic.Inc()
		// A panic-restart means nothing is being probed during the pause:
		// keep link_up honest (the next matched echo restores it) rather
		// than freezing a healthy-looking 1 across repeated restarts.
		m.linkUp.Set(0)
		state.linkUp = false
		// Re-emit /status now that link_up dropped: the per-interval snapshot
		// lives inside runEchoLoop, which just exited, so without this /status
		// would keep reporting link_up:true through the restart pause.
		emitTargetStatus(m, state, stats, stats.CurrentRTO(), 0, 0)
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
		seq       uint64
		ts        uint64
		recv      time.Time
		corrupted bool
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

	// readerDone is closed by the reader goroutine on ANY exit so the main
	// loop can tell that responses are no longer being consumed and re-dial
	// instead of probing into a void.
	readerDone := make(chan struct{})

	defer conn.Close()

	go func() {
		defer close(readerDone)
		// Read into a buffer larger than the payload so an oversized
		// datagram is not silently truncated to PayloadSize by the kernel
		// and mistaken for a valid probe (Read truncates to the buffer).
		buf := make([]byte, MaxDatagramSize)
		// Scratch for regenerating the expected payload pattern; reused
		// across packets (single reader goroutine).
		var payloadScratch []byte
		if cfg.Payload > 0 {
			payloadScratch = make([]byte, cfg.Payload)
		}
		deadlineFails := 0
		// readFails bounds consecutive non-timeout Read errors: they can be
		// persistent (a dead interface surfaces each poll as an error) and a
		// bare `continue` would busy-spin at Debug level. Reset on any
		// successful read or timeout.
		readFails := 0
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
					readFails = 0
					continue
				}
				if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
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
					logger.Debug("UDP read error (peer unreachable); probe will time out", "err", err)
					continue
				}
				// Anything else persistent is unexpected: bound it so the reader
				// cannot spin at Debug level forever.
				readFails++
				if readFails >= maxConsecutiveReadFails {
					logger.Error("Persistent UDP read errors; stopping reader",
						"consecutive_failures", readFails, "err", err)
					return
				}
				logger.Debug("UDP read error", "err", err)
				continue
			}
			readFails = 0
			expectedSize := PayloadSize
			if cfg.EchoSecret != "" {
				expectedSize = PayloadSizeWithHMAC
			}
			expectedSize += cfg.Payload
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
			resp := response{seq: seq, ts: ts, recv: time.Now()}
			if cfg.Payload > 0 {
				// Validate the echoed payload byte-for-byte against the
				// pattern regenerated from the frame's own seq/ts.
				plOff := PayloadSize
				if cfg.EchoSecret != "" {
					plOff = PayloadSizeWithHMAC
				}
				fillPayload(payloadScratch, seq, ts)
				resp.corrupted = !bytes.Equal(payloadScratch, buf[plOff:plOff+cfg.Payload])
			}

			select {
			case respCh <- resp:
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
	buf := make([]byte, payloadSize+cfg.Payload)
	pending := make(map[uint64]time.Time)
	pendingHighWater := 0
	// started bounds the socket lifetime: once ReconnectInterval has
	// elapsed and no probes are in flight, the loop returns errReconnect
	// so the caller re-dials and re-resolves DNS.
	started := time.Now()

	// drainResponses consumes every response the reader has already buffered
	// and matches them against pending. It is the single definition of the
	// drain step, shared by the main loop and the two failure exits (reader
	// death, panic restart) so those exits can drain BEFORE flushing the rest
	// as loss — otherwise an echo already sitting in respCh would be charged
	// as packet loss. Non-blocking: it returns once respCh is empty.
	drainResponses := func() {
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

				if resp.corrupted {
					// Payload bytes were altered in flight while magic,
					// seq and timestamp survived: data-path corruption,
					// not loss. The balance invariant gains a bucket:
					// sent = rtt + timed_out + corrupted + inflight.
					// The round trip completed, so the link is up; the
					// sample stays out of RTT/jitter/RTO statistics.
					m.corrupted.Inc()
					state.consecutiveMisses = 0
					m.linkUp.Set(1)
					state.linkUp = true
					state.lastEcho = resp.recv
					continue
				}

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
					m.srtt.Set(stats.SRTT().Seconds())
				}
				state.consecutiveMisses = 0
				m.linkUp.Set(1)
				state.linkUp = true
				state.lastEcho = resp.recv
			default:
				return
			}
		}
	}

	defer func() {
		if r := recover(); r != nil {
			logger.Error("Panic in echo loop; continuing", "panic", r)
			retErr = fmt.Errorf("panic in echo loop: %v", r)
			// Drain any echo already received before flushing: it was
			// delivered, not lost, and charging it as a timeout would
			// fabricate loss. The remaining abandoned probes can never match
			// on this socket, so they are counted as timed out to keep
			// sent = rtt_count + timed_out + inflight balancing across the
			// restart (same treatment as the reconnect flush).
			drainResponses()
			m.timedOut.Add(float64(len(pending)))
		}
		// Probes still in flight die with the loop on cancellation
		// without counting as timeouts, but must leave the gauge.
		inflight := m.inflight
		if n := float64(len(pending)); n > 0 {
			inflight.Sub(n)
		}
	}()

	// flushPending abandons every in-flight probe as a loss: they can never
	// match on this socket, so counting them as timed out keeps the
	// sent = rtt + timed_out + inflight balance intact across a re-dial.
	// Shared by the reconnect and dead-reader exits (the panic recovery
	// defer does the same).
	flushPending := func() {
		if n := len(pending); n > 0 {
			m.timedOut.Add(float64(n))
			m.inflight.Sub(float64(n))
			pending = make(map[uint64]time.Time)
		}
	}

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
		// pi-lens-ignore: waitgroup-done-scope
		case <-ctx.Done():
			return nil
		case <-readerDone:
			// The reader was the only path that could resolve a probe; with
			// it gone, every in-flight probe is a guaranteed loss and every
			// later send would go unanswered until the next reconnect.
			if ctx.Err() != nil {
				return nil // reader torn down by shutdown
			}
			// The counter is incremented here; probeTarget owns the log and the
			// bounded re-dial pause (a persistent reader failure must not spin).
			m.internalReaderDead.Inc()
			// Drain echoes the reader delivered before it died: they WERE
			// received, so the flush below must not charge them as loss (or as
			// link-up misses). Deliberately before the miss count.
			drainResponses()
			// A reader death is a real measurement failure: the abandoned probes
			// got no echo and can never match on this socket. Count them toward
			// the link-up miss threshold (at least one, even with nothing in
			// flight) so a PERSISTENT read-side failure cannot leave link_up
			// frozen at 1 across re-dial cycles, while a single transient blip
			// costs one miss and does not flap a healthy link. Deliberately
			// unlike the reconnect flush below, whose probes were cut short by a
			// planned socket swap rather than lost.
			if n := len(pending); n > 0 {
				state.consecutiveMisses += n
			} else {
				state.consecutiveMisses++
			}
			if state.consecutiveMisses >= LinkUpMissThreshold {
				m.linkUp.Set(0)
				state.linkUp = false
			}
			flushPending()
			// Re-emit the snapshot so /status reflects the dropped link_up
			// immediately rather than up to a full interval later.
			emitTargetStatus(m, state, stats, timeout, writeFails, len(pending))
			return errReaderDead
		case <-intervalTimer.C:
		}
		next = next.Add(interval)

		drainResponses()

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
			state.linkUp = false
		}

		// Refresh the /status snapshot once per interval (nil-safe when
		// no registry is wired). LastEchoAge is -1 until the first echo.
		emitTargetStatus(m, state, stats, timeout, writeFails, len(pending))

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
			flushPending()
			return errReconnect
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
		sendTime := time.Now()
		seq := state.seq + 1
		copy(buf[0:8], MagicBytes)
		binary.LittleEndian.PutUint64(buf[8:16], seq)
		ts := uint64(sendTime.UnixNano())
		binary.LittleEndian.PutUint64(buf[16:24], ts)
		if cfg.EchoSecret != "" {
			h := computeHMAC(cfg.EchoSecret, seq, ts)
			copy(buf[24:32], h[:])
		}
		if cfg.Payload > 0 {
			// Header end is payloadSize (24 or 32): fill the rest with the
			// deterministic corruption-detection pattern.
			fillPayload(buf[payloadSize:payloadSize+cfg.Payload], seq, ts)
		}

		// Send first, then register: registering in-flight only after a
		// successful write means a failed or panicking write can never
		// orphan a gauge increment (every pending entry has exactly one
		// matching inflight unit, so any exit-path flush balances).
		if _, err := conn.Write(buf); err != nil {
			writeFails++
			m.sendErr.Inc()
			if writeFails == maxConsecutiveWriteFails {
				// Sustained local write failures mean nothing is being
				// probed while consecutiveMisses stays frozen — the worst
				// failure mode is link_up stuck at 1. Escalate once at
				// Error (Debug is invisible at default verbosity) and
				// reflect reality in the gauge.
				logger.Error("Persistent UDP write failures; marking link down",
					"consecutive_failures", writeFails, "err", err)
				m.linkUp.Set(0)
				state.linkUp = false
				// Re-emit /status so the dropped link_up is visible immediately
				// rather than up to a full interval later.
				emitTargetStatus(m, state, stats, timeout, writeFails, len(pending))
			}
			continue
		}
		writeFails = 0
		state.seq = seq

		pending[state.seq] = sendTime
		m.inflight.Inc()
		m.sent.Inc()
	}
}
