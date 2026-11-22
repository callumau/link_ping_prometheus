package prober

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"runtime"
	"strings"
	"sync"
	"time"

	"link_ping_prometheus/internal/filetrust"
)

// Target identifies a single probe destination.
type Target struct {
	Name     string        `json:"name"`
	Address  string        `json:"address"`
	Interval time.Duration `json:"interval,omitempty"`
	Timeout  time.Duration `json:"timeout,omitempty"`
}

// runClientDoneKey carries the RunClient root context's Done channel into
// every probe-loop context, so an exiting loop can distinguish "the process
// is shutting down" (every series stops being exported) from "this loop was
// cancelled for a restart" (kept-series restarts keep exporting while the
// old loop unwinds). The distinction decides the clean-cancel exit
// accounting — see the runEchoLoop exit defer.
type runClientDoneKey struct{}

func runClientShuttingDown(ctx context.Context) bool {
	d, ok := ctx.Value(runClientDoneKey{}).(<-chan struct{})
	if !ok || d == nil {
		// Defensive: no marker means no root to consult. Treat as shutdown
		// (inflight-only accounting) — the conservative choice.
		return true
	}
	select {
	case <-d:
		return true
	default:
		return false
	}
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
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
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

// targetByName returns the named target from targets, if present. Used by the
// straggler release path to decide a name's fate against the desired set that
// is current at exit time, not the one that was current when it timed out.
func targetByName(targets []Target, name string) (Target, bool) {
	for _, t := range targets {
		if t.Name == name {
			return t, true
		}
	}
	return Target{}, false
}

// FilterSelfTargets drops the target whose Name equals source, so one targets
// file listing every site (including the local one) can be deployed unchanged
// on every site of a mesh. The match is exact: target names are Prometheus
// label values and are case-sensitive, so a case variant is a different series
// and must not be dropped. The input slice is not modified.
func FilterSelfTargets(targets []Target, source string) []Target {
	kept := make([]Target, 0, len(targets))
	for _, t := range targets {
		if t.Name == source {
			slog.Info("Skipping self target (mesh mode: one targets file for every site)", "name", t.Name)
			continue
		}
		kept = append(kept, t)
	}
	return kept
}

// LoadTargets reads and validates a JSON file containing an array of
// Target objects. Each target address is verified via ValidateTarget.
// The file must be ≤ MaxTargetsFileSize (1 MB) and contain ≤ MaxTargetsCount
// (1000) entries. Target names must be unique: they are Prometheus label
// values, and duplicates would produce ambiguous metric series.
//
// The same trust checks hardenLogSink applies to the log sink apply here: the
// targets file steers where probes go (a redirected address turns the monitor
// into an oracle for another host) and can blank the set outright (the empty
// array stops all probing). A symlink or a group/world-writable file therefore
// lets any local user make that decision. Lstat, not Stat: following a symlink
// is exactly what a local attacker would rely on.
func LoadTargets(path string) ([]Target, error) {
	data, info, err := filetrust.ReadFileWith(path, MaxTargetsFileSize, filetrust.TrustOptions{DenyForeignWrite: true})
	if err != nil {
		return nil, fmt.Errorf("read targets file: %w", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o022 != 0 {
		// 0644/0604/0620 stay accepted (readable is not the risk — writing
		// is); group- or world-WRITABLE is not. os.Stat always reports 0666
		// on Windows, so the perm-bit check is meaningless there (the log
		// sink's hardenLogSink makes the same exemption and relies on the
		// file's DACL instead).
		return nil, fmt.Errorf("targets file %q is group/world-writable (mode %04o): another local user could redirect or blank the probe set; fix with: chmod o-w,g-w %s (0600 is recommended)",
			path, info.Mode().Perm(), path)
	}
	var targets []Target
	if err := json.Unmarshal(data, &targets); err != nil {
		return nil, fmt.Errorf("parse targets json: %w", err)
	}
	// A document that is not an array must not silently mean "probe nothing":
	// `null` used to unmarshal into a nil slice with no error, blanking the
	// probe set and purging every series exactly like [] (which at least warns).
	if targets == nil {
		return nil, fmt.Errorf("parse targets json: expected an array of targets, got null")
	}
	if len(targets) > MaxTargetsCount {
		return nil, fmt.Errorf("too many targets: %d (max %d)", len(targets), MaxTargetsCount)
	}
	if err := validateTargets(targets); err != nil {
		return nil, fmt.Errorf("invalid targets: %w", err)
	}
	return targets, nil
}

// stragglerStopTimeout bounds how long RunClient waits for a removed or
// changed target's probe loop to join before leaving it stopped. A variable
// (not a constant) so tests can lower it — the 5s value is chosen for real
// sockets, and the straggler path also has to be exercised. A loop that
// misses this bound is recorded as a straggler and restarted (when the target
// is still in the file) once it does exit.
var stragglerStopTimeout = 5 * time.Second

// stragglerReLogInterval re-asserts the stranded-target state at Warn
// level: a permanently wedged probe loop (write with no deadline) leaves
// its target silently unprobed for the process lifetime — one Error line
// at mark time is invisible to log-frequency alerting, and nothing else
// re-states the condition. A package var so tests can shorten it (the
// stragglerStopTimeout/DynClientTTL precedent).
var stragglerReLogInterval = time.Minute

type runningTarget struct {
	tg     Target
	cancel context.CancelFunc
	done   chan struct{}
}

type joinTarget struct {
	name string
	done chan struct{}
}

// supervisor manages per-target probe goroutines across hot reloads.
// Keyed by target name so the targets file can be reloaded (SIGHUP, poll
// interval, or injected ReloadSignal) without restarting the process.
type supervisor struct {
	ctx  context.Context
	cfg  Config
	live map[string]runningTarget

	// stragglers maps a name whose old probe loop did NOT join within
	// stragglerStopTimeout to that OLD loop (whose Target carries the labels a
	// purge needs). Such a loop may still be alive and still writing that
	// target's series, so a later reload must NOT start a second loop for the
	// name — two loops on one target double-count link_probes_sent_total and
	// break the loss ratio. The set lives at supervisor scope (not inside
	// apply) so it survives across reloads; the entry is removed by the
	// supervisor once the loop has actually exited (freed), and only then is
	// the name's fate decided.
	stragglersMu sync.Mutex
	stragglers   map[string]runningTarget
	// desired mirrors the target set currently in force, and freed reports a
	// straggler whose loop has exited. Only the supervisor goroutine mutates
	// `live`, so the cleanup goroutine signals instead of deciding anything.
	desired []Target
	freed   chan string
}

func newSupervisor(ctx context.Context, cfg Config) *supervisor {
	return &supervisor{
		ctx:        ctx,
		cfg:        cfg,
		live:       make(map[string]runningTarget),
		stragglers: make(map[string]runningTarget),
		freed:      make(chan string, 1),
	}
}

func (s *supervisor) logConfigWarnings() {
	cfg := s.cfg
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
	// Sub-second cadences are warned about, never rejected: -mtu-sweep below 1s
	// means continuous DF sweeping (a restricted path costs
	// ~2*log2(MaxPayloadBytes) probes per sweep), and
	// -targets-reload-interval below 1s re-parses the whole JSON file and logs
	// an unconditional Info line on every tick. Warn-only on purpose — tests
	// and embedders set these through Config directly, so rejecting would
	// break them, and neither is a correctness hazard.
	if cfg.MTUSweep > 0 && cfg.MTUSweep < time.Second {
		slog.Warn("MTU sweep interval below 1s; DF sweeping will run continuously",
			"mtu_sweep", cfg.MTUSweep, "fix", "raise -mtu-sweep (e.g. 5m) unless you are testing")
	}
	if cfg.TargetsPath != "" && cfg.ReloadInterval > 0 && cfg.ReloadInterval < time.Second {
		slog.Warn("Targets reload interval below 1s; the targets file will be re-read and logged every tick",
			"targets_reload_interval", cfg.ReloadInterval, "path", cfg.TargetsPath,
			"fix", "raise -targets-reload-interval (e.g. 30s)")
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
}

// markStraggler records name until its timed-out loop exits, then wakes
// the supervisor. Everything else — purging, /status removal, restarting
// the replacement — is decided THERE, because both the desired set and the
// target's absence can change while the old loop is still winding down:
// a removal that races the exit must not be missed (that left a ghost
// /status row and a frozen link_up series for the process lifetime).
func (s *supervisor) markStraggler(name string, r runningTarget) {
	s.cfg.Status.MarkStraggler(name, true)
	s.stragglersMu.Lock()
	s.stragglers[name] = r
	s.stragglersMu.Unlock()
	go func() {
		<-r.done
		// Wake the supervisor. Deliberately a BLOCKING send: a dropped
		// wake-up could leave this name permanently unprobed if its exit
		// raced the supervisor's apply. The channel buffers one value, so
		// with two stragglers one sender is briefly parked until the
		// supervisor returns to its select (which it always does: apply is
		// bounded by stragglerStopTimeout per target).
		select {
		case s.freed <- name:
		case <-s.ctx.Done():
			// RunClient is tearing down; nobody consumes the wake-up.
		}
	}()
}

func (s *supervisor) isStraggler(name string) bool {
	s.stragglersMu.Lock()
	defer s.stragglersMu.Unlock()
	_, ok := s.stragglers[name]
	return ok
}

// releaseStraggler clears one exited straggler and reproduces exactly what
// the clean stop path does for it: a removed target loses its series and its
// /status entry, an address change retires the old endpoint's series (the
// replacement is seeded by the following apply), and an interval/timeout
// change keeps them — still one endpoint, counters must stay continuous.
func (s *supervisor) releaseStraggler(name string) {
	s.stragglersMu.Lock()
	r, ok := s.stragglers[name]
	if ok {
		delete(s.stragglers, name)
	}
	s.stragglersMu.Unlock()
	// Clear the flag even for a name whose snapshot was already
	// removed (purge path deletes the whole entry): keeping the
	// /status row honest for the keep-case replacement matters.
	s.cfg.Status.MarkStraggler(name, false)
	if !ok {
		return
	}
	w, wanted := targetByName(s.desired, name)
	switch {
	case !wanted:
		deleteTargetSeries(s.cfg.Source, r.tg)
		s.cfg.Status.Remove(name)
	case w.Address != r.tg.Address:
		deleteTargetSeries(s.cfg.Source, r.tg)
	}
}

// start spawns one probe loop. Every loop context carries the RunClient
// root context's Done channel so its exit can distinguish "the process
// is shutting down" from "this loop was cancelled for a restart" — the
// distinction the runEchoLoop exit defer needs for its accounting.
func (s *supervisor) start(tg Target) {
	tctx, cancel := context.WithCancel(context.WithValue(s.ctx, runClientDoneKey{}, s.ctx.Done()))
	r := runningTarget{tg: tg, cancel: cancel, done: make(chan struct{})}
	s.live[tg.Name] = r
	go func() {
		defer close(r.done)
		probeTarget(tctx, tg, s.cfg)
	}()
}

// stop cancels a target's loop and joins it with a bound. It returns
// false when the join timed out (the loop may still be writing that
// target's series). purge additionally withdraws every metric series so
// a REMOVED target stops being exported — see deleteTargetSeries.
func (s *supervisor) stop(name string, purge bool) bool {
	r, ok := s.live[name]
	if !ok {
		return true
	}
	delete(s.live, name)
	r.cancel()
	// Bounded join: probeTarget exits promptly on cancel (its own
	// retry waits are at most 1s). A slow exit must not block a reload,
	// and a process shutdown (ctx.Done) must not wait sequentially per
	// target.
	select {
	case <-r.done:
		if purge {
			deleteTargetSeries(s.cfg.Source, r.tg)
			s.cfg.Status.Remove(name)
		}
		return true
	case <-s.ctx.Done():
		return false
	case <-time.After(stragglerStopTimeout):
		slog.Warn("Removed target probe loop did not stop in time", "target", name, "timeout", stragglerStopTimeout)
		return false
	}
}

// apply swaps the running set to match targets: removed targets stop and
// have their series deleted, changed targets restart with the new values
// (an address change also withdraws the old address's series — a retired IP
// must not keep exporting a frozen link_up; an interval/timeout change keeps
// them, still the same endpoint), new targets start fresh. targets must
// already be validated (LoadTargets and Config.Validate both do).
func (s *supervisor) apply(targets []Target) {
	if s.ctx.Err() != nil {
		return
	}
	s.desired = targets
	want := make(map[string]Target, len(targets))
	for _, tg := range targets {
		want[tg.Name] = tg
	}
	for name, r := range s.live {
		if s.ctx.Err() != nil {
			return
		}
		w, ok := want[name]
		if ok && w.Address == r.tg.Address && w.Interval == r.tg.Interval && w.Timeout == r.tg.Timeout {
			continue
		}
		// !ok means the target was removed from the file: purge it.
		if !s.stop(name, !ok) {
			if s.ctx.Err() != nil {
				return
			}
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
			ProberInternalErrors.WithLabelValues(s.cfg.Source, r.tg.Name, r.tg.Address, "stop_timeout").Inc()
			s.markStraggler(name, r)
			continue
		}
		if ok {
			// Same name but a different address is a DIFFERENT endpoint:
			// withdraw the old address's series, or a retired IP keeps
			// exporting its last link_up=1 for the life of the process (the
			// same frozen-green bug the removal purge fixes). An
			// interval/timeout change keeps the series: still one endpoint,
			// so its counters must stay continuous. Mark only the keep case
			// as a kept-series restart — a withdrawn series makes the old
			// exit accounting invisible, so no marker is needed there.
			if r.tg.Address != w.Address {
				deleteTargetSeries(s.cfg.Source, r.tg)
				s.cfg.Status.Remove(name)
			}
			SeedMetrics(s.cfg.Source, []Target{w})
			s.start(w)
		}
	}
	for _, tg := range targets {
		if s.isStraggler(tg.Name) {
			continue
		}
		if _, ok := s.live[tg.Name]; !ok {
			// A freed straggler whose series were kept (interval/timeout
			// change) restarts on the same series. No per-restart marker is
			// needed: the exit defer consults the root Done channel and
			// counts on every non-shutdown cancellation (the count is
			// invisible on withdrawn series — detached children).
			SeedMetrics(s.cfg.Source, []Target{tg})
			s.start(tg)
		}
	}
}

func (s *supervisor) reload() {
	if s.cfg.TargetsPath == "" {
		slog.Info("Targets reload requested but no -targets file is configured; ignoring")
		return
	}
	targets, err := LoadTargets(s.cfg.TargetsPath)
	if err != nil {
		// A broken file mid-edit must never take the monitor down:
		// keep probing the previous set.
		slog.Error("Targets reload failed; keeping previous targets", "path", s.cfg.TargetsPath, "err", err)
		return
	}
	if s.cfg.SkipSelf {
		// Mesh mode: the shared file lists every site including this one,
		// and the reload must drop self exactly as the initial load did.
		targets = FilterSelfTargets(targets, s.cfg.Source)
	}
	// The effective-window check needs the GLOBAL interval/timeout, so it
	// cannot live in LoadTargets: reject a reload that would build an
	// unbounded in-flight window rather than accept it and peg a core.
	if err := validatePendingWindow(s.cfg.BaseInterval, s.cfg.BaseTimeout, targets); err != nil {
		slog.Error("Targets reload rejected (in-flight window too large); keeping previous targets", "path", s.cfg.TargetsPath, "err", err)
		return
	}
	if len(targets) == 0 {
		// Respect the operator's intent (an empty array means "probe
		// nothing"), but name the consequence: this stops ALL probing and
		// purges every target's series, so a truncated or half-written
		// file that happens to parse as [] is loud rather than silent.
		slog.Warn("Targets file is empty; ALL probing stopped and every target's series will be purged",
			"path", s.cfg.TargetsPath)
	}
	slog.Info("Targets reloaded", "targets_count", len(targets))
	s.apply(targets)
}

func joinBounded(kind string, targets []joinTarget, budget *time.Timer) {
	for i, jt := range targets {
		select {
		case <-jt.done:
		case <-budget.C:
			stuck := make([]string, 0, len(targets)-i)
			for _, rest := range targets[i:] {
				stuck = append(stuck, rest.name)
			}
			slog.Warn("Probe loop did not stop within the bound; abandoning it",
				"loops", kind, "targets", strings.Join(stuck, ","), "timeout", stragglerStopTimeout)
			return
		}
	}
}

// drainLive waits for every live loop and any straggler up to stragglerStopTimeout
// so a wedged socket op cannot hang SIGTERM/Stop indefinitely. Each loop joins its
// own MTU sweep before returning.
func (s *supervisor) drainLive() {
	// Created here, not at RunClient scope: a timer started at startup
	// would already have fired by drain time and abandon every loop
	// instantly.
	budget := time.NewTimer(stragglerStopTimeout)
	defer budget.Stop()

	liveJoins := make([]joinTarget, 0, len(s.live))
	for name, r := range s.live {
		liveJoins = append(liveJoins, joinTarget{name: name, done: r.done})
	}
	joinBounded("live", liveJoins, budget)

	s.stragglersMu.Lock()
	stragglerJoins := make([]joinTarget, 0, len(s.stragglers))
	for name, r := range s.stragglers {
		stragglerJoins = append(stragglerJoins, joinTarget{name: name, done: r.done})
	}
	s.stragglersMu.Unlock()
	joinBounded("straggler", stragglerJoins, budget)
}

// warnStragglers re-states the stranded-target set at Warn level so a
// permanently wedged loop is visible to log alerting for the whole
// time the target stays unprobed (not just at mark time).
func (s *supervisor) warnStragglers() {
	s.stragglersMu.Lock()
	names := make([]string, 0, len(s.stragglers))
	for name := range s.stragglers {
		names = append(names, name)
	}
	s.stragglersMu.Unlock()
	if len(names) == 0 {
		return
	}
	slog.Warn("Probe targets stranded: loop did not exit in time; target is not being probed",
		"targets", strings.Join(names, ","), "count", len(names))
}

// RunClient starts probe loops for every target in cfg.Targets. Each
// target is probed in its own goroutine. Blocks until ctx is cancelled.
func RunClient(ctx context.Context, cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}

	s := newSupervisor(ctx, cfg)
	s.logConfigWarnings()
	SeedMetrics(cfg.Source, cfg.Targets)
	s.apply(cfg.Targets)

	stragglerReLog := time.NewTicker(stragglerReLogInterval)
	defer stragglerReLog.Stop()

	if cfg.ReloadSignal == nil && (cfg.ReloadInterval <= 0 || cfg.TargetsPath == "") {
		// Wait on ctx explicitly; drainLive uses a bounded timer and belongs only to shutdown.
		<-ctx.Done()
		s.drainLive()
		return nil
	}

	var reloadTick <-chan time.Time
	if cfg.ReloadInterval > 0 && cfg.TargetsPath != "" {
		t := time.NewTicker(cfg.ReloadInterval)
		defer t.Stop()
		reloadTick = t.C
	}
	for {
		if ctx.Err() != nil {
			s.drainLive()
			return nil
		}
		select {
		case <-ctx.Done():
			s.drainLive()
			return nil
		case <-cfg.ReloadSignal:
			s.reload()
		case <-reloadTick:
			s.reload()
		case <-stragglerReLog.C:
			s.warnStragglers()
		case name := <-s.freed:
			// A timed-out loop finally exited. Resolve it against the CURRENT
			// desired set, then re-apply so a still-wanted target gets its
			// replacement loop now that the straggler flag is cleared.
			s.releaseStraggler(name)
			s.apply(s.desired)
		}
	}
}
