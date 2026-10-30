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
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
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
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("read targets file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing symlinked targets file %q: a symlink lets another local user repoint the probes; point -targets at the real file", path)
	}
	if info.Mode().IsDir() {
		return nil, fmt.Errorf("targets path is a directory, not a file")
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

	// stragglers maps a name whose old probe loop did NOT join within
	// stragglerStopTimeout to that OLD loop (whose Target carries the labels a
	// purge needs). Such a loop may still be alive and still writing that
	// target's series, so a later reload must NOT start a second loop for the
	// name — two loops on one target double-count link_probes_sent_total and
	// break the loss ratio. The set lives at RunClient scope (not inside apply)
	// so it survives across reloads; the entry is removed by the SUPERVISOR
	// once the loop has actually exited (freed), and only then is the name's
	// fate decided.
	stragglers := make(map[string]running)
	var stragglersMu sync.Mutex
	// desired mirrors the target set currently in force, and freed reports a
	// straggler whose loop has exited. Only the supervisor goroutine mutates
	// `live`, so the cleanup goroutine signals instead of deciding anything.
	var desired []Target
	freed := make(chan string, 1)

	// markStraggler records name until its timed-out loop exits, then wakes
	// the supervisor. Everything else — purging, /status removal, restarting
	// the replacement — is decided THERE, because both the desired set and the
	// target's absence can change while the old loop is still winding down:
	// a removal that races the exit must not be missed (that left a ghost
	// /status row and a frozen link_up series for the process lifetime).

	markStraggler := func(name string, r running) {
		cfg.Status.MarkStraggler(name, true)
		stragglersMu.Lock()
		stragglers[name] = r
		stragglersMu.Unlock()
		go func() {
			<-r.done
			// Wake the supervisor. Deliberately a BLOCKING send: a dropped
			// wake-up could leave this name permanently unprobed if its exit
			// raced the supervisor's apply. The channel buffers one value, so
			// with two stragglers one sender is briefly parked until the
			// supervisor returns to its select (which it always does: apply is
			// bounded by stragglerStopTimeout per target).
			select {
			case freed <- name:
			case <-ctx.Done():
				// RunClient is tearing down; nobody consumes the wake-up.
			}
		}()
	}
	isStraggler := func(name string) bool {
		stragglersMu.Lock()
		defer stragglersMu.Unlock()
		_, ok := stragglers[name]
		return ok
	}
	// releaseStraggler clears one exited straggler and reproduces exactly what
	// the clean stop path does for it: a removed target loses its series and its
	// /status entry, an address change retires the old endpoint's series (the
	// replacement is seeded by the following apply), and an interval/timeout
	// change keeps them — still one endpoint, counters must stay continuous.
	releaseStraggler := func(name string) {
		stragglersMu.Lock()
		r, ok := stragglers[name]
		if ok {
			delete(stragglers, name)
		}
		stragglersMu.Unlock()
		// Clear the flag even for a name whose snapshot was already
		// removed (purge path deletes the whole entry): keeping the
		// /status row honest for the keep-case replacement matters.
		cfg.Status.MarkStraggler(name, false)
		if !ok {
			return
		}
		w, wanted := targetByName(desired, name)
		switch {
		case !wanted:
			deleteTargetSeries(cfg.Source, r.tg)
			cfg.Status.Remove(name)
		case w.Address != r.tg.Address:
			deleteTargetSeries(cfg.Source, r.tg)
		}
	}

	// start spawns one probe loop. Every loop context carries the RunClient
	// root context's Done channel so its exit can distinguish "the process
	// is shutting down" from "this loop was cancelled for a restart" — the
	// distinction the runEchoLoop exit defer needs for its accounting.
	start := func(tg Target) {
		tctx, cancel := context.WithCancel(context.WithValue(ctx, runClientDoneKey{}, ctx.Done()))
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
	apply := func(targets []Target) {
		desired = targets
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
				markStraggler(name, r)
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
				// A freed straggler whose series were kept (interval/timeout
				// change) restarts on the same series. No per-restart marker is
				// needed: the exit defer consults the root Done channel and
				// counts on every non-shutdown cancellation (the count is
				// invisible on withdrawn series — detached children).
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
		if cfg.SkipSelf {
			// Mesh mode: the shared file lists every site including this one,
			// and the reload must drop self exactly as the initial load did.
			targets = FilterSelfTargets(targets, cfg.Source)
		}
		// The effective-window check needs the GLOBAL interval/timeout, so it
		// cannot live in LoadTargets: reject a reload that would build an
		// unbounded in-flight window rather than accept it and peg a core.
		if err := validatePendingWindow(cfg.BaseInterval, cfg.BaseTimeout, targets); err != nil {
			slog.Error("Targets reload rejected (in-flight window too large); keeping previous targets", "path", cfg.TargetsPath, "err", err)
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

	// drainLive waits for every live probe loop to exit, then gives any
	// straggler one final bounded wait (stragglerStopTimeout). The BOUND on
	// both joins matters: the per-loop cancels make every loop exit promptly
	// in the normal case, but a wedged socket op (a UDP write with no
	// deadline) would otherwise block shutdown forever — SIGTERM ignored, no
	// log line saying why, until the process is killed. Each probe loop joins
	// its own MTU sweep before returning, so a sweep cannot outlive this drain
	// by more than one sliced read arm (mtuReadArm).
	//
	// One timer covers both joins: a single shutdown budget is what the
	// service manager gives us anyway. Names are logged at Warn so a target
	// that never joined is visible instead of silently abandoned.
	type joinTarget struct {
		name string
		done chan struct{}
	}
	drainLive := func() {
		// Created here, not at RunClient scope: a timer started at startup
		// would already have fired by drain time and abandon every loop
		// instantly.
		budget := time.NewTimer(stragglerStopTimeout)
		defer budget.Stop()
		joinBounded := func(kind string, targets []joinTarget) {
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

		liveJoins := make([]joinTarget, 0, len(live))
		for name, r := range live {
			liveJoins = append(liveJoins, joinTarget{name: name, done: r.done})
		}
		joinBounded("live", liveJoins)

		stragglersMu.Lock()
		stragglerJoins := make([]joinTarget, 0, len(stragglers))
		for name, r := range stragglers {
			stragglerJoins = append(stragglerJoins, joinTarget{name: name, done: r.done})
		}
		stragglersMu.Unlock()
		joinBounded("straggler", stragglerJoins)
	}

	// stragglerWarn re-states the stranded-target set at Warn level so a
	// permanently wedged loop is visible to log alerting for the whole
	// time the target stays unprobed (not just at mark time).
	stragglerWarn := func() {
		stragglersMu.Lock()
		names := make([]string, 0, len(stragglers))
		for name := range stragglers {
			names = append(names, name)
		}
		stragglersMu.Unlock()
		if len(names) == 0 {
			return
		}
		slog.Warn("Probe targets stranded: loop did not exit in time; target is not being probed",
			"targets", strings.Join(names, ","), "count", len(names))
	}

	stragglerReLog := time.NewTicker(stragglerReLogInterval)
	defer stragglerReLog.Stop()

	if cfg.ReloadSignal == nil && (cfg.ReloadInterval <= 0 || cfg.TargetsPath == "") {
		// No reload path: block until shutdown, which is the only thing that
		// ends a probe loop (probeTarget restarts itself on every internal
		// failure, so a loop's done channel closes only on cancellation).
		//
		// Do NOT call drainLive() here: its join is deliberately BOUNDED
		// (stragglerStopTimeout) so a wedged socket op cannot hang Stop, and
		// using it as the steady-state wait made a plain client run return
		// after five seconds — run() then took modeDone, shut the metrics
		// server down and exited, i.e. every deployment without -targets died
		// five seconds after start while looking healthy. Wait on ctx
		// explicitly; the bounded drain belongs to shutdown.
		<-ctx.Done()
		drainLive()
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
			drainLive()
			return nil
		case <-cfg.ReloadSignal:
			reload()
		case <-reloadTick:
			reload()
		case <-stragglerReLog.C:
			stragglerWarn()
		case name := <-freed:
			// A timed-out loop finally exited. Resolve it against the CURRENT
			// desired set, then re-apply so a still-wanted target gets its
			// replacement loop now that the straggler flag is cleared.
			releaseStraggler(name)
			apply(desired)
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
	// pi-lens-ignore: waitgroup-done-scope
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// stopDrain resets a timer and drains a possibly-queued tick so Reset
// starts clean (Go's Reset contract), shared by three sites.
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

// rttSeconds computes one RTT sample from a matched send/receive pair, and
// reports ok=false when the instants are out of order. A negative sample must
// never be published: link_rtt_seconds_sum is a Prometheus sum, so observing
// one DECREASES it (rate() reads negative), and AdaptiveStats feeds the value
// into SRTT/RTTVAR, collapsing the RTO floor to its minimum and fabricating
// loss on a link that answered. Both instants come from time.Now() and
// therefore carry the monotonic reading, so time.Time.Sub is immune to a wall
// clock step — the UnixNano subtraction this replaces was not. QPC wins when
// both sides carry a counter reading: Go's time.Now() is interrupt-time
// quantized on Windows (sub-quantum RTTs compute as exactly 0 there, pinning
// SRTT to 0 and the RTO to its floor), while the counter pair restores ~100ns
// fidelity.
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

// probeExpired reports whether an in-flight probe has used up its timeout.
// A sentAt in the FUTURE counts as EXPIRED. Both instants are time.Time carrying
// the monotonic reading, so a wall clock step (VM snapshot restore, chrony/NTP
// step, manual `date`) can no longer move sentAt or now — this check is
// defensive, not the load-bearing guard it was for the old UnixNano arithmetic.
// It stays because the failure it prevents is catastrophic: entries stuck in
// the future never retire, they accumulate until maxPendingWindow throttles
// every send, and nothing is probed while link_up stays 1 — the worst failure
// mode for a monitor. If it ever DOES fire, the observable effect is a single
// tick that sweeps the whole pending set: link_probes_timed_out_total jumps by
// N, consecutiveMisses can cross LinkUpMissThreshold (one interval of
// link_up=0) and the loss ratio reads elevated for one window. The balance
// stays exact because the sweep is a normal pending exit (timed_out + inflight).
// The comparison is strictly greater: a probe exactly at its timeout is retired
// by the next tick, which is the documented loss deadline (the first probe tick
// AFTER the RTO expires).
func probeExpired(now, sentAt time.Time, timeout time.Duration) bool {
	if now.Before(sentAt) {
		return true
	}
	return now.Sub(sentAt) > timeout
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

	// respCh buffers in-flight responses between the reader and the drain.
	// Size scales with expected max inflight (timeout/interval) so aggressive
	// intervals (e.g. 10ms/3s => 300) do not stall the reader. With
	// -adaptive the applied timeout is the RFC 6298 RTO whose max(200ms,
	// 2*SRTT) floor is unbounded above, so the STATIC pair under-counts:
	// a healthy long-haul link can legitimately hold maxPendingWindow
	// probes in flight, and a channel sized from the static pair then
	// back-pressures the reader — parked in the send select, the kernel
	// drops further echoes, which get swept as timed_out on a link that
	// answered everything (fabricated loss on a healthy link). Under
	// adaptive the channel is therefore sized to the same cap the send
	// site enforces (maxPendingWindow); under a static pair the validated
	// window always fits by construction.
	respCh := make(chan response, responseBufferCapacity(cfg))

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
		// Same panic contract as the echo loop below: a reader panic is
		// per-event corruption, not a link condition. close(readerDone)
		// still fires (deferred above), so the main loop re-dials via the
		// errReaderDead path instead of probing into a void, and the
		// failure is counted and logged at Error rather than vanishing.
		defer func() {
			if r := recover(); r != nil {
				logger.Error("Panic in UDP reader; stopping reader", "panic", r)
				m.internalPanic.Inc()
			}
		}()
		// Read into a buffer larger than the payload so an oversized
		// datagram is not silently truncated to PayloadSize by the kernel
		// and mistaken for a valid probe (Read truncates to the buffer).
		// Frame shape: constant for this socket's lifetime (depends only
		// on configuration fixed at loop start).
		expectedSize := PayloadSize
		if cfg.EchoSecret != "" {
			expectedSize = PayloadSizeWithHMAC
		}
		expectedSize += cfg.Payload
		buf := make([]byte, MaxDatagramSize)
		// Scratch for regenerating the expected payload pattern; reused
		// across packets (single reader goroutine).
		var payloadScratch []byte
		if cfg.Payload > 0 {
			payloadScratch = make([]byte, cfg.Payload)
		}
		// One reusable HMAC state for the reader goroutine (the send loop
		// has its own; crypto/hmac state is not safe for concurrent use).
		var rMac *probeMACer
		if cfg.EchoSecret != "" {
			rMac = newProbeMACer(cfg.EchoSecret)
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
			// Stamp the receive instant BEFORE any validation: the size,
			// magic and (with -echo-secret) full-frame HMAC gates cost 1-3us
			// of SHA-256, which is material on LAN RTTs and would bias every
			// sample by that amount. Everything after this line is our own
			// filtering, not time on the wire.
			recvAt := time.Now()
			recvQPC, _ := qpcNow()
			if n != expectedSize {
				continue
			}
			if string(buf[0:8]) != MagicBytes {
				continue
			}

			seq := binary.LittleEndian.Uint64(buf[8:16])
			ts := binary.LittleEndian.Uint64(buf[16:24])
			if cfg.EchoSecret != "" {
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
				if cfg.HmacCoverage == HMACFullFrameCoverage && cfg.Payload > 0 {
					if !rMac.verifyFullFrame(buf[:n]) {
						continue
					}
				} else if !rMac.verifyHeader(seq, ts, buf[24:32]) {
					continue
				}
			}
			resp := response{seq: seq, ts: ts, recvAt: recvAt, recvQPC: recvQPC}
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
			case respCh <- resp:
			default:
				select {
				case respCh <- resp:
				case <-ctx.Done():
					return
				case <-done:
					return
				}
			}
		}
	}()

	var warnedSlowRTT bool
	writeFails := 0
	// warnedWriteDown makes the Error log fire once per failure streak
	// (the drop itself is re-asserted on every failing tick).
	warnedWriteDown := false
	// warnedThrottle makes the pending-window throttle Warn fire once per
	// sustained-throttle streak; reset on the next successful send.
	warnedThrottle := false
	payloadSize := PayloadSize
	if cfg.EchoSecret != "" {
		payloadSize = PayloadSizeWithHMAC
	}
	buf := make([]byte, payloadSize+cfg.Payload)
	// One reusable HMAC state for the send loop; the reader goroutine has
	// its own (crypto/hmac state is not safe for concurrent use).
	var mac *probeMACer
	if cfg.EchoSecret != "" {
		mac = newProbeMACer(cfg.EchoSecret)
	}
	pendingHighWater := 0
	// started bounds the socket lifetime: once ReconnectInterval has
	// elapsed and no probes are in flight, the loop returns errReconnect
	// so the caller re-dials and re-resolves DNS.
	started := time.Now()

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
	pending := make(map[uint64]sentStamp)

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
				st, ok := pending[resp.seq]
				if !ok {
					continue
				}
				if resp.ts != uint64(st.sentNS) {
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
					if writeFails < maxConsecutiveWriteFails {
						m.linkUp.Set(1)
						state.linkUp = true
					}
					state.lastEcho = resp.recvAt
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
				// Re-arm link_up only while local sends are healthy. An echo
				// that lands after the write-failure streak reached the
				// threshold proves the far end was reachable, NOT that this
				// socket can still send: re-arming unconditionally used to
				// freeze link_up at 1 forever, because the down transition
				// below fires once (writeFails keeps growing past the
				// threshold, so an equality test never matches again) and
				// the pending set empties, leaving no misses to count.
				if writeFails < maxConsecutiveWriteFails {
					m.linkUp.Set(1)
					state.linkUp = true
				}
				state.lastEcho = resp.recvAt
			default:
				return
			}
		}
	}

	defer func() {
		// Close the socket FIRST and give the reader one bounded join
		// before any accounting: the reader can be parked in its send-select
		// or mid-parse of an already-read datagram, and an echo it pushes in
		// AFTER the non-blocking drain below would be charged as a timeout
		// on a probe the link actually answered — fabricated loss. conn
		// Close unblocks its Read (net.ErrClosed), readerDone closes when
		// the goroutine exits on any path, and the bound keeps a wedged
		// reader from stretching any join deadline (Stop's 20s, a reload's
		// 5s stragglerStopTimeout). The join cost is paid once per loop exit,
		// never per event. (Deliberately also fixes the panic-recovery drain
		// below, which runs inside this same defer.)
		// pi-lens-ignore: go-ignored-call-result
		_ = conn.Close()
		select {
		case <-readerDone:
		case <-time.After(mtuReadArm):
		}
		if r := recover(); r != nil {
			logger.Error("Panic in echo loop; continuing", "panic", r)
			retErr = fmt.Errorf("panic in echo loop: %v", r)
			// Drain any echo already received before flushing: it was
			// delivered, not lost, and charging it as a timeout would
			// fabricate loss. The remaining abandoned probes can never match
			// on this socket, so they are counted as timed out to keep
			// sent = rtt_count + timed_out + inflight balancing across the
			// restart (same treatment as the reconnect flush). The flush is
			// UNCONDITIONAL — a panicking loop is never a process shutdown
			// (shutdown cancels the context; the loop returns normally), the
			// supervisor restarts it, and its series stay exported — and it
			// clears pending: the tail below would otherwise re-run its own
			// accounting (a RunClient-managed restart exits with the root
			// context still alive, so runClientShuttingDown is false and the
			// tail re-adds) and every abandoned probe would be counted
			// twice, over-reporting loss through the balance invariant.
			drainResponses()
			if n := len(pending); n > 0 {
				m.timedOut.Add(float64(n))
				m.inflight.Sub(float64(n))
				pending = make(map[uint64]sentStamp)
			}
		}
		// Probes still in flight die with the loop on cancellation. Whether
		// they must also be counted as timed out depends on whether the
		// series stays exported after this exit:
		// - Process shutdown (the RunClient root context is done): every
		//   series stops being exported, so counting them would fabricate
		//   loss — inflight-only accounting (pinned by
		//   TestGracefulShutdown_NoPhantomTimeouts).
		// - A restart (reload keep-restart, straggler replacement, removal,
		//   address change): the series either stays attached — the balance
		//   must hold on the live series, so drain delivered echoes (they
		//   count as RTT, not loss) and count the remaining abandoned probes
		//   as timed out (the reconnect-flush convention) — or was just
		//   withdrawn (detached children make the count invisible).
		// The straggler case exits on its own with the root still alive and
		// gets the same treatment; releaseStraggler decides keep-or-purge
		// afterwards, and a purged series only detaches the (invisible)
		// children.
		if !runClientShuttingDown(ctx) {
			drainResponses()
			if n := len(pending); n > 0 {
				m.timedOut.Add(float64(n))
			}
		}
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
			pending = make(map[uint64]sentStamp)
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
		// Publish the applied timeout for the MTU sweep's probe deadline (see
		// mtuDeadline): on an adaptive link the RTO can be well above
		// cfg.BaseTimeout, and a sweep that waited only -timeout would fail
		// every DF probe there.
		state.rtoNs.Store(int64(timeout))

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
			// The socket that just lost its reader can no longer deliver
			// echoes: zero socketStart so the re-emit below — the snapshot
			// /readyz is built on — reports socket_age_seconds=0 for the whole
			// bounded re-dial pause instead of a stale age from a dead socket.
			state.socketStart = time.Time{}
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
			for s, st := range pending {
				if probeExpired(now, st.sentAt, timeout) {
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
			pending = make(map[uint64]sentStamp)
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
			// Drain first, like the reader-dead and panic exits: an echo that
			// already reached respCh answered a probe, and charging it as loss
			// would fabricate wire loss on a healthy link.
			drainResponses()
			flushPending()
			return errReconnect
		}

		// Pending-window send throttle: the static interval/timeout pair is
		// validated at startup and reload (validatePendingWindow), but with
		// -adaptive the applied timeout is the RFC 6298 RTO, whose floor
		// max(200ms, 2*SRTT) is unbounded above — a large-SRTT link with a
		// fast interval would otherwise grow `pending` past the cap and
		// sweep all of it on every tick. When the window is at the cap, SKIP
		// the send for this tick: no frame is built, nothing reaches the
		// wire, and neither sent nor inflight moves — the balance invariant
		// is untouched because the probe never existed (this is NOT a
		// pending exit path). The skip is a measured probe-rate reduction,
		// not loss; it is counted in link_probes_throttled_total, which
		// stays outside the balance by design (like send errors).
		if len(pending) >= maxPendingWindow {
			m.throttled.Inc()
			if !warnedThrottle {
				// Bounded like the write-failure warning: once per
				// sustained-throttle streak, Warn level (Debug is invisible
				// at default verbosity). Reset on the next successful send.
				warnedThrottle = true
				logger.Warn("Pending window is full; skipping probe sends until probes resolve",
					"pending", len(pending), "window", maxPendingWindow)
			}
			continue
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
		seq := state.seq + 1
		ts := uint64(sendNS)
		// One spelling of the wire layout, shared with the MTU sweep:
		// see buildProbeFrame.
		buildProbeFrame(buf, seq, ts, cfg.Payload, mac, cfg.HmacCoverage)

		// Send first, then register: registering in-flight only after a
		// successful write means a failed or panicking write can never
		// orphan a gauge increment (every pending entry has exactly one
		// matching inflight unit, so any exit-path flush balances).
		// The write is deadline-bounded like the MTU sweep's probes (mtu.go):
		// a UDP write can block when the local send buffer is saturated, and a
		// wedged write would otherwise hang this loop — and therefore
		// shutdown/reload — with no way out but SIGKILL.
		// pi-lens-ignore: go-ignored-call-result
		_ = conn.SetWriteDeadline(time.Now().Add(timeout))
		if _, err := conn.Write(buf); err != nil {
			writeFails++
			m.sendErr.Inc()
			if writeFails >= maxConsecutiveWriteFails {
				if !warnedWriteDown {
					// Sustained local write failures mean nothing is being
					// probed while consecutiveMisses stays frozen — the worst
					// failure mode is link_up stuck at 1. Escalate once at
					// Error (Debug is invisible at default verbosity) and
					// reflect reality in the gauge.
					warnedWriteDown = true
					logger.Error("Persistent UDP write failures; marking link down",
						"consecutive_failures", writeFails, "err", err)
				}
				// Idempotent on purpose: unlike the old `==` transition this
				// re-asserts reality on every failing tick, so an echo drained
				// by an earlier stage of this same iteration can never leave
				// the gauge green while no probe can leave the host.
				wasUp := state.linkUp
				m.linkUp.Set(0)
				state.linkUp = false
				if wasUp {
					// Re-emit /status so the dropped link_up is visible immediately
					// rather than up to a full interval later.
					emitTargetStatus(m, state, stats, timeout, writeFails, len(pending))
				}
			}
			continue
		}
		writeFails = 0
		warnedWriteDown = false
		warnedThrottle = false
		state.seq = seq

		pending[state.seq] = sentStamp{sentAt: sentAt, sentNS: sendNS, qpc: sendQPC}
		m.inflight.Inc()
		m.sent.Inc()
	}
}
