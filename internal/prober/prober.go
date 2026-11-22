// Package prober implements a UDP echo probing engine for measuring
// network latency and packet loss. It provides both a server (UDP echo
// responder) and a client (active prober with adaptive RTO).
//
// Wire format: 24 bytes per probe — 8-byte magic header "LNKPING\x00",
// 8-byte little-endian sequence number, 8-byte Unix-ns timestamp.
// The server validates the magic header before echoing; invalid datagrams
// are dropped.
//
// UDP is used deliberately: no retransmission means a probe without an
// echo within the RTO is genuinely lost on the wire, so the loss ratio
// is exact rather than masked by TCP retransmission.
package prober

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

// syscallConn is implemented by *net.UDPConn; the platform-specific
// socket-option helpers (DSCP on Linux, DF on Linux+Windows) use it to
// reach the raw descriptor.
type syscallConn interface {
	SyscallConn() (syscall.RawConn, error)
}

// Protocol constants.
const (
	DefaultAlpha    = 0.125
	DefaultBeta     = 0.25
	// DefaultClockGranularity is G in RFC 6298: the granularity of the
	// clock used to measure RTT, used as the lower bound for 4*RTTVAR.
	DefaultClockGranularity = time.Millisecond
	// DefaultMinRTO floors the adaptive RTO to prevent false positive
	// timeouts caused by normal latency jitter.
	DefaultMinRTO = 200 * time.Millisecond
	DefaultMaxRTO = 3 * time.Second
	// LinkUpMissThreshold is the number of consecutive probes without an
	// echo before link_up drops to 0 (enterprise health-check convention:
	// down after N failures, so single losses don't flap the state).
	LinkUpMissThreshold = 3
	MaxTargetsFileSize  = 1 << 20
	MaxTargetsCount     = 1000
)

// ReconnectInterval bounds how long a client keeps one UDP socket before
// re-dialing so a target hostname that changes IP via DNS is re-resolved.
// The re-dial normally happens with no probes in flight, but when the probe
// interval is shorter than the RTO probes are perpetually in flight; those
// are abandoned by the socket swap and counted as timed out
// (link_probes_timed_out_total), which keeps the
// sent/rtt/timedout/inflight balance intact across the re-dial. A variable
// (not a constant) so tests can lower it.
var ReconnectInterval = 5 * time.Minute

// Config holds the client probing configuration.
type Config struct {
	// Source is the topology label applied to every metric series, e.g.
	// the local datacenter or site name ("sydney-dc").
	Source  string
	Targets []Target
	// SkipSelf is the mesh-mode (-allow-from-targets) marker: the caller has
	// already removed the target whose Name equals Source, and the reload
	// path must apply that same removal so a hot reload cannot re-add the
	// local site as a probe target.
	SkipSelf     bool
	Adaptive     bool
	BaseInterval time.Duration
	BaseTimeout  time.Duration
	// EchoSecret, when non-empty, enables HMAC-SHA256 authentication of
	// UDP probes to mitigate reflector spoofing (SEC22). When set, probes
	// are 32 bytes (magic+seq+timestamp+hmac8); otherwise 24 bytes for
	// backward compatibility.
	EchoSecret string
	// ReconnectInterval bounds how long a UDP socket is kept before
	// re-dialing for DNS re-resolution. Zero means use the global
	// ReconnectInterval var (test compat).
	ReconnectInterval time.Duration
	// Payload, when > 0, sends probes of header+Payload bytes with a
	// deterministic pattern validated on echo. Corruption is counted in
	// link_probes_corrupted_total (distinct from loss). Must be ≤
	// MaxPayloadBytes so probes are never fragmented.
	Payload int
	// HmacCoverage selects which frame bytes the HMAC tag covers when
	// EchoSecret is set: the 24-byte header only (the Go zero value and
	// the -hmac-coverage=header escape hatch, byte-identical to the v0.7
	// wire format) or the header plus the pattern payload (the flag
	// default, HMACFullFrameCoverage), so a tampered payload — or a
	// payload riding a captured tag — no longer authenticates. Only
	// meaningful with EchoSecret AND Payload > 0: the two coverages
	// produce byte-identical tags for zero-payload frames.
	HmacCoverage HmacCoverage
	// MTUSweep, when > 0, runs a periodic DF-bit sweep per target to
	// discover the largest frame the path carries (link_path_mtu_bytes,
	// /status path_mtu_bytes). 0 disables. Linux and Windows (IPv4 from
	// Server 2003 via the DF flag, 1703+/Server 2019+ through full path-MTU
	// discovery; IPv6 needs the latter); a platform without the socket
	// option disables just the sweep with a one-time warning. Sweep
	// counters are separate from the loss metrics.
	MTUSweep time.Duration
	// DSCP, when 1-63, marks probe packets with that traffic class
	// (e.g. 46 = EF) so QoS-managed networks class them accordingly.
	// 0 (default) leaves packets unmarked. Best effort, Linux support.
	DSCP int
	// Status, when non-nil, receives a live per-target snapshot each
	// probe interval for the /status debug endpoint. Nil in server-only
	// mode and unit tests (Update is nil-receiver-safe).
	Status *StatusRegistry
	// TargetsPath is the -targets file path for hot-reload. When set,
	// reloads re-read and re-validate it; a broken file keeps the
	// previous set running.
	TargetsPath string
	// ReloadSignal, when non-nil, triggers a targets reload on receive
	// (SIGHUP via signal.Notify in main; direct send in tests). A nil
	// channel never fires. The received value is ignored.
	ReloadSignal <-chan os.Signal
	// ReloadInterval, when > 0, polls TargetsPath at this interval for
	// Windows services (no SIGHUP). 0 disables polling.
	ReloadInterval time.Duration
}

// minProbeInterval is the smallest accepted probe interval and timeout.
const minProbeInterval = time.Millisecond

// maxPendingWindow caps timeout/interval per target to bound the in-flight map
// and the matching reader response channel capacity.
const maxPendingWindow = 1000

// maxProbeTimeout bounds configured probe timeouts within safe int64 Duration math.
const maxProbeTimeout = 24 * time.Hour

// checkPendingWindow rejects an interval/timeout pair whose in-flight window exceeds maxPendingWindow.
func checkPendingWindow(interval, timeout time.Duration) error {
	if interval <= 0 || timeout <= 0 {
		return nil
	}
	// Compare by division to avoid int64 overflow in maxPendingWindow*interval.
	quotient, remainder := timeout/interval, timeout%interval
	if quotient < maxPendingWindow || (quotient == maxPendingWindow && remainder == 0) {
		return nil
	}
	return fmt.Errorf("probe timeout %v is more than %d probe intervals (%v): the in-flight window would hold ~%d probes per target, and every probe tick scans all of them; lower -timeout or raise -interval",
		timeout, maxPendingWindow, interval, int(timeout/interval))
}

// validatePendingWindow applies the effective-window check to the global pair
// and to every per-target override (a target's own interval/timeout wins over
// the global one). Called at startup and again on every reload, so a hand-edited
// targets file cannot introduce an unbounded window either.
func validatePendingWindow(baseInterval, baseTimeout time.Duration, targets []Target) error {
	if err := checkPendingWindow(baseInterval, baseTimeout); err != nil {
		return err
	}
	for _, t := range targets {
		interval, timeout := baseInterval, baseTimeout
		if t.Interval != 0 {
			interval = t.Interval
		}
		if t.Timeout != 0 {
			timeout = t.Timeout
		}
		if err := checkPendingWindow(interval, timeout); err != nil {
			return fmt.Errorf("target %q: %w", t.Name, err)
		}
	}
	return nil
}

// validateDurationBounds validates a probe interval or timeout value.
func validateDurationBounds(label string, d time.Duration, allowZero bool) error {
	if allowZero && d == 0 {
		return nil
	}
	if d <= 0 {
		return fmt.Errorf("%s must be positive, got %v", label, d)
	}
	if d < minProbeInterval {
		return fmt.Errorf("%s must be at least %v, got %v", label, minProbeInterval, d)
	}
	if d > maxProbeTimeout {
		return fmt.Errorf("%s must be at most %v, got %v", label, maxProbeTimeout, d)
	}
	return nil
}

// Validate checks that at least one target is present and that all
// target addresses are well-formed.
func (c Config) Validate() error {
	if len(c.Targets) == 0 {
		return errors.New("no targets specified")
	}
	if err := validateDurationBounds("probe interval (-interval)", c.BaseInterval, false); err != nil {
		return err
	}
	if err := validateDurationBounds("probe timeout (-timeout)", c.BaseTimeout, false); err != nil {
		return err
	}
	if c.ReconnectInterval < 0 {
		return fmt.Errorf("reconnect interval must be >= 0, got %v", c.ReconnectInterval)
	}
	if c.ReloadInterval < 0 {
		return fmt.Errorf("targets reload interval must be >= 0, got %v", c.ReloadInterval)
	}
	if c.DSCP < 0 || c.DSCP > 63 {
		return fmt.Errorf("dscp must be 0-63, got %d", c.DSCP)
	}
	if c.Payload < 0 || c.Payload > MaxPayloadBytes {
		return fmt.Errorf("payload must be 0-%d bytes, got %d", MaxPayloadBytes, c.Payload)
	}
	if c.MTUSweep < 0 {
		return fmt.Errorf("mtu sweep interval must be >= 0, got %v", c.MTUSweep)
	}
	if c.HmacCoverage != HMACHeaderCoverage && c.HmacCoverage != HMACFullFrameCoverage {
		return fmt.Errorf("hmac coverage must be header or full-frame, got %d", c.HmacCoverage)
	}
	if c.ReconnectInterval != 0 && c.ReconnectInterval < c.BaseInterval {
		return fmt.Errorf("reconnect interval %v must be >= probe interval %v", c.ReconnectInterval, c.BaseInterval)
	}
	if err := validateTargets(c.Targets); err != nil {
		return err
	}
	return validatePendingWindow(c.BaseInterval, c.BaseTimeout, c.Targets)
}

// validateTargets checks each target's address and name and rejects
// duplicate names (target names are Prometheus label values).
func validateTargets(targets []Target) error {
	seen := make(map[string]struct{}, len(targets))
	for _, t := range targets {
		if err := ValidateTarget(t.Address); err != nil {
			return fmt.Errorf("target %q: %w", t.Name, err)
		}
		if err := ValidateTargetName(t.Name); err != nil {
			return fmt.Errorf("target %q: %w", t.Name, err)
		}
		if err := validateDurationBounds("interval", t.Interval, true); err != nil {
			return fmt.Errorf("target %q: %w", t.Name, err)
		}
		if err := validateDurationBounds("timeout", t.Timeout, true); err != nil {
			return fmt.Errorf("target %q: %w", t.Name, err)
		}
		if _, dup := seen[t.Name]; dup {
			return fmt.Errorf("duplicate target name %q: metric labels would be ambiguous", t.Name)
		}
		seen[t.Name] = struct{}{}
	}
	return nil
}
