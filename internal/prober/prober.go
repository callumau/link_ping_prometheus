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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
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
	MagicBytes          = "LNKPING\x00"
	PayloadSize         = 24
	PayloadSizeWithHMAC = 32
	// MaxPayloadBytes caps the optional client payload beyond the header.
	// Frames stay well under MaxDatagramSize (1500) so a probe is never
	// IP-fragmented: header (24, or 32 with -echo-secret) + payload, i.e.
	// at most 1424 bytes normally and 1432 with HMAC.
	MaxPayloadBytes = 1400
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
	Source       string
	Targets      []Target
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

// minProbeInterval is the smallest accepted probe interval. Below it the
// in-flight set grows to ~RTO/interval entries and every tick sweeps
// O(len(pending)) timeouts, pegging a core — and the loss ratio becomes
// meaningless. Rejected at config load with an error naming the flag.
const minProbeInterval = time.Millisecond

// maxPendingWindow caps the effective timeout/interval ratio, i.e. how many
// probes may be in flight per target at once. minProbeInterval bounds the
// denominator; this bounds the numerator, which was unlimited: a 1ms interval
// with a 1m timeout built a ~60k-entry pending map per target and swept all of
// it on every tick (a pegged core, and hundreds of MB with a full targets
// file). The cap matches the reader channel's own 1000-response ceiling, so a
// config inside the limit cannot outrun the drain either.
const maxPendingWindow = 1000

// checkPendingWindow rejects an effective interval/timeout pair whose in-flight
// window would be unbounded (see maxPendingWindow). The error names the flags
// so the operator knows what to change: the timeout is what must come down.
func checkPendingWindow(interval, timeout time.Duration) error {
	if interval <= 0 || timeout <= maxPendingWindow*interval {
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

// Validate checks that at least one target is present and that all
// target addresses are well-formed.
func (c Config) Validate() error {
	if len(c.Targets) == 0 {
		return errors.New("no targets specified")
	}
	if c.BaseInterval <= 0 {
		return fmt.Errorf("probe interval must be positive, got %v", c.BaseInterval)
	}
	if c.BaseInterval < minProbeInterval {
		return fmt.Errorf("probe interval (-interval) must be at least %v, got %v", minProbeInterval, c.BaseInterval)
	}
	if c.BaseTimeout <= 0 {
		return fmt.Errorf("probe timeout must be positive, got %v", c.BaseTimeout)
	}
	if c.ReconnectInterval < 0 {
		return fmt.Errorf("reconnect interval must be >= 0, got %v", c.ReconnectInterval)
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
	if c.ReconnectInterval != 0 && c.ReconnectInterval < c.BaseInterval {
		return fmt.Errorf("reconnect interval %v must be >= probe interval %v", c.ReconnectInterval, c.BaseInterval)
	}
	if err := validateTargets(c.Targets); err != nil {
		return err
	}
	return validatePendingWindow(c.BaseInterval, c.BaseTimeout, c.Targets)
}

// validateTargets checks each target's address and name and rejects
// duplicate names (target names are Prometheus label values, so
// duplicates would produce ambiguous metric series). Shared by
// Config.Validate and LoadTargets.
func validateTargets(targets []Target) error {
	seen := make(map[string]struct{}, len(targets))
	for _, t := range targets {
		if err := ValidateTarget(t.Address); err != nil {
			return fmt.Errorf("target %q: %w", t.Name, err)
		}
		if err := ValidateTargetName(t.Name); err != nil {
			return fmt.Errorf("target %q: %w", t.Name, err)
		}
		if t.Interval < 0 {
			return fmt.Errorf("target %q: interval must be >= 0, got %v", t.Name, t.Interval)
		}
		if t.Interval != 0 && t.Interval < minProbeInterval {
			return fmt.Errorf("target %q: interval must be at least %v, got %v", t.Name, minProbeInterval, t.Interval)
		}
		if t.Timeout < 0 {
			return fmt.Errorf("target %q: timeout must be >= 0, got %v", t.Name, t.Timeout)
		}
		if _, dup := seen[t.Name]; dup {
			return fmt.Errorf("duplicate target name %q: metric labels would be ambiguous", t.Name)
		}
		seen[t.Name] = struct{}{}
	}
	return nil
}

// fillPayload writes a deterministic pattern into the probe payload,
// derived from the frame's own seq/ts. The client regenerates the
// pattern from the echoed header and compares byte-for-byte: any
// in-flight corruption (or reflection of a wrong frame) surfaces as a
// corrupted frame — counted separately from loss — instead of as a
// valid-but-wrong RTT sample.
func fillPayload(buf []byte, seq, ts uint64) {
	// xorshift64* keyed by seq/ts: cheap, deterministic, well spread.
	x := seq*0x9E3779B97F4A7C15 ^ ts
	for i := range buf {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		buf[i] = byte(x >> 24)
	}
}

// computeHMAC returns truncated HMAC-SHA256 (first 8 bytes) over
// magic+seq+timestamp. Used when EchoSecret is set to authenticate
// probes and mitigate reflector spoofing (SEC22). Truncation keeps
// payload at 32 bytes while retaining 64-bit forgery resistance.
func computeHMAC(key string, seq, ts uint64) [8]byte {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(MagicBytes))
	var tmp [16]byte
	binary.LittleEndian.PutUint64(tmp[0:8], seq)
	binary.LittleEndian.PutUint64(tmp[8:16], ts)
	mac.Write(tmp[:])
	sum := mac.Sum(nil)
	var out [8]byte
	copy(out[:], sum[:8])
	return out
}

// validHMAC reports whether the supplied 8-byte tag matches the
// expected HMAC for the given seq/ts and key. Constant-time compare
// via hmac.Equal.
func validHMAC(key string, seq, ts uint64, tag []byte) bool {
	expected := computeHMAC(key, seq, ts)
	return hmac.Equal(expected[:], tag)
}

// validHMACAny reports whether the tag matches the primary secret or,
// during a zero-downtime rotation, the previous secret. secretOld is
// empty when no rotation is in progress. Constant-time per attempt.
func validHMACAny(secret, secretOld string, seq, ts uint64, tag []byte) bool {
	if validHMAC(secret, seq, ts, tag) {
		return true
	}
	return secretOld != "" && validHMAC(secretOld, seq, ts, tag)
}
