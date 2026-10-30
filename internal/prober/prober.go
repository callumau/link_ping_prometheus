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
	"hash"
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

// minProbeInterval is the smallest accepted probe interval, and the smallest
// accepted probe timeout. Below it the in-flight set grows to ~RTO/interval
// entries and every tick sweeps O(len(pending)) timeouts, pegging a core — and
// the loss ratio becomes meaningless. The same floor on the timeout is a
// correctness bound, not a cost one: a sub-millisecond timeout expires before
// any echo can return over a real link, so every probe reads as loss (fabricated
// 100% loss). Rejected at config load with an error naming the flag.
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
	// Non-positive values are Config.Validate's business (they fail there with
	// their own errors); the window check passes them, as it always did.
	if interval <= 0 || timeout <= 0 {
		return nil
	}
	// Compare by division, never by maxPendingWindow*interval: that product
	// overflows int64 once interval passes ~106 days (1000 × 292 years of
	// nanoseconds), and a wrapped product is a nonsense bound — it rejected
	// absurd-but-flag-supported intervals that were in fact fine. The
	// quotient/remainder form is exactly equivalent to
	// "timeout > maxPendingWindow*interval" without the overflow.
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
	if c.BaseTimeout < minProbeInterval {
		return fmt.Errorf("probe timeout (-timeout) must be at least %v, got %v", minProbeInterval, c.BaseTimeout)
	}
	if c.ReconnectInterval < 0 {
		return fmt.Errorf("reconnect interval must be >= 0, got %v", c.ReconnectInterval)
	}
	if c.ReloadInterval < 0 {
		// A negative -targets-reload-interval silently DISABLED hot reload
		// (ticker construction is gated on > 0), reading to the operator
		// as configured reloading that never fires — on a Windows service
		// there is no SIGHUP fallback, so the targets file would never
		// be re-read for the life of the process. Reject instead; 0 is the
		// documented way to disable the timer.
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
		// An out-of-range value used to behave silently as header-only: the
		// operator asked for payload coverage and got the v0.7 check.
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
		if t.Timeout != 0 && t.Timeout < minProbeInterval {
			// A per-target override bypasses the global floor otherwise: a
			// sub-millisecond timeout timeouts every probe and reads as 100%
			// loss on the link it was supposed to measure.
			return fmt.Errorf("target %q: timeout must be at least %v, got %v", t.Name, minProbeInterval, t.Timeout)
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

// tagsPayload reports whether the tag must cover the payload: full-frame
// coverage with at least one payload byte. With no payload the two coverages
// produce byte-identical tags, so the header tag is the same tag. One
// spelling of the condition for the send and read paths.
func tagsPayload(coverage HmacCoverage, payload int) bool {
	return coverage == HMACFullFrameCoverage && payload > 0
}

// buildProbeFrame writes one probe frame into buf: magic, sequence number,
// wire timestamp, the optional deterministic payload, and — when mac is
// non-nil — the 8-byte tag under coverage. The header size is derived from
// mac so a caller cannot pair a 24-byte header with a tag slot; payload is
// the number of pattern bytes after the header. buf must have room for
// headerSize+payload. This is the single spelling of the wire layout, shared
// by the main prober and the MTU sweep: two spellings could tag differently
// on a full-frame deployment and silently stop authenticating.
func buildProbeFrame(buf []byte, seq, ts uint64, payload int, mac *probeMACer, coverage HmacCoverage) {
	headerSize := PayloadSize
	if mac != nil {
		headerSize = PayloadSizeWithHMAC
	}
	copy(buf[0:8], MagicBytes)
	binary.LittleEndian.PutUint64(buf[8:16], seq)
	binary.LittleEndian.PutUint64(buf[16:24], ts)
	if payload > 0 {
		fillPayload(buf[headerSize:headerSize+payload], seq, ts)
	}
	if mac == nil {
		return
	}
	var tag [8]byte
	if tagsPayload(coverage, payload) {
		tag = mac.digestFrame(buf[:headerSize+payload])
	} else {
		tag = mac.digestHeader(seq, ts)
	}
	copy(buf[24:32], tag[:])
}

// probeMACer wraps ONE reusable crypto/hmac state. Every hot HMAC site
// (client loop, reader, MTU sweep, server read loop) is single-goroutine,
// so a Reset()-per-frame marshaler avoids the per-frame hmac struct +
// sha256 digest + Sum(nil) slice (3 allocs / ~250B/frame - measured
// dominant at the server's 10k/s global cap) and the two identical pad
// block-compressions crypto/hmac re-runs fresh per frame. Reset-then-digest
// yields the same tag as a fresh state (pinned by the coverage tests), and
// scratch holds Sum's output so digesting allocates nothing.
type probeMACer struct {
	h       hash.Hash
	scratch [32]byte
}

// newProbeMACer builds a reusable HMAC-SHA256 state for secret.
func newProbeMACer(secret string) *probeMACer {
	return &probeMACer{h: hmac.New(sha256.New, []byte(secret))}
}

// digestHeader truncates the header HMAC (magic+seq+ts) to 8 bytes - the
// v0.7 wire tag. Reset/Write/Sum on the same state next call.
func (m *probeMACer) digestHeader(seq, ts uint64) [8]byte {
	m.h.Reset()
	m.h.Write([]byte(MagicBytes))
	var tmp [16]byte
	binary.LittleEndian.PutUint64(tmp[0:8], seq)
	binary.LittleEndian.PutUint64(tmp[8:16], ts)
	m.h.Write(tmp[:])
	var out [8]byte
	copy(out[:], m.h.Sum(m.scratch[:0])[:8])
	return out
}

// digestFrame truncates the full-frame HMAC (header + payload, tag slot
// skipped) to 8 bytes. For a zero-payload frame (len ==
// PayloadSizeWithHMAC) it is byte-identical to digestHeader over the
// header - the forwards-compatibility keystone. The frame must be at
// least PayloadSize bytes; every caller is size-gated to at least
// PayloadSizeWithHMAC.
func (m *probeMACer) digestFrame(frame []byte) [8]byte {
	m.h.Reset()
	m.h.Write(frame[0:PayloadSize])
	if len(frame) > PayloadSizeWithHMAC {
		m.h.Write(frame[PayloadSizeWithHMAC:])
	}
	var out [8]byte
	copy(out[:], m.h.Sum(m.scratch[:0])[:8])
	return out
}

// verifyHeader reports whether tag matches the expected header tag.
// Constant-time via hmac.Equal.
func (m *probeMACer) verifyHeader(seq, ts uint64, tag []byte) bool {
	want := m.digestHeader(seq, ts)
	return hmac.Equal(want[:], tag)
}

// verifyFullFrame reports whether frame[24:32] matches the expected
// full-frame tag. Constant-time via hmac.Equal.
func (m *probeMACer) verifyFullFrame(frame []byte) bool {
	want := m.digestFrame(frame)
	return hmac.Equal(want[:], frame[24:32])
}

// macAny reports whether the tag matches the primary secret or, during a
// zero-downtime rotation, the previous secret. nil entries are skipped
// (no rotation / no secret). Constant-time per attempt.
func macAny(cur, old *probeMACer, seq, ts uint64, tag []byte) bool {
	if cur != nil && cur.verifyHeader(seq, ts, tag) {
		return true
	}
	return old != nil && old.verifyHeader(seq, ts, tag)
}

// fullFrameAny mirrors macAny for the full-frame coverage fallback.
func fullFrameAny(cur, old *probeMACer, frame []byte) bool {
	if cur != nil && cur.verifyFullFrame(frame) {
		return true
	}
	return old != nil && old.verifyFullFrame(frame)
}

// HmacCoverage selects which frame bytes the client's HMAC tag covers.
type HmacCoverage int

const (
	// HMACHeaderCoverage tags only the 24-byte header (magic+seq+ts): the
	// v0.7 behavior, the Go zero value, and the -hmac-coverage=header
	// escape hatch for v0.7 peers; the wire bytes are unchanged.
	HMACHeaderCoverage HmacCoverage = iota
	// HMACFullFrameCoverage tags the header AND the pattern payload while
	// skipping the 8-byte tag slot itself, closing the substitution gap
	// where a payload tampered in flight — or a different payload riding a
	// captured header tag — still authenticated.
	HMACFullFrameCoverage
)

// ParseHMACCoverage maps the -hmac-coverage flag value onto the enum.
func ParseHMACCoverage(s string) (HmacCoverage, error) {
	switch s {
	case "header":
		return HMACHeaderCoverage, nil
	case "full-frame":
		return HMACFullFrameCoverage, nil
	default:
		return 0, fmt.Errorf("invalid -hmac-coverage %q: must be \"header\" or \"full-frame\"", s)
	}
}
