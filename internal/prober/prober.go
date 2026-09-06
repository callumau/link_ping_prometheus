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
	"time"
)

// Protocol constants.
const (
	MagicBytes          = "LNKPING\x00"
	PayloadSize         = 24
	PayloadSizeWithHMAC = 32
	DefaultAlpha        = 0.125
	DefaultBeta         = 0.25
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
// The re-dial only happens with no probes in flight, so it never abandons
// an in-flight probe or breaks the sent/rtt/timedout/inflight balance. A
// variable (not a constant) so tests can lower it.
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
	// DSCP, when 1-63, marks probe packets with that traffic class
	// (e.g. 46 = EF) so QoS-managed networks class them accordingly.
	// 0 (default) leaves packets unmarked. Best effort, Linux support.
	DSCP int
	// Status, when non-nil, receives a live per-target snapshot each
	// probe interval for the /status debug endpoint. Nil in server-only
	// mode and unit tests (Update is nil-receiver-safe).
	Status *StatusRegistry
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
	if c.BaseTimeout <= 0 {
		return fmt.Errorf("probe timeout must be positive, got %v", c.BaseTimeout)
	}
	if c.ReconnectInterval < 0 {
		return fmt.Errorf("reconnect interval must be >= 0, got %v", c.ReconnectInterval)
	}
	if c.DSCP < 0 || c.DSCP > 63 {
		return fmt.Errorf("dscp must be 0-63, got %d", c.DSCP)
	}
	if c.ReconnectInterval != 0 && c.ReconnectInterval < c.BaseInterval {
		return fmt.Errorf("reconnect interval %v must be >= probe interval %v", c.ReconnectInterval, c.BaseInterval)
	}
	return validateTargets(c.Targets)
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
