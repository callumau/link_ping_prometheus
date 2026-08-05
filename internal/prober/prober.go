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
	"time"
)

// Protocol constants.
const (
	MagicBytes   = "LNKPING\x00"
	PayloadSize  = 24
	DefaultAlpha = 0.125
	DefaultBeta  = 0.25
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

// Config holds the client probing configuration.
type Config struct {
	// Source is the topology label applied to every metric series, e.g.
	// the local datacenter or site name ("sydney-dc").
	Source       string
	Targets      []Target
	Adaptive     bool
	BaseInterval time.Duration
	BaseTimeout  time.Duration
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
	seen := make(map[string]struct{}, len(c.Targets))
	for _, t := range c.Targets {
		if err := ValidateTarget(t.Address); err != nil {
			return err
		}
		if err := ValidateTargetName(t.Name); err != nil {
			return err
		}
		if _, dup := seen[t.Name]; dup {
			return fmt.Errorf("duplicate target name %q: metric labels would be ambiguous", t.Name)
		}
		seen[t.Name] = struct{}{}
	}
	return nil
}
