// Package prober implements a TCP echo probing engine for measuring
// network latency, packet loss, and jitter. It provides both a server
// (TCP echo responder) and a client (active prober with adaptive RTO).
//
// Wire format: 24 bytes per probe — 8-byte magic header "TCPPING\x00",
// 8-byte little-endian sequence number, 8-byte Unix-ns timestamp.
// The server validates the magic header before echoing; invalid packets
// cause an immediate connection close.
package prober

import (
	"errors"
	"time"
)

// Protocol constants.
const (
	MagicBytes         = "TCPPING\x00"
	PayloadSize        = 24
	DefaultAlpha       = 0.125
	DefaultBeta        = 0.25
	DefaultMinRTO      = 100 * time.Millisecond
	DefaultMaxRTO      = 3 * time.Second
	MaxTargetsFileSize = 1 << 20
	MaxTargetsCount    = 1000
)

// Config holds the client probing configuration.
type Config struct {
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
	for _, t := range c.Targets {
		if err := ValidateTarget(t.Address); err != nil {
			return err
		}
	}
	return nil
}
