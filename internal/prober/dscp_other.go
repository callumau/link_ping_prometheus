//go:build !linux

package prober

import (
	"errors"
	"net"
)

// setDSCP is a no-op outside Linux: Windows QoS policies and other
// platforms either ignore IP_TOS or need per-platform socket options.
// Probes continue unmarked; the caller warns once per (re)dial.
func setDSCP(net.Conn, int, net.Addr) error {
	return errors.New("DSCP marking not supported on this platform")
}
