//go:build !linux

package prober

import (
	"errors"
	"net"
)

// setDontFragment is a no-op outside Linux: the DF socket option needed
// for meaningful MTU probing is not wired for other platforms (same
// policy as DSCP marking). runMTUSweep disables itself with a one-time
// warning when this fails.
func setDontFragment(net.Conn) error {
	return errors.New("DF probing not supported on this platform")
}
