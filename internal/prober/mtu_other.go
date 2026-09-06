//go:build !linux && !windows

package prober

import (
	"errors"
	"net"
)

// setDontFragment is a no-op outside Linux and Windows 10+: the DF
// socket option needed for meaningful MTU probing is not wired for
// other platforms. runMTUSweep disables itself with a one-time
// warning when this fails.
func setDontFragment(net.Conn) error {
	return errors.New("DF probing not supported on this platform")
}
