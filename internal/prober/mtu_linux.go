//go:build linux

package prober

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// setDontFragment turns the socket into a PMTUD prober: datagrams larger
// than the path can carry are dropped by the kernel/routers instead of
// being silently fragmented, so a no-echo at size N means "the path does
// not survive N". IPv4 via IP_MTU_DISCOVER=PMTUDISC_DO, IPv6 via
// IPV6_MTU_DISCOVER=PMTUDISC_DO. No ICMP involved: survival is inferred
// purely from echo/no-echo.
func setDontFragment(conn net.Conn) error {
	sc, ok := conn.(syscallConn)
	if !ok {
		// Comma-ok, not a bare assertion: a caller handing us a non-*net.UDPConn
		// must get a bounded error (the sweep disables itself with a warning),
		// never a panic in the probe loop.
		return fmt.Errorf("setDontFragment: %T does not implement SyscallConn", conn)
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return err
	}
	udp, ok := conn.RemoteAddr().(*net.UDPAddr)
	if !ok || udp.IP == nil {
		return errors.New("remote is not a UDP address")
	}
	var serr error
	if ctlErr := rc.Control(func(fd uintptr) {
		if udp.IP.To4() != nil {
			serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO)
		} else {
			serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_DO)
		}
	}); ctlErr != nil {
		return ctlErr
	}
	return serr
}
