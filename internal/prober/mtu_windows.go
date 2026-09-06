//go:build windows

package prober

import (
	"errors"
	"net"

	"golang.org/x/sys/windows"
)

// setDontFragment turns the socket into a PMTUD prober (Windows 10+):
// datagrams larger than the path can carry are dropped by the
// kernel/routers instead of being silently fragmented, so a no-echo at
// size N means "the path does not survive N". No ICMP involved:
// survival is inferred purely from echo/no-echo.
//
// Uses the Linux-compatible IP_MTU_DISCOVER/IPV6_MTU_DISCOVER options
// (0x47) that Microsoft added in ws2ipdef.h. NOTE: the PMTUDISC enum
// values differ from Linux — on Windows IP_PMTUDISC_DO is 1 (Linux
// uses 2), so always use the x/sys/windows constants, never hardcoded
// Linux values. On pre-10 Windows the setsockopt fails (WSAENOPROTOOPT)
// and the sweep disables itself with a one-time warning.
func setDontFragment(conn net.Conn) error {
	rc, err := conn.(syscallConn).SyscallConn()
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
			serr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, windows.IP_MTU_DISCOVER, windows.IP_PMTUDISC_DO)
		} else {
			serr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, windows.IPV6_MTU_DISCOVER, windows.IP_PMTUDISC_DO)
		}
	}); ctlErr != nil {
		return ctlErr
	}
	return serr
}
