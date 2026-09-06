//go:build windows

package prober

import (
	"errors"
	"net"

	"golang.org/x/sys/windows"
)

// ws2ipdef.h constants not exposed by x/sys/windows at the time of
// writing. IP_DONTFRAGMENT/IPV6_DONTFRAG (value 14) are supported since
// Windows XP/Server 2003 per MSDN's IPPROTO_IP support table ("Microsoft
// TCP/IP providers respect this option for UDP"), and set the DF bit
// while suppressing fragmentation — the same observable behavior our
// sweep needs ("no echo at size N = the path does not survive N").
const (
	ipDontFragment = 14
	ipv6DontFrag   = 14
)

// setDontFragment turns the socket into a PMTUD prober: datagrams larger
// than the path can carry are dropped by the kernel/routers instead of
// being silently fragmented, so a no-echo at size N means "the path does
// not survive N". No ICMP involved: survival is inferred purely from
// echo/no-echo.
//
// Windows version support, with a fallback ladder:
//   - IP_MTU_DISCOVER/IPV6_MTU_DISCOVER (71, PMTUD_STATE) — Windows 10
//     1703+ / Windows Server 2019+. Rich path-MTU semantics.
//   - IP_DONTFRAGMENT/IPV6_DONTFRAG (14) — every Windows since XP /
//     Server 2003; plain DF-bit + no local fragmentation, which is all
//     the sweep needs. This covers older Windows Server versions
//     (2008R2/2012/2016) for IPv4 targets.
//
// NOTE: the PMTUDISC enum values differ from Linux — on Windows
// IP_PMTUDISC_DO is 1 (Linux uses 2), so always use the x/sys/windows
// constants, never hardcoded Linux values.
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
		h := windows.Handle(fd)
		if udp.IP.To4() != nil {
			// Modern path first; older Windows Server versions
			// (2003/2008R2/2012/2016) fall back to the classic DF flag.
			serr = windows.SetsockoptInt(h, windows.IPPROTO_IP, windows.IP_MTU_DISCOVER, windows.IP_PMTUDISC_DO)
			if serr != nil {
				serr = windows.SetsockoptInt(h, windows.IPPROTO_IP, ipDontFragment, 1)
			}
		} else {
			// IPv6 rich path on Windows 10 1703+ / Server 2019+; older
			// systems may still honor IPV6_DONTFRAG (not guaranteed by
			// MSDN — a failure here disables the sweep with a warning).
			serr = windows.SetsockoptInt(h, windows.IPPROTO_IPV6, windows.IPV6_MTU_DISCOVER, windows.IP_PMTUDISC_DO)
			if serr != nil {
				serr = windows.SetsockoptInt(h, windows.IPPROTO_IPV6, ipv6DontFrag, 1)
			}
		}
	}); ctlErr != nil {
		return ctlErr
	}
	return serr
}
