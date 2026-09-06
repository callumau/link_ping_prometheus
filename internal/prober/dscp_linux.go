//go:build linux

package prober

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// setDSCP marks the probe socket's IP layer with the DSCP value (0-63,
// e.g. 46 = EF) so QoS-managed networks treat probes like the traffic
// class they emulate: IPv4 via IP_TOS, IPv6 via IPV6_TCLASS. Best
// effort — the caller logs a warning and probes continue unmarked on
// failure.
func setDSCP(conn net.Conn, dscp int, remote net.Addr) error {
	if dscp <= 0 || dscp > 63 {
		return errors.New("dscp out of range 0-63")
	}
	rc, err := conn.(syscallConn).SyscallConn()
	if err != nil {
		return err
	}
	udp, ok := remote.(*net.UDPAddr)
	if !ok || udp.IP == nil {
		return errors.New("remote is not a UDP address")
	}
	var serr error
	if ctlErr := rc.Control(func(fd uintptr) {
		if udp.IP.To4() != nil {
			serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TOS, dscp<<2)
		} else {
			serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_TCLASS, dscp<<2)
		}
	}); ctlErr != nil {
		return ctlErr
	}
	return serr
}
