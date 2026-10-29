//go:build windows

package prober

import (
	"net"
	"testing"

	"golang.org/x/sys/windows"
)

// TestSetDontFragment_MarksV4Socket: setDontFragment must succeed on a
// connected IPv4 UDP socket, or the whole MTU sweep disables itself (and
// link_path_mtu_bytes never populates) on Windows. Which of the two slots it
// ends up on is deliberately not asserted: the ladder tries
// IP_MTU_DISCOVER (Windows 10 1703+) and falls back to the classic
// IP_DONTFRAGMENT (every Windows since XP), so pinning a readback of one slot
// would fail on the other — the fallback IS the contract.
// pi-lens-ignore: go-test-functions
func TestSetDontFragment_MarksV4Socket(t *testing.T) {
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if err := setDontFragment(conn); err != nil {
		t.Fatalf("setDontFragment must work on a connected IPv4 socket: %v", err)
	}
}

// TestSetDontFragment_MarksV6Socket: the IPv6 half of the same contract, with
// the environment caveat MSDN leaves open — neither IPV6_MTU_DISCOVER (Windows
// 10 1703+) nor IPV6_DONTFRAG is guaranteed on older builds, so a host where
// BOTH slots are rejected skips instead of failing. When either slot works,
// setDontFragment must find it: a silent failure here is what leaves an IPv6
// target with path_mtu_bytes stuck at 0 and MtuSweepUnresolved mis-reporting
// the path as DF-blocked.
func TestSetDontFragment_MarksV6Socket(t *testing.T) {
	conn, err := net.DialUDP("udp6", nil, &net.UDPAddr{IP: net.IPv6loopback, Port: 1})
	if err != nil {
		t.Skipf("no IPv6 stack on this host: %v", err)
	}
	defer conn.Close()

	if !ipv6DFSlotAvailable(t, conn) {
		t.Skip("this Windows build honors neither IPV6_MTU_DISCOVER nor IPV6_DONTFRAG")
	}
	if err := setDontFragment(conn); err != nil {
		t.Fatalf("setDontFragment must use whichever IPv6 DF slot the platform supports: %v", err)
	}
}

// ipv6DFSlotAvailable reports whether the kernel accepts EITHER IPv6 DF option
// on this socket, mirroring the probes setDontFragment itself makes so the test
// can tell "platform does not support it" (skip) from "setDontFragment lost the
// option" (fail).
func ipv6DFSlotAvailable(t *testing.T, conn net.Conn) bool {
	t.Helper()
	sc, ok := conn.(syscallConn)
	if !ok {
		t.Fatalf("%T does not implement SyscallConn", conn)
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var available bool
	if ctlErr := rc.Control(func(fd uintptr) {
		h := windows.Handle(fd)
		if windows.SetsockoptInt(h, windows.IPPROTO_IPV6, windows.IPV6_MTU_DISCOVER, windows.IP_PMTUDISC_DO) == nil {
			available = true
			return
		}
		available = windows.SetsockoptInt(h, windows.IPPROTO_IPV6, ipv6DontFrag, 1) == nil
	}); ctlErr != nil {
		t.Fatal(ctlErr)
	}
	return available
}

// TestSetDontFragment_NonSyscallConnReturnsError pins the comma-ok
// syscallConn guard: a net.Conn that is not a *net.UDPConn (net.Pipe here) must
// yield a bounded error, never a type-assertion panic inside the sweep — the
// same rule pinned platform-independently by
// TestSocketOptionHelpers_NonSyscallConnReturnsError on Linux.
func TestSetDontFragment_NonSyscallConnReturnsError(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	if err := setDontFragment(c1); err == nil {
		t.Error("setDontFragment must return an error for a non-SyscallConn net.Conn")
	}
}
