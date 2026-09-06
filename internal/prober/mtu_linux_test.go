//go:build linux

package prober

import (
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

// TestSetDontFragment_MarksV4Socket: setDontFragment turns on kernel
// PMTUDISC_DO so oversized datagrams vanish instead of fragmenting —
// verifiable via getsockopt. Linux-only (see mtu_other.go).
// pi-lens-ignore: go-test-functions
func TestSetDontFragment_MarksV4Socket(t *testing.T) {
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if err := setDontFragment(conn); err != nil {
		t.Fatalf("setDontFragment failed: %v", err)
	}
	rc, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var got int
	var gerr error
	if ctlErr := rc.Control(func(fd uintptr) {
		got, gerr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER)
	}); ctlErr != nil {
		t.Fatal(ctlErr)
	}
	if gerr != nil {
		t.Fatal(gerr)
	}
	if got != unix.IP_PMTUDISC_DO {
		t.Errorf("expected IP_MTU_DISCOVER=%d (PMTUDISC_DO), got %d", unix.IP_PMTUDISC_DO, got)
	}
}
