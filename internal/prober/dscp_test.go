//go:build linux

package prober

import (
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

// TestSetDSCP_MarksV4Socket: setDSCP writes the DSCP field shifted into
// the IP_TOS socket option, verifiable via getsockopt. Linux-only: the
// marking itself is Linux-only (see dscp_other.go).
// pi-lens-ignore: go-test-functions
func TestSetDSCP_MarksV4Socket(t *testing.T) {
	// Range validation before any socket work.
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if err := setDSCP(conn, 0, conn.RemoteAddr()); err == nil {
		t.Error("dscp=0 must be rejected by setDSCP (0 means 'no marking' upstream)")
	}
	if err := setDSCP(conn, 64, conn.RemoteAddr()); err == nil {
		t.Error("dscp=64 must be rejected (6-bit field)")
	}

	if err := setDSCP(conn, 46, conn.RemoteAddr()); err != nil {
		t.Fatalf("setDSCP(46) failed: %v", err)
	}
	rc, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var got int
	var gerr error
	if ctlErr := rc.Control(func(fd uintptr) {
		got, gerr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TOS)
	}); ctlErr != nil {
		t.Fatal(ctlErr)
	}
	if gerr != nil {
		t.Fatal(gerr)
	}
	if want := 46 << 2; got != want {
		t.Errorf("expected IP_TOS=%d (EF=46 shifted), got %d", want, got)
	}
}
