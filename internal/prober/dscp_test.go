//go:build linux

package prober

import (
	"net"
	"testing"
	"time"

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

// TestConfigValidate_DSCPRange pins the 0-63 bound end to end with the
// flag wiring.
// pi-lens-ignore: go-test-functions
func TestConfigValidate_DSCPRange(t *testing.T) {
	base := func() Config {
		return Config{
			Targets:      []Target{{Name: "t", Address: "127.0.0.1:4000"}},
			BaseInterval: 500 * time.Millisecond,
			BaseTimeout:  time.Second,
		}
	}
	for _, d := range []int{-1, 64, 255} {
		cfg := base()
		cfg.DSCP = d
		if err := cfg.Validate(); err == nil {
			t.Errorf("expected error for dscp=%d", d)
		}
	}
	cfg := base()
	cfg.DSCP = 46
	if err := cfg.Validate(); err != nil {
		t.Errorf("expected dscp=46 valid, got %v", err)
	}
}
