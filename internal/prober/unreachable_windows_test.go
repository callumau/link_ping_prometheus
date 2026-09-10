//go:build windows

package prober

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

// TestIsPeerUnreachable_WindowsErrnos pins the Windows classification that
// keeps a legitimately DOWN peer from killing its reader goroutine. Windows
// surfaces a UDP read after ICMP as a raw winsock code, so the portable
// syscall.ECONNRESET — which is APPLICATION_ERROR + 23 there, not 10054 —
// never matches; using it would make every down target look like a broken
// local socket on Windows. Go's net package makes the same distinction in
// net/error_windows.go.
func TestIsPeerUnreachable_WindowsErrnos(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"WSAECONNRESET is a peer failure", windows.WSAECONNRESET, true},
		{"WSAECONNREFUSED is a peer failure", windows.WSAECONNREFUSED, true},
		{"WSAEHOSTUNREACH is a peer failure", windows.WSAEHOSTUNREACH, true},
		{"WSAENETUNREACH is a peer failure", windows.WSAENETUNREACH, true},
		{"wrapped winsock errno still classifies", fmt.Errorf("read: %w", windows.WSAECONNRESET), true},
		{"the portable ECONNRESET is not what Windows reports", syscall.ECONNRESET, false},
		{"read deadline is a local failure", os.ErrDeadlineExceeded, false},
		{"generic error is a local failure", errors.New("injected read failure"), false},
		{"nil is not a peer failure", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isPeerUnreachable(tc.err); got != tc.want {
				t.Errorf("isPeerUnreachable(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
