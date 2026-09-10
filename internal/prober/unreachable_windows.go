//go:build windows

package prober

import "golang.org/x/sys/windows"

// peerUnreachableErrnos are the ICMP-derived socket errors that mean "the far
// end, or a hop on the way to it, is unreachable" rather than "this host's
// socket is broken". A connected UDP socket reports one of these on Read
// after the network answers with an ICMP port/host/net-unreachable: the probe
// simply times out, and the reader MUST survive (see isPeerUnreachable) or a
// legitimately DOWN peer would kill its reader, inflate
// link_prober_internal_errors_total{reason="reader_dead"} and re-dial once a
// second.
//
// Windows returns the RAW winsock codes, which are not the portable
// `syscall.ECONNRESET` value: syscall's constant is APPLICATION_ERROR + 23 (a
// synthetic errno used by the fake network implementation), while a UDP read
// after ICMP port-unreachable yields WSAECONNRESET = 10054. Go's own net
// package draws exactly this distinction in net/error_windows.go, where
// isConnReset compares against syscall.WSAECONNRESET. Classifying with the
// portable constants compiles on every platform and silently never matches on
// Windows — the worst kind of cross-platform bug.
var peerUnreachableErrnos = []error{
	windows.WSAECONNREFUSED, // 10061 ICMP port unreachable
	windows.WSAECONNRESET,   // 10054 ICMP port unreachable / hard reset
	windows.WSAEHOSTUNREACH, // 10065 a router replied host unreachable
	windows.WSAENETUNREACH,  // 10051 a router replied net unreachable
}
