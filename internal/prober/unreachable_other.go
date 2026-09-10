//go:build !windows

package prober

import "syscall"

// peerUnreachableErrnos are the ICMP-derived socket errors that mean "the far
// end, or a hop on the way to it, is unreachable" rather than "this host's
// socket is broken". A connected UDP socket reports one of these on Read
// after the network answers with an ICMP port/host/net-unreachable: the probe
// simply times out, and the reader MUST survive (see isPeerUnreachable) or a
// legitimately DOWN peer would kill its reader, inflate
// link_prober_internal_errors_total{reason="reader_dead"} and re-dial once a
// second.
//
// Windows needs its own list: it reports raw winsock codes, so this file's
// constants would never match there. See unreachable_windows.go.
var peerUnreachableErrnos = []error{
	syscall.ECONNREFUSED, // ICMP port unreachable
	syscall.ECONNRESET,   // some stacks report the port case as a reset
	syscall.EHOSTUNREACH, // a router replied host unreachable
	syscall.ENETUNREACH,  // a router replied net unreachable
}
