package prober

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	// MaxDatagramSize bounds each read so oversized or foreign datagrams
	// are seen whole and dropped instead of truncated.
	MaxDatagramSize = 1500
)

var (
	// MaxPktsPerIP caps validated probes echoed per remote IP per second.
	// UDP has no connection state, so a misconfigured or hostile prober
	// would otherwise be able to flood the echo loop. A variable (not a
	// constant) so tests can lower it.
	MaxPktsPerIP = 1000
	// MaxPktsGlobal caps total echoed probes per second.
	MaxPktsGlobal = 10000
)

// ParseAllowlist parses a comma-separated list of client IP addresses
// into a canonical set for the echo responder's fail-closed allowlist.
// An empty input yields an empty (admit-nothing) set: server mode will
// not run without at least one allowed prober.
func ParseAllowlist(s string) (map[string]struct{}, error) {
	set := make(map[string]struct{})
	for part := range strings.SplitSeq(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		ip := net.ParseIP(part)
		if ip == nil {
			return nil, fmt.Errorf("invalid allowlist IP %q", part)
		}
		set[ip.String()] = struct{}{}
	}
	return set, nil
}

// rateLimiter is a fixed-window per-IP + global packet rate limiter for
// the UDP echo loop.
type rateLimiter struct {
	mu        sync.Mutex
	window    time.Time
	perIP     map[string]int
	global    int
	perIPCap  int
	globalCap int
}

func newRateLimiter(perIPCap, globalCap int) *rateLimiter {
	return &rateLimiter{perIP: make(map[string]int), perIPCap: perIPCap, globalCap: globalCap}
}

// allow reports whether a packet from ip may be processed, incrementing
// the window counters when it may. The window resets every second.
func (r *rateLimiter) allow(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	if now.Sub(r.window) >= time.Second {
		r.window = now
		r.perIP = make(map[string]int)
		r.global = 0
	}
	if r.global >= r.globalCap {
		return false
	}
	if r.perIP[ip] >= r.perIPCap {
		return false
	}
	r.perIP[ip]++
	r.global++
	return true
}

// RunServer starts a UDP echo responder on addr. served is the
// fail-closed allowlist of prober client IPs; it must be non-empty, or
// the server refuses to start. Each accepted 24-byte datagram with a
// valid magic header from an allowed source is echoed back to its
// sender and counted in ServerProbesReceived under the remote IP. There
// is no connection lifecycle: loss is measured exactly because UDP does
// not retransmit. Blocks until ctx is cancelled, then closes the socket.
func RunServer(ctx context.Context, addr string, source string, allowed map[string]struct{}) error {
	if len(allowed) == 0 {
		return errors.New("server requires a non-empty client allowlist (-allow); fail-closed")
	}
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	slog.Info("Echo server listening (UDP)", "addr", addr)

	go func() {
		<-ctx.Done()
		pc.Close()
	}()

	if err := ServePacketConn(ctx, pc, source, allowed); err != nil {
		return err
	}
	return nil
}

// ServePacketConn runs the UDP echo loop on pc. Datagrams of exactly
// PayloadSize bytes with a valid magic header from an allowlisted source
// are echoed and counted; everything else is dropped. The allowlist is
// fail-closed: an empty or nil map admits no clients, so only permitted
// prober IPs can drive the echo responder or contribute metric labels.
// Per-IP and global rate limits bound echo processing. Blocks until ctx
// is cancelled or pc is closed.
func ServePacketConn(ctx context.Context, pc net.PacketConn, source string, allowed map[string]struct{}) error {
	buf := make([]byte, MaxDatagramSize)
	rl := newRateLimiter(MaxPktsPerIP, MaxPktsGlobal)

	for {
		n, raddr, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			// Other read errors on an unconnected UDP socket are
			// transient; the loop survives them.
			slog.Debug("UDP read error", "err", err)
			continue
		}
		if n != PayloadSize {
			continue
		}
		if string(buf[0:8]) != MagicBytes {
			continue
		}
		// The echo responder is UDP-only, so ReadFrom yields a
		// *net.UDPAddr whose IP is already canonical for the allowlist
		// lookup (no string round-trip or double parsing).
		ua, ok := raddr.(*net.UDPAddr)
		if !ok {
			continue
		}
		norm := ua.IP.String()
		if _, ok := allowed[norm]; !ok {
			continue
		}
		if !rl.allow(norm) {
			continue
		}

		ServerProbesReceived.WithLabelValues(source, norm).Inc()
		if nw, err := pc.WriteTo(buf[:n], raddr); err != nil && ctx.Err() == nil {
			slog.Debug("UDP write error", "addr", raddr, "bytes", nw, "err", err)
		}
	}
}
