package prober

import (
	"context"
	"encoding/binary"
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
	// maxReplayWindow bounds how far a probe's timestamp may drift from
	// the server clock before it is rejected as a captured-and-replayed
	// frame (the HMAC alone cannot distinguish a replay). Requires
	// approximately synchronized clocks between nodes (e.g. NTP); 30s
	// tolerates typical WAN skew.
	maxReplayWindow = 30 * time.Second
)

var (
	// MaxPktsPerIP caps validated probes echoed per remote IP per second.
	// UDP has no connection state, so a misconfigured or hostile prober
	// would otherwise be able to flood the echo loop. A variable (not a
	// constant) so tests can lower it. The cap must cover the largest
	// supported client (MaxTargetsCount targets at the default 500ms
	// interval = 2000 probes/sec), or a legit client's probes get
	// silently dropped and its loss ratio reads artificially high.
	MaxPktsPerIP = 2000
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
	if len(set) > 256 {
		return nil, fmt.Errorf("allowlist too large: %d (max 256)", len(set))
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
		// clear in place (Go 1.21+) instead of reallocating: the window
		// resets every second for the lifetime of the server, so reusing
		// the map avoids per-second GC churn.
		clear(r.perIP)
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
// When echoSecret is non-empty, probes must be 32 bytes with HMAC; this
// mitigates reflector spoofing where static magic alone allows off-path
// 1:1 reflect to a victim allowlisted IP.
func RunServer(ctx context.Context, addr string, source string, allowed map[string]struct{}, echoSecret string) error {
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

	if err := ServePacketConn(ctx, pc, source, allowed, echoSecret); err != nil {
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
// is cancelled or pc is closed. Datagram handling order is deliberate:
// cheap untrusted-source rejection (allowlist, rate limit) runs ahead of
// any per-packet validation work, so a flood from a non-allowlisted host
// costs no crypto and no metric work. A recovered panic is returned as an
// error so callers treat it as a fatal failure, never a clean exit.
// When echoSecret is non-empty, only 32-byte HMAC-authenticated datagrams
// with a fresh timestamp are accepted; this mitigates reflector spoofing
// (SEC22). When empty, 24-byte backward-compatible datagrams are accepted.
func ServePacketConn(ctx context.Context, pc net.PacketConn, source string, allowed map[string]struct{}, echoSecret string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			retErr = fmt.Errorf("echo server panic: %v", r)
			slog.Error("panic in echo server", "panic", r)
		}
	}()
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
		// Cheap untrusted-source rejection MUST stay ahead of crypto
		// work: any internet host must not be able to buy HMAC-SHA256
		// CPU per flood packet on a latency-measuring box.
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

		expectedSize := PayloadSize
		if echoSecret != "" {
			expectedSize = PayloadSizeWithHMAC
		}
		if n != expectedSize {
			continue
		}
		if string(buf[0:8]) != MagicBytes {
			continue
		}
		if echoSecret != "" {
			seq := binary.LittleEndian.Uint64(buf[8:16])
			ts := binary.LittleEndian.Uint64(buf[16:24])
			if !validHMAC(echoSecret, seq, ts, buf[24:32]) {
				continue
			}
			// Replay guard: an authenticated frame older or newer than
			// the window is a capture-replay, not a live probe. Clocks
			// between nodes must be approximately synchronized (NTP).
			skew := time.Since(time.Unix(0, int64(ts)))
			if skew > maxReplayWindow || skew < -maxReplayWindow {
				slog.Debug("replayed or stale probe timestamp rejected", "addr", norm, "skew", skew)
				continue
			}
		}

		ServerProbesReceived.WithLabelValues(source, norm).Inc()
		if nw, err := pc.WriteTo(buf[:n], raddr); err != nil && ctx.Err() == nil {
			slog.Debug("UDP write error", "addr", raddr, "bytes", nw, "err", err)
		}
	}
}
