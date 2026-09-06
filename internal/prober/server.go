package prober

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
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

// MaxClientSeries bounds how many distinct prefix-matched (CIDR)
// client IPs get their own {source,client} metric series. Beyond it,
// probes from new sources are dropped (client_overflow) instead of
// growing the label space. A var so tests can lower it. Exact-IP
// allowlist entries are unaffected: their handles are pre-resolved.
var MaxClientSeries = 1024

// Allowlist is the fail-closed set of permitted prober source IPs:
// exact IPs plus optional CIDR prefixes (e.g. 203.0.113.0/24). Exact
// IPs keep O(1) matching and pre-resolved metric handles; prefix
// matches resolve metric handles on demand under MaxClientSeries so
// metric cardinality stays bounded.
type Allowlist struct {
	exact  map[string]struct{}
	prefix []netip.Prefix
}

// ParseAllowlist parses a comma-separated list of client IP addresses
// or CIDR prefixes (e.g. "203.0.113.5,10.0.0.0/24") into the echo
// responder's fail-closed allowlist. An empty input yields an empty
// (admit-nothing) allowlist: server mode will not run without at least
// one allowed prober.
func ParseAllowlist(s string) (*Allowlist, error) {
	a := &Allowlist{exact: make(map[string]struct{})}
	for part := range strings.SplitSeq(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "/") {
			p, err := netip.ParsePrefix(part)
			if err != nil {
				return nil, fmt.Errorf("invalid allowlist CIDR %q: %w", part, err)
			}
			a.prefix = append(a.prefix, p.Masked())
			continue
		}
		addr, err := netip.ParseAddr(part)
		if err != nil {
			return nil, fmt.Errorf("invalid allowlist IP %q", part)
		}
		a.exact[addr.String()] = struct{}{}
	}
	if n := len(a.exact) + len(a.prefix); n > 256 {
		return nil, fmt.Errorf("allowlist too large: %d (max 256)", n)
	}
	return a, nil
}

// Len reports the number of allowlist entries (exact IPs + prefixes).
// Nil-safe: an absent allowlist is empty.
func (a *Allowlist) Len() int {
	if a == nil {
		return 0
	}
	return len(a.exact) + len(a.prefix)
}

// Allows reports whether a source is permitted. norm is the incoming
// datagram's canonical source IP string (net.IP.String()), ip its
// parsed address. A nil or empty allowlist admits nothing.
func (a *Allowlist) Allows(norm string, ip netip.Addr) bool {
	if a.Len() == 0 {
		return false
	}
	if _, ok := a.exact[norm]; ok {
		return true
	}
	for _, p := range a.prefix {
		if p.Contains(ip) {
			return true
		}
	}
	return false
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
	ok, _ := r.allowWithReason(ip)
	return ok
}

// allowWithReason is like allow but also returns the reason when denied: "rate_global" or "rate_ip".
func (r *rateLimiter) allowWithReason(ip string) (bool, string) {
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
		return false, "rate_global"
	}
	if r.perIP[ip] >= r.perIPCap {
		return false, "rate_ip"
	}
	r.perIP[ip]++
	r.global++
	return true, ""
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
// 1:1 reflect to a victim allowlisted IP. During a rotation,
// echoSecretOld (when non-empty) is also accepted so clients can switch
// secrets one endpoint at a time.
func RunServer(ctx context.Context, addr string, source string, allowed *Allowlist, echoSecret string, echoSecretOld ...string) error {
	if allowed.Len() == 0 {
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

	if err := ServePacketConn(ctx, pc, source, allowed, echoSecret, echoSecretOld...); err != nil {
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
// During a rotation, echoSecretOld (when set) is also accepted so clients
// can switch to the new secret one endpoint at a time.
func ServePacketConn(ctx context.Context, pc net.PacketConn, source string, allowed *Allowlist, echoSecret string, echoSecretOld ...string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			retErr = fmt.Errorf("echo server panic: %v", r)
			slog.Error("panic in echo server", "panic", r)
		}
	}()
	buf := make([]byte, MaxDatagramSize)
	rl := newRateLimiter(MaxPktsPerIP, MaxPktsGlobal)

	// Pre-resolve per-client metric handles for exact allowlist IPs once:
	// only allowlisted IPs reach these metrics, so the set is bounded by
	// the exact allowlist (max 256). Avoids the per-packet WithLabelValues
	// hash+lookup on the hot path — the same resolve-once convention the
	// client probe loop uses. Prefix-matched clients resolve their handles
	// on demand under MaxClientSeries (see resolve below).
	type clientHandles struct {
		recv prometheus.Counter
		skew prometheus.Gauge
	}
	handles := make(map[string]clientHandles, allowed.Len())
	for ip := range allowed.exact {
		handles[ip] = clientHandles{
			recv: ServerProbesReceived.WithLabelValues(source, ip),
			skew: ServerClockSkew.WithLabelValues(source, ip),
		}
	}
	var dynMu sync.Mutex
	dyn := make(map[string]clientHandles)
	resolve := func(norm string) (clientHandles, bool) {
		dynMu.Lock()
		defer dynMu.Unlock()
		if h, ok := dyn[norm]; ok {
			return h, true
		}
		if len(dyn) >= MaxClientSeries {
			return clientHandles{}, false
		}
		h := clientHandles{
			recv: ServerProbesReceived.WithLabelValues(source, norm),
			skew: ServerClockSkew.WithLabelValues(source, norm),
		}
		dyn[norm] = h
		return h, true
	}

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
			ServerProbesDropped.WithLabelValues(source, "invalid_addr").Inc()
			continue
		}
		norm := ua.IP.String()
		// ua.IP.String() of a socket-reported IP is always parseable.
		na, _ := netip.ParseAddr(norm)
		if !allowed.Allows(norm, na) {
			ServerProbesDropped.WithLabelValues(source, "allowlist").Inc()
			continue
		}
		if ok, reason := rl.allowWithReason(norm); !ok {
			ServerProbesDropped.WithLabelValues(source, reason).Inc()
			continue
		}

		expectedSize := PayloadSize
		if echoSecret != "" {
			expectedSize = PayloadSizeWithHMAC
		}
		// Accept the header frame plus any bounded payload extension:
		// clients can probe with a payload (MTU/data-path corruption
		// detection) without coordinating server-side config. Reflection
		// stays 1:1 and bounded well below MaxDatagramSize; anything
		// larger is an arbitrary-payload reflector attempt.
		if n < expectedSize || n > expectedSize+MaxPayloadBytes {
			ServerProbesDropped.WithLabelValues(source, "size").Inc()
			continue
		}
		if string(buf[0:8]) != MagicBytes {
			ServerProbesDropped.WithLabelValues(source, "magic").Inc()
			continue
		}
		// Resolve per-client metric handles after the cheap size/magic
		// checks, before any HMAC work: exact allowlist IPs hit the
		// pre-resolved map with no lock; prefix matches go through the
		// capped dynamic map, so rotating spoofed sources cannot grow the
		// label space beyond MaxClientSeries (H1 cardinality guard).
		h, pre := handles[norm]
		if !pre {
			res, resOK := resolve(norm)
			if !resOK {
				ServerProbesDropped.WithLabelValues(source, "client_overflow").Inc()
				continue
			}
			h = res
		}
		if echoSecret != "" {
			oldSecret := ""
			if len(echoSecretOld) > 0 {
				oldSecret = echoSecretOld[0]
			}
			seq := binary.LittleEndian.Uint64(buf[8:16])
			ts := binary.LittleEndian.Uint64(buf[16:24])
			if !validHMACAny(echoSecret, oldSecret, seq, ts, buf[24:32]) {
				ServerProbesDropped.WithLabelValues(source, "hmac").Inc()
				continue
			}
			// Replay guard: an authenticated frame older or newer than
			// the window is a capture-replay, not a live probe. Clocks
			// between nodes must be approximately synchronized (NTP).
			skew := time.Since(time.Unix(0, int64(ts)))
			h.skew.Set(skew.Seconds())
			if skew > maxReplayWindow || skew < -maxReplayWindow {
				ServerProbesDropped.WithLabelValues(source, "replay").Inc()
				slog.Warn("replayed or stale probe timestamp rejected (check NTP/clock sync)", "addr", norm, "skew", skew, "window", maxReplayWindow)
				continue
			}
		}

		h.recv.Inc()
		if nw, err := pc.WriteTo(buf[:n], raddr); err != nil && ctx.Err() == nil {
			slog.Debug("UDP write error", "addr", raddr, "bytes", nw, "err", err)
		}
	}
}
