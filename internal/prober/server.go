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
	// dynSweepInterval rate-limits the DynClientTTL sweep below: it walks
	// the whole dynamic client map under dynMu, so running it on every
	// resolve would be O(len(dyn)) at packet rate.
	dynSweepInterval = time.Second
	// maxConsecutiveServerReadFails bounds successive UNEXPECTED read
	// errors. ICMP-derived errors are classified out (a vanished client, or
	// a spoofed source inside the allowlist, is a normal condition — on
	// Windows it even arrives as a read error), so what remains is a
	// genuinely misbehaving socket. A bare `continue` there would spin at
	// Debug level forever; the loop instead logs once at Error, sleeps
	// serverReadErrorBackoff between attempts, and keeps serving, because a
	// responder that an unreachable peer can kill is worse than a slow one.
	maxConsecutiveServerReadFails = 10
	serverReadErrorBackoff        = 100 * time.Millisecond
)

var (
	// DynClientTTL ages out dynamically resolved (prefix-matched) clients
	// and their metric series. It must comfortably exceed both the 30s
	// replay window and any sane scrape interval (~15-60s): evicting a
	// still-active client deletes its counters, so the next scrape would
	// read the unaffected rate() as a restart. 10 minutes is far beyond
	// both, yet bounded enough that a spoofed-source sweep cannot pin the
	// MaxClientSeries slots forever. Exported (a var, not a const) for the
	// same reason as MaxClientSeries: tests lower it to exercise eviction.
	DynClientTTL = 10 * time.Minute
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
//
// Entries are keyed by netip.Addr (a comparable value), not by string: the
// datagram hot path then needs no per-packet IP.String() allocation and no
// re-parse of the canonical form, and the label string is produced once, when
// a series is actually created.
type Allowlist struct {
	exact  map[netip.Addr]struct{}
	prefix []netip.Prefix
}

// ParseAllowlist parses a comma-separated list of client IP addresses
// or CIDR prefixes (e.g. "203.0.113.5,10.0.0.0/24") into the echo
// responder's fail-closed allowlist. An empty input yields an empty
// (admit-nothing) allowlist: server mode will not run without at least
// one allowed prober.
func ParseAllowlist(s string) (*Allowlist, error) {
	a := &Allowlist{exact: make(map[netip.Addr]struct{})}
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
			// Normalise to the unmapped (IPv4) form: a datagram from an IPv4
			// source reports as "10.0.0.1", never "::ffff:10.0.0.1", and
			// netip does not unmap either address or prefix on its own, so a
			// 4-in-6 allowlist entry would silently never match.
			if p.Addr().Is4In6() {
				if p.Bits() < 96 {
					// A 4-in-6 prefix shorter than /96 covers more than the IPv4
					// space and can never match an unmapped IPv4 source (netip
					// requires equal address bit-lengths), so it would silently
					// admit nothing. Fail loudly instead: write it as IPv4.
					return nil, fmt.Errorf("invalid allowlist CIDR %q: an IPv4-mapped prefix shorter than /96 can never match an IPv4 source; write it as an IPv4 CIDR", part)
				}
				// Note: ::ffff:0:0/96 becomes 0.0.0.0/0, i.e. every IPv4 source —
				// semantically correct, but a whole-IPv4 allowlist.
				p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
			}
			a.prefix = append(a.prefix, p.Masked())
			continue
		}
		addr, err := netip.ParseAddr(part)
		if err != nil {
			return nil, fmt.Errorf("invalid allowlist IP %q", part)
		}
		if addr.Zone() != "" {
			// netip parses "fe80::1%eth0" happily, but a datagram source
			// never carries a scope zone (net.IP.String() has none), so the
			// entry can never match: the server would start normally and
			// drop 100% of that client's probes as allowlist drops. Fails
			// closed, but silently — reject it loudly instead.
			return nil, fmt.Errorf("invalid allowlist IP %q: a scope zone can never match a datagram source", part)
		}
		a.exact[addr.Unmap()] = struct{}{}
	}
	if n := len(a.exact) + len(a.prefix); n > 256 {
		return nil, fmt.Errorf("allowlist too large: %d (max 256)", n)
	}
	return a, nil
}

// AllowEntriesFromTargets returns a comma-separated allowlist spec derived
// from the target addresses (for -allow-from-targets). Every address must be
// an IP literal: allowlisting a DNS name would need a resolution at
// config-load time, and load-time validation deliberately never touches the
// network (a reload must not depend on DNS). The result is meant to be
// combined with any explicit -allow entries and passed to ParseAllowlist
// once, so the CIDR, IPv4-mapped and size rules are applied in one place.
func AllowEntriesFromTargets(targets []Target) (string, error) {
	entries := make([]string, 0, len(targets))
	for _, t := range targets {
		host, _, err := net.SplitHostPort(t.Address)
		if err != nil {
			return "", fmt.Errorf("target %q: %w", t.Name, err)
		}
		addr, err := netip.ParseAddr(host)
		if err != nil {
			return "", fmt.Errorf("target %q address %q is not an IP literal (%w): -allow-from-targets cannot allowlist a DNS name (config load never resolves); use IP addresses in the mesh targets file, or list the host in -allow", t.Name, t.Address, err)
		}
		if addr.Zone() != "" {
			// ParseAllowlist would reject this too, but its message speaks of
			// allowlist entries, not of the target that produced one; name the
			// target so the fix is obvious.
			return "", fmt.Errorf("target %q address %q has an IPv6 scope zone: a datagram source never carries one, so it cannot be allowlisted; use a global address", t.Name, t.Address)
		}
		entries = append(entries, addr.String())
	}
	return strings.Join(entries, ","), nil
}

// Len reports the number of allowlist entries (exact IPs + prefixes).
// Nil-safe: an absent allowlist is empty.
func (a *Allowlist) Len() int {
	if a == nil {
		return 0
	}
	return len(a.exact) + len(a.prefix)
}

// Contains reports whether a source is permitted. A nil, empty or invalid
// address (or an empty allowlist) admits nothing.
// Entries are stored unmapped and ip is unmapped here too, so a 4-in-6
// datagram source matches a plain IPv4 entry and vice versa. Taking the
// netip.Addr directly (rather than its string form) keeps the per-datagram
// path free of an allocation and a re-parse.
func (a *Allowlist) Contains(ip netip.Addr) bool {
	if a.Len() == 0 || !ip.IsValid() {
		return false
	}
	ip = ip.Unmap()
	if _, ok := a.exact[ip]; ok {
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
// the UDP echo loop. The per-IP budget is keyed by netip.Addr so the hot
// path never builds a string for it.
type rateLimiter struct {
	mu        sync.Mutex
	window    time.Time
	perIP     map[netip.Addr]int
	global    int
	perIPCap  int
	globalCap int
}

func newRateLimiter(perIPCap, globalCap int) *rateLimiter {
	return &rateLimiter{perIP: make(map[netip.Addr]int), perIPCap: perIPCap, globalCap: globalCap}
}

// rateMapReallocHint is the per-IP map size at which a window reset
// reallocates instead of clearing in place: clear() keeps the bucket
// array sized to the high-water mark forever, so one flood of rotating
// fake IPs inside an allowed CIDR (secret-less mode; per-IP charge is
// post-authentication) would pin its buckets for the server's lifetime.
// Below the hint, in-place clear wins on per-second GC churn.
const rateMapReallocHint = 1024

// resetLocked rolls the fixed window forward when a second has elapsed.
// Caller must hold r.mu.
func (r *rateLimiter) resetLocked(now time.Time) {
	if now.Sub(r.window) >= time.Second {
		r.window = now
		if len(r.perIP) > rateMapReallocHint {
			r.perIP = make(map[netip.Addr]int, 64)
		} else {
			// clear in place (Go 1.21+) instead of reallocating: the
			// window resets every second for the lifetime of the
			// server, so reusing the map avoids per-second GC churn.
			clear(r.perIP)
		}
		r.global = 0
	}
}

// chargeGlobal consumes one unit of the global per-second budget and
// returns "rate_global" when exhausted. It runs before size/magic/HMAC
// validation: bounding total loop work — crypto included — by
// MaxPktsGlobal is what stops an allowlisted-but-spoofed flood from
// buying HMAC-SHA256 CPU on a latency-measuring box.
func (r *rateLimiter) chargeGlobal() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.resetLocked(time.Now())
	if r.global >= r.globalCap {
		return "rate_global"
	}
	r.global++
	return ""
}

// chargeIP consumes one unit of ip's per-second budget and returns
// "rate_ip" when exhausted. It runs only after a frame has authenticated
// (or, with no secret, passed the size/magic checks): junk from a
// spoofed source inside an allowed CIDR must not spend a real client's
// budget and read as 100% loss for that client.
func (r *rateLimiter) chargeIP(ip netip.Addr) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.resetLocked(time.Now())
	if r.perIP[ip] >= r.perIPCap {
		return "rate_ip"
	}
	r.perIP[ip]++
	return ""
}

// skewReplayed reports whether an authenticated frame's timestamp skew
// exceeds the ±maxReplayWindow replay window. Extracted from the read
// loop so the boundary comparison is unit-pinnable: over a real socket
// the exact ±30s edge is untestable (processing delay drifts the observed
// skew in both directions between capture and compare), so the open/fair
// and >=/< semantics of the edge can only be pinned here. Deliberately
// strict > and < — a frame exactly at the window edge is a live probe.
func skewReplayed(skew time.Duration) bool {
	return skew > maxReplayWindow || skew < -maxReplayWindow
}

// FNV-1a 64-bit constants for the echo-loop guard's frame identity hash.
const (
	fnvOffset64 = 14695981039346656037
	fnvPrime64  = 1099511628211
)

// dupRingSize bounds the echo-loop guard's memory: a fixed 65536-entry
// FIFO ring of 64-bit frame identities plus a membership map, so the
// guard stays bounded (~2MB) while outlasting multi-second bursts even near
// MaxPktsGlobal.
const dupRingSize = 65536

// echoDupGuard remembers the identities of recently echoed frames so the
// responder can refuse to echo the same frame twice. Without it, one
// spoofed datagram whose source is another link-ping server's listen
// socket seeds an infinite echo bounce (each leg spending rate-limit
// budget), and a source equal to this server's own address self-loops at
// line rate; with -echo-secret the 30s replay window bounds that, without
// one nothing does.
//
// Used only from the single echo-loop goroutine in ServePacketConn; no
// locking.
type echoDupGuard struct {
	seen  map[uint64]struct{}
	ring  [dupRingSize]uint64
	next  int
	count int
}

func newEchoDupGuard() *echoDupGuard {
	return &echoDupGuard{seen: make(map[uint64]struct{}, dupRingSize)}
}

// record adds a key, FIFO-evicting the oldest entry once the ring is
// full, so the guard tracks a bounded recent window and an old identity
// becomes echoable again.
func (g *echoDupGuard) record(key uint64) {
	if g.count == dupRingSize {
		delete(g.seen, g.ring[g.next])
	} else {
		g.count++
	}
	g.ring[g.next] = key
	g.next = (g.next + 1) % dupRingSize
	g.seen[key] = struct{}{}
}

// fnv1a64 continues the FNV-1a hash h over b.
func fnv1a64(h uint64, b []byte) uint64 {
	for _, c := range b {
		h = (h ^ uint64(c)) * fnvPrime64
	}
	return h
}

// echoFrameKey derives the loop-guard identity of a frame: FNV-1a over
// the source IP bytes and the header's seq+ts fields (frame[8:24]). The
// source address is part of the identity: two clients that happen to send
// the same seq+ts are independent probes, and only a repeat from the SAME
// source can be a bounce. The source PORT is deliberately excluded: one
// captured authenticated frame replayed at a victim's source IP from a
// rotating source port would otherwise present a fresh identity per
// replay, and each replay would spend the victim's per-IP budget until it
// reads 100% loss (the manufactured-loss path this guard exists to
// close). Inline FNV keeps the per-datagram path allocation-free.
func echoFrameKey(ip netip.Addr, frame []byte) uint64 {
	ipb := ip.As16() // deterministic for both v4 (4-in-6) and v6
	return fnv1a64(fnv1a64(fnvOffset64, ipb[:]), frame[8:24])
}

// RunServer starts a UDP echo responder on addr. served is the
// fail-closed allowlist of prober client IPs; it must be non-empty, or
// the server refuses to start. Each accepted datagram — the header
// (24 bytes, or 32 with HMAC) plus any bounded payload extension, with a
// valid magic header — from an allowed source is echoed back to its
// sender and counted in ServerProbesReceived under the remote IP. There
// is no connection lifecycle: loss is measured exactly because UDP does
// not retransmit. Blocks until ctx is cancelled, then closes the socket.
// When echoSecret is non-empty, probes must start with the 32-byte HMAC
// frame; this mitigates reflector spoofing where static magic alone
// allows off-path 1:1 reflect to a victim allowlisted IP. During a
// rotation, echoSecretOld (when non-empty) is also accepted so clients
// can switch secrets one endpoint at a time.
func RunServer(ctx context.Context, addr string, source string, allowed *Allowlist, echoSecret string, echoSecretOld ...string) error {
	if allowed.Len() == 0 {
		return errors.New("server requires a non-empty client allowlist (-allow); fail-closed")
	}
	if echoSecret == "" {
		// A client configured with -echo-secret emits a 32-byte HMAC frame;
		// without a secret here that frame is indistinguishable from a
		// legitimate 24+8 payload probe (header ≤ size ≤ header+payload) and
		// is echoed. A half-configured fleet (secret on clients, not on the
		// server) therefore looks perfectly healthy while reflector
		// protection is silently absent: set -echo-secret on BOTH ends.
		slog.Warn("-echo-secret is unset: HMAC-authenticated frames are indistinguishable from payload probes and will be echoed; set -echo-secret on BOTH ends, otherwise the allowlist is the only reflector protection")
		// Without HMAC, any host that can spoof a source inside an
		// allowlisted prefix can use the server as a 1:1 reflector towards
		// that source (magic is a public constant). Exact IPs are
		// comparatively narrow, so only warn per wide prefix — the ones
		// that admit an attacker's spoofed address in practice.
		for _, p := range allowed.prefix {
			if p.Addr().Is4() {
				if p.Bits() >= 24 {
					continue
				}
			} else if p.Bits() > 64 {
				continue
			}
			slog.Warn("wide client allowlist prefix without -echo-secret: anyone able to spoof a source inside it can reflect probes off this server; set -echo-secret", "prefix", p.String())
		}
	}
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	slog.Info("Echo server listening (UDP)", "addr", addr)

	// ctxWatcher closes the socket on cancellation and exits as soon as
	// ServePacketConn returns, so RunServer leaves no goroutine behind on
	// any return path (a read loop killed by an external pc.Close, a
	// panic recovery, or a live ctx) — the socket close is idempotent.
	serveDone := make(chan struct{})
	defer close(serveDone)
	go func() {
		select {
		case <-ctx.Done():
			pc.Close()
		case <-serveDone:
		}
	}()

	if err := ServePacketConn(ctx, pc, source, allowed, echoSecret, echoSecretOld...); err != nil {
		return err
	}
	return nil
}

type clientHandles struct {
	recv prometheus.Counter
	skew prometheus.Gauge
	// key is the {client} label value (the canonical address string).
	key string
	// lastSeen ages dynamic entries out (DynClientTTL); unused for
	// pre-resolved exact-IP handles, which are never evicted.
	lastSeen time.Time
}

type serverDropCounters struct {
	invalidAddr    prometheus.Counter
	allowlist      prometheus.Counter
	rateIP         prometheus.Counter
	rateGlobal     prometheus.Counter
	size           prometheus.Counter
	magic          prometheus.Counter
	clientOverflow prometheus.Counter
	hmac           prometheus.Counter
	replay         prometheus.Counter
	dup            prometheus.Counter
}

func newServerDropCounters(source string) serverDropCounters {
	// Pre-resolve the fixed set of drop reasons once, so a dropped
	// datagram (the flood case) costs no label-map hashing. If a new drop
	// reason is added, add a field here and to the Help text in metrics.go.
	return serverDropCounters{
		invalidAddr:    ServerProbesDropped.WithLabelValues(source, "invalid_addr"),
		allowlist:      ServerProbesDropped.WithLabelValues(source, "allowlist"),
		rateIP:         ServerProbesDropped.WithLabelValues(source, "rate_ip"),
		rateGlobal:     ServerProbesDropped.WithLabelValues(source, "rate_global"),
		size:           ServerProbesDropped.WithLabelValues(source, "size"),
		magic:          ServerProbesDropped.WithLabelValues(source, "magic"),
		clientOverflow: ServerProbesDropped.WithLabelValues(source, "client_overflow"),
		hmac:           ServerProbesDropped.WithLabelValues(source, "hmac"),
		replay:         ServerProbesDropped.WithLabelValues(source, "replay"),
		dup:            ServerProbesDropped.WithLabelValues(source, "dup"),
	}
}

type dynClientCache struct {
	source    string
	mu        sync.Mutex
	entries   map[netip.Addr]clientHandles
	lastSweep time.Time
}

func newDynClientCache(source string) *dynClientCache {
	return &dynClientCache{
		source:  source,
		entries: make(map[netip.Addr]clientHandles),
	}
}

// sweepExpired drops clients idle for DynClientTTL. Caller must hold
// c.mu. Both the map entry AND the Prometheus series are removed —
// the vecs retain a series per label set forever otherwise, so
// lifetime cardinality would still grow without bound.
func (c *dynClientCache) sweepExpired(now time.Time) {
	for ip, eh := range c.entries {
		if now.Sub(eh.lastSeen) >= DynClientTTL {
			ServerProbesReceived.DeleteLabelValues(c.source, eh.key)
			ServerClockSkew.DeleteLabelValues(c.source, eh.key)
			delete(c.entries, ip)
		}
	}
}

func (c *dynClientCache) resolve(ip netip.Addr) (clientHandles, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	// Sweep on every resolve, not only under MaxClientSeries pressure:
	// below the cap an expired client's series would otherwise be
	// exported forever at its last value (a frozen link_server_clock_skew
	// alert that can never resolve). Time-gated because the walk is
	// O(len(entries)) under the lock; a live client refreshes lastSeen on
	// each resolve, so it is never evicted.
	if now.Sub(c.lastSweep) >= dynSweepInterval {
		c.lastSweep = now
		c.sweepExpired(now)
	}
	if h, ok := c.entries[ip]; ok {
		h.lastSeen = now
		c.entries[ip] = h
		return h, true
	}
	// No extra sweep under pressure. This branch used to call
	// sweepExpired on every frame from a new CIDR source while the map
	// was full, i.e. a full MaxClientSeries walk per packet (~10.6us at
	// 1024 entries), even though the gate above and the dedicated 1s
	// sweeper already evict idle clients. A spoofed flood can now hold
	// the map at its cap for at most one sweep interval; after that the
	// sleeper releases the TTL-expired slots exactly as before, without
	// the per-packet O(n).
	if len(c.entries) >= MaxClientSeries {
		return clientHandles{}, false
	}
	key := ip.String()
	h := clientHandles{
		recv:     ServerProbesReceived.WithLabelValues(c.source, key),
		skew:     ServerClockSkew.WithLabelValues(c.source, key),
		key:      key,
		lastSeen: now,
	}
	c.entries[ip] = h
	return h, true
}

// startSweeper starts a dedicated ticker that evicts idle dynamic clients
// regardless of incoming traffic, and returns a stop function that joins it.
func (c *dynClientCache) startSweeper(ctx context.Context) func() {
	dynStop := make(chan struct{})
	dynDone := make(chan struct{})
	go func() {
		defer close(dynDone)
		ticker := time.NewTicker(dynSweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-dynStop:
				return
			case now := <-ticker.C:
				c.mu.Lock()
				// Record the sweep time so resolve()'s once-per-second gate
				// does not walk the map a second time on the next probe.
				c.lastSweep = now
				c.sweepExpired(now)
				c.mu.Unlock()
			}
		}
	}()
	return func() {
		close(dynStop)
		<-dynDone
	}
}

type udpServer struct {
	ctx              context.Context
	pc               net.PacketConn
	allowed          *Allowlist
	echoSecret       string
	expectedSize     int
	rl               *rateLimiter
	guard            *echoDupGuard
	curMAC           *probeMACer
	oldMAC           *probeMACer
	handles          map[netip.Addr]clientHandles
	dyn              *dynClientCache
	drops            serverDropCounters
	echoErrors       prometheus.Counter
	unauthHMACFrames prometheus.Counter

	lastWriteLog         time.Time
	lastReplayLog        time.Time
	consecutiveReadFails int
	warnedReadErrors     bool
}

func newUDPServer(ctx context.Context, pc net.PacketConn, source string, allowed *Allowlist, echoSecret string, echoSecretOld ...string) *udpServer {
	// Pre-resolve per-client metric handles for exact allowlist IPs once:
	// only allowlisted IPs reach these metrics, so the set is bounded by
	// the exact allowlist (max 256). Avoids the per-packet WithLabelValues
	// hash+lookup on the hot path — the same resolve-once convention the
	// client probe loop uses. Prefix-matched clients resolve their handles
	// on demand under MaxClientSeries.
	handles := make(map[netip.Addr]clientHandles, len(allowed.exact))
	for ip := range allowed.exact {
		key := ip.String()
		handles[ip] = clientHandles{
			recv: ServerProbesReceived.WithLabelValues(source, key),
			skew: ServerClockSkew.WithLabelValues(source, key),
			key:  key,
		}
	}

	// Reusable HMAC states for the read loop's verify chain (single
	// goroutine, so one state per secret; crypto/hmac is not concurrent-
	// safe). Built once instead of the previous 2-4 hmac.New per frame.
	var curMAC, oldMAC *probeMACer
	expectedSize := PayloadSize
	if echoSecret != "" {
		expectedSize = PayloadSizeWithHMAC
		curMAC = newProbeMACer(echoSecret)
		// The EMPTY old secret must be rejected here, not tolerated
		// downstream: main passes the (usually empty) -echo-secret-old as a
		// one-element variadic, and a zero-length key is a perfectly valid
		// HMAC key — newProbeMACer("") would silently install a verifier for
		// HMAC-SHA256(key ""), so any off-path host could tag its own frames
		// and get them echoed (reflection, plus the victim's per-IP budget
		// burned) while the server looks correctly configured.
		if len(echoSecretOld) > 0 && echoSecretOld[0] != "" {
			oldMAC = newProbeMACer(echoSecretOld[0])
		}
	}

	return &udpServer{
		ctx:              ctx,
		pc:               pc,
		allowed:          allowed,
		echoSecret:       echoSecret,
		expectedSize:     expectedSize,
		rl:               newRateLimiter(MaxPktsPerIP, MaxPktsGlobal),
		guard:            newEchoDupGuard(),
		curMAC:           curMAC,
		oldMAC:           oldMAC,
		handles:          handles,
		dyn:              newDynClientCache(source),
		drops:            newServerDropCounters(source),
		echoErrors:       ServerEchoErrors.WithLabelValues(source),
		unauthHMACFrames: ServerUnauthHMACFrames.WithLabelValues(source),
	}
}

func (s *udpServer) handleReadError(err error) bool {
	if s.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
		return false
	}
	if isPeerUnreachable(err) {
		// A client (or a spoofed source inside an allowlisted CIDR)
		// is unreachable: normal, and no reason to count toward the
		// failure bound. Same classification as the client's reader.
		s.consecutiveReadFails = 0
		slog.Debug("UDP read error (peer unreachable)", "err", err)
		return true
	}
	// Unexpected read errors on an unconnected UDP socket are
	// transient; the loop survives them, but bounded so a socket that
	// fails persistently cannot peg a core at Debug level.
	s.consecutiveReadFails++
	if s.consecutiveReadFails >= maxConsecutiveServerReadFails {
		if !s.warnedReadErrors {
			s.warnedReadErrors = true
			slog.Error("Persistent UDP read errors; backing off (echo service degraded)",
				"consecutive_failures", s.consecutiveReadFails, "err", err)
		}
		select {
		case <-s.ctx.Done():
			return false
		case <-time.After(serverReadErrorBackoff):
		}
		return true
	}
	slog.Debug("UDP read error", "err", err)
	return true
}

func (s *udpServer) handlePacket(buf []byte, n int, raddr net.Addr) {
	// Cheap untrusted-source rejection MUST stay ahead of crypto
	// work: any internet host must not be able to buy HMAC-SHA256
	// CPU per flood packet on a latency-measuring box. The echo
	// responder is UDP-only, so ReadFrom yields a *net.UDPAddr whose
	// IP converts to a netip.Addr with no allocation and no string
	// round-trip: the string form is materialised only when a log line
	// or a new metric series actually needs it.
	ua, ok := raddr.(*net.UDPAddr)
	if !ok {
		s.drops.invalidAddr.Inc()
		return
	}
	na, ok := netip.AddrFromSlice(ua.IP)
	if !ok {
		s.drops.invalidAddr.Inc()
		return
	}
	na = na.Unmap()
	if !s.allowed.Contains(na) {
		s.drops.allowlist.Inc()
		return
	}
	// Deliberate invariant: the global budget is charged pre-validation
	// so total work in this loop, HMAC-SHA256 included, is bounded by
	// MaxPktsGlobal; the per-IP budget is charged post-validation so
	// only frames that actually authenticate can spend a legit
	// client's allowance (spoofed junk inside an allowed CIDR must not
	// fake 100% loss for that client).
	if reason := s.rl.chargeGlobal(); reason != "" {
		s.drops.rateGlobal.Inc()
		return
	}

	// Accept header plus bounded payload; reject oversized reflector attempts.
	if n < s.expectedSize || n > s.expectedSize+MaxPayloadBytes {
		s.drops.size.Inc()
		return
	}
	if string(buf[0:8]) != MagicBytes {
		s.drops.magic.Inc()
		return
	}
	// Count bare 32B frames received without -echo-secret as half-configured HMAC.
	// Larger 32B+payload frames are indistinguishable from valid -payload probes.
	if s.echoSecret == "" && n == PayloadSizeWithHMAC {
		s.unauthHMACFrames.Inc()
	}
	// Authenticate and check replay window BEFORE handle resolution so unauthenticated
	// sources cannot consume MaxClientSeries slots or inflate label cardinality.
	var skew time.Duration
	if s.echoSecret != "" {
		seq := binary.LittleEndian.Uint64(buf[8:16])
		ts := binary.LittleEndian.Uint64(buf[16:24])
		// Accept either header-only (v0.7) or full-frame (v0.8+) tags on payload frames.
		if !macAny(s.curMAC, s.oldMAC, seq, ts, buf[24:32]) {
			if n == s.expectedSize || !fullFrameAny(s.curMAC, s.oldMAC, buf[:n]) {
				s.drops.hmac.Inc()
				return
			}
		}
		skew = time.Since(time.Unix(0, int64(ts)))
		if skewReplayed(skew) {
			s.drops.replay.Inc()
			if s.lastReplayLog.IsZero() || time.Since(s.lastReplayLog) >= time.Minute {
				slog.Warn("replayed or stale probe timestamp rejected (check NTP/clock sync)", "addr", na.String(), "skew", skew, "window", maxReplayWindow)
				s.lastReplayLog = time.Now()
			}
			return
		}
	}
	// Echo-loop guard: a frame identical to one recently echoed (same
	// source, seq, timestamp) is a bounce off another responder (or an
	// in-window replay), not a live probe — echoing it again would
	// sustain the loop forever. Runs BEFORE per-IP charge and BEFORE handle
	// resolution so a dup never spends budget or allocates a series.
	key := echoFrameKey(na, buf)
	if _, dup := s.guard.seen[key]; dup {
		s.drops.dup.Inc()
		return
	}
	// Per-IP budget is charged here, after authentication (or, with no
	// secret, after size/magic) and after the dup guard.
	if reason := s.rl.chargeIP(na); reason != "" {
		s.drops.rateIP.Inc()
		return
	}
	// Resolve the per-client metric handles last: exact allowlist IPs hit
	// the pre-resolved map with no lock, while prefix matches go through
	// the capped dynamic map (H1 cardinality guard).
	h, pre := s.handles[na]
	if !pre {
		res, resOK := s.dyn.resolve(na)
		if !resOK {
			s.drops.clientOverflow.Inc()
			return
		}
		h = res
	}
	if s.echoSecret != "" {
		// The gauge is set only for in-window frames: a single replayed
		// authenticated frame would otherwise peg the skew gauge at
		// hours and trip the ClockSkewApproaching alert.
		h.skew.Set(skew.Seconds())
	}

	h.recv.Inc()
	// Record the identity immediately BEFORE the echo write, not after
	// a successful write: the check→record window must not include the
	// write syscall, and in secret-less mode a registered-but-unechoed
	// identity merely loses that one frame instead of opening a race window.
	s.guard.record(key)
	if nw, err := s.pc.WriteTo(buf[:n], raddr); err != nil {
		if s.ctx.Err() == nil {
			s.echoErrors.Inc()
			if s.lastWriteLog.IsZero() || time.Since(s.lastWriteLog) >= time.Minute {
				slog.Warn("UDP echo write failed (further failures logged at most once per minute)", "addr", raddr, "bytes", nw, "err", err)
				s.lastWriteLog = time.Now()
			}
		}
	}
}

func (s *udpServer) serve() error {
	buf := make([]byte, MaxDatagramSize)
	for {
		n, raddr, err := s.pc.ReadFrom(buf)
		if err != nil {
			if !s.handleReadError(err) {
				return nil
			}
			continue
		}
		s.consecutiveReadFails = 0
		s.warnedReadErrors = false
		s.handlePacket(buf, n, raddr)
	}
}

// ServePacketConn runs the UDP echo loop on pc. Datagrams whose size is
// the expected header (PayloadSize, or PayloadSizeWithHMAC when a secret
// is set) plus a bounded payload extension, with a valid magic header
// from an allowlisted source, are echoed and counted; everything else is
// dropped. The allowlist is
// fail-closed: an empty or nil map admits no clients, so only permitted
// prober IPs can drive the echo responder or contribute metric labels.
// Per-IP and global rate limits bound echo processing. Datagram
// handling order is deliberate: the fail-closed allowlist and the global
// rate charge run ahead of any per-packet validation work, so a flood
// from a non-allowlisted host costs no crypto and no metric work;
// validation (size, magic, HMAC, replay window) then runs ahead of the
// per-IP charge, so only frames that actually authenticate can spend a
// client's per-IP budget, and the dup guard runs ahead of the per-IP
// charge but before any metric-handle resolution: a frame identical to
// one recently echoed (same source, seq, timestamp — an echo loop or an
// in-window replay) is dropped as dup, never spends a client's per-IP
// budget, and never allocates a series or a MaxClientSeries slot. Blocks
// until ctx is cancelled or pc is closed.
// A recovered panic is returned as an error so callers treat it as a
// fatal failure, never a clean exit.
// When echoSecret is non-empty, only HMAC-authenticated datagrams with a
// fresh timestamp are accepted; this mitigates reflector spoofing
// (SEC22). When empty, backward-compatible 24-byte-header datagrams (plus
// any bounded payload) are accepted.
// During a rotation, echoSecretOld (when set) is also accepted so clients
// can switch to the new secret one endpoint at a time.
func ServePacketConn(ctx context.Context, pc net.PacketConn, source string, allowed *Allowlist, echoSecret string, echoSecretOld ...string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			retErr = fmt.Errorf("echo server panic: %v", r)
			slog.Error("panic in echo server", "panic", r)
		}
	}()
	s := newUDPServer(ctx, pc, source, allowed, echoSecret, echoSecretOld...)
	stopSweeper := s.dyn.startSweeper(ctx)
	defer stopSweeper()
	return s.serve()
}
