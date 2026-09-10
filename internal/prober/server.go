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
		a.exact[addr.Unmap().String()] = struct{}{}
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
// The entries are stored unmapped by ParseAllowlist; net.IP.String()
// already renders a 4-in-6 source as dotted quad, but ip is unmapped
// here anyway so a caller passing a mapped address still matches.
func (a *Allowlist) Allows(norm string, ip netip.Addr) bool {
	if a.Len() == 0 {
		return false
	}
	if _, ok := a.exact[norm]; ok {
		return true
	}
	ip = ip.Unmap()
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

// resetLocked rolls the fixed window forward when a second has elapsed.
// Caller must hold r.mu.
func (r *rateLimiter) resetLocked(now time.Time) {
	if now.Sub(r.window) >= time.Second {
		r.window = now
		// clear in place (Go 1.21+) instead of reallocating: the window
		// resets every second for the lifetime of the server, so reusing
		// the map avoids per-second GC churn.
		clear(r.perIP)
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
func (r *rateLimiter) chargeIP(ip string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.resetLocked(time.Now())
	if r.perIP[ip] >= r.perIPCap {
		return "rate_ip"
	}
	r.perIP[ip]++
	return ""
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
			} else if p.Bits() >= 64 {
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
// Per-IP and global rate limits bound echo processing. Datagram
// handling order is deliberate: the fail-closed allowlist and the global
// rate charge run ahead of any per-packet validation work, so a flood
// from a non-allowlisted host costs no crypto and no metric work;
// validation (size, magic, HMAC, replay window) then runs ahead of the
// per-IP charge, so only frames that actually authenticate can spend a
// client's per-IP budget. Blocks until ctx is cancelled or pc is closed.
// A recovered panic is returned as an error so callers treat it as a
// fatal failure, never a clean exit.
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
	var lastWriteLog time.Time
	var lastReplayLog time.Time
	// Pre-resolve the echo-failure counter once: a label lookup per write
	// error would be pointless work on the hot path.
	echoErrors := ServerEchoErrors.WithLabelValues(source)

	// Pre-resolve the fixed set of drop reasons once, so a dropped
	// datagram (the flood case) costs no label-map hashing. If a new drop
	// reason is added, add a field here and to the Help text in metrics.go.
	drops := struct {
		invalidAddr, allowlist, rateIP, rateGlobal, size, magic, clientOverflow, hmac, replay prometheus.Counter
	}{
		invalidAddr:    ServerProbesDropped.WithLabelValues(source, "invalid_addr"),
		allowlist:      ServerProbesDropped.WithLabelValues(source, "allowlist"),
		rateIP:         ServerProbesDropped.WithLabelValues(source, "rate_ip"),
		rateGlobal:     ServerProbesDropped.WithLabelValues(source, "rate_global"),
		size:           ServerProbesDropped.WithLabelValues(source, "size"),
		magic:          ServerProbesDropped.WithLabelValues(source, "magic"),
		clientOverflow: ServerProbesDropped.WithLabelValues(source, "client_overflow"),
		hmac:           ServerProbesDropped.WithLabelValues(source, "hmac"),
		replay:         ServerProbesDropped.WithLabelValues(source, "replay"),
	}

	// Pre-resolve per-client metric handles for exact allowlist IPs once:
	// only allowlisted IPs reach these metrics, so the set is bounded by
	// the exact allowlist (max 256). Avoids the per-packet WithLabelValues
	// hash+lookup on the hot path — the same resolve-once convention the
	// client probe loop uses. Prefix-matched clients resolve their handles
	// on demand under MaxClientSeries (see resolve below).
	type clientHandles struct {
		recv prometheus.Counter
		skew prometheus.Gauge
		// lastSeen ages dynamic entries out (DynClientTTL); unused for
		// pre-resolved exact-IP handles, which are never evicted.
		lastSeen time.Time
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
	var lastSweep time.Time
	// sweepExpired drops clients idle for DynClientTTL. Caller must hold
	// dynMu. Both the map entry AND the Prometheus series are removed —
	// the vecs retain a series per label set forever otherwise, so
	// lifetime cardinality would still grow without bound.
	sweepExpired := func(now time.Time) {
		for ip, eh := range dyn {
			if now.Sub(eh.lastSeen) >= DynClientTTL {
				ServerProbesReceived.DeleteLabelValues(source, ip)
				ServerClockSkew.DeleteLabelValues(source, ip)
				delete(dyn, ip)
			}
		}
	}
	resolve := func(norm string) (clientHandles, bool) {
		dynMu.Lock()
		defer dynMu.Unlock()
		now := time.Now()
		// Sweep on every resolve, not only under MaxClientSeries pressure:
		// below the cap an expired client's series would otherwise be
		// exported forever at its last value (a frozen link_server_clock_skew
		// alert that can never resolve). Time-gated because the walk is
		// O(len(dyn)) under the lock; a live client refreshes lastSeen on
		// each resolve, so it is never evicted.
		if now.Sub(lastSweep) >= dynSweepInterval {
			lastSweep = now
			sweepExpired(now)
		}
		if h, ok := dyn[norm]; ok {
			h.lastSeen = now
			dyn[norm] = h
			return h, true
		}
		if len(dyn) >= MaxClientSeries {
			// Under pressure, sweep idle clients regardless of the gate
			// above: a source may reach resolve before HMAC validation, so
			// spoofed sources inside an allowed CIDR could otherwise pin
			// every slot and black out all other CIDR-matched clients
			// (client_overflow) permanently.
			sweepExpired(now)
		}
		if len(dyn) >= MaxClientSeries {
			return clientHandles{}, false
		}
		h := clientHandles{
			recv:     ServerProbesReceived.WithLabelValues(source, norm),
			skew:     ServerClockSkew.WithLabelValues(source, norm),
			lastSeen: now,
		}
		dyn[norm] = h
		return h, true
	}

	// A dedicated sweeper ticks regardless of traffic: resolve()'s gate
	// only runs when another prefix-matched probe arrives, so a lone CIDR
	// client that disappears would otherwise keep its series (and a frozen
	// link_server_clock_skew alert) forever. The stop channel is closed by
	// the defer below once the read loop returns; ctx cancellation alone
	// closes pc and lets the read loop exit, after which this join runs, so
	// ServePacketConn never leaks the goroutine into a later test.
	dynStop := make(chan struct{})
	dynDone := make(chan struct{})
	defer func() {
		close(dynStop)
		<-dynDone
	}()
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
				dynMu.Lock()
				// Record the sweep time so resolve()'s once-per-second gate
				// does not walk the map a second time on the next probe.
				lastSweep = now
				sweepExpired(now)
				dynMu.Unlock()
			}
		}
	}()

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
		// CPU per flood packet on a latency-measuring box. The echo
		// responder is UDP-only, so ReadFrom yields a *net.UDPAddr whose
		// IP is already canonical for the allowlist lookup (no string
		// round-trip or double parsing).
		ua, ok := raddr.(*net.UDPAddr)
		if !ok {
			drops.invalidAddr.Inc()
			continue
		}
		norm := ua.IP.String()
		// ua.IP.String() of a socket-reported IP is always parseable.
		na, _ := netip.ParseAddr(norm)
		if !allowed.Allows(norm, na) {
			drops.allowlist.Inc()
			continue
		}
		// Deliberate invariant: the global budget is charged pre-validation
		// so total work in this loop, HMAC-SHA256 included, is bounded by
		// MaxPktsGlobal; the per-IP budget is charged post-validation so
		// only frames that actually authenticate can spend a legit
		// client's allowance (spoofed junk inside an allowed CIDR must not
		// fake 100% loss for that client).
		if reason := rl.chargeGlobal(); reason != "" {
			drops.rateGlobal.Inc()
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
			drops.size.Inc()
			continue
		}
		if string(buf[0:8]) != MagicBytes {
			drops.magic.Inc()
			continue
		}
		// Authentication and the replay guard run BEFORE per-client handle
		// resolution. resolve() allocates a {source,client} series pair and
		// consumes one of the MaxClientSeries slots, so resolving first let
		// unauthenticated frames from inside an allowlisted CIDR grow the
		// label space and pin every slot, blacking out real clients as
		// client_overflow (manufactured 100% loss) and inflating /metrics.
		// Only a frame that authenticated — or, with no secret configured,
		// one that already passed the cheap size/magic checks — may create a
		// series.
		var skew time.Duration
		if echoSecret != "" {
			oldSecret := ""
			if len(echoSecretOld) > 0 {
				oldSecret = echoSecretOld[0]
			}
			seq := binary.LittleEndian.Uint64(buf[8:16])
			ts := binary.LittleEndian.Uint64(buf[16:24])
			if !validHMACAny(echoSecret, oldSecret, seq, ts, buf[24:32]) {
				drops.hmac.Inc()
				continue
			}
			// Replay guard: an authenticated frame older or newer than
			// the window is a capture-replay, not a live probe. Clocks
			// between nodes must be approximately synchronized (NTP).
			skew = time.Since(time.Unix(0, int64(ts)))
			if skew > maxReplayWindow || skew < -maxReplayWindow {
				drops.replay.Inc()
				// Throttled like the write-error warning: a captured frame
				// replayed at the per-IP cap — or a client with a large clock
				// skew — must not be able to flood the log. The counter still
				// records every rejection, so nothing is lost for alerting.
				if lastReplayLog.IsZero() || time.Since(lastReplayLog) >= time.Minute {
					slog.Warn("replayed or stale probe timestamp rejected (check NTP/clock sync)", "addr", norm, "skew", skew, "window", maxReplayWindow)
					lastReplayLog = time.Now()
				}
				continue
			}
		}
		// Per-IP budget is charged here, after authentication (or, with no
		// secret, after size/magic), so only frames that authenticate can
		// consume the source's allowance.
		if reason := rl.chargeIP(norm); reason != "" {
			drops.rateIP.Inc()
			continue
		}
		// Resolve the per-client metric handles last: exact allowlist IPs hit
		// the pre-resolved map with no lock, while prefix matches go through
		// the capped dynamic map (H1 cardinality guard), and a frame dropped
		// above for rate/HMAC/replay never allocates a series at all.
		h, pre := handles[norm]
		if !pre {
			res, resOK := resolve(norm)
			if !resOK {
				drops.clientOverflow.Inc()
				continue
			}
			h = res
		}
		if echoSecret != "" {
			// The gauge is set only for in-window frames: a single replayed
			// authenticated frame would otherwise peg the skew gauge at
			// hours and trip the ClockSkewApproaching alert.
			h.skew.Set(skew.Seconds())
		}

		h.recv.Inc()
		if nw, err := pc.WriteTo(buf[:n], raddr); err != nil && ctx.Err() == nil {
			// A failed echo is our fault, not the network's: count it so the
			// client's loss can be attributed correctly. Warn (throttled to
			// once per minute, as client.go's dial loop does) rather than
			// Debug-per-packet, which default verbosity would hide entirely.
			echoErrors.Inc()
			if lastWriteLog.IsZero() || time.Since(lastWriteLog) >= time.Minute {
				slog.Warn("UDP echo write failed (further failures logged at most once per minute)", "addr", raddr, "bytes", nw, "err", err)
				lastWriteLog = time.Now()
			}
		}
	}
}
