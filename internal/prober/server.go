package prober

import (
	"context"
	"errors"
	"log/slog"
	"net"
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

// rateLimiter is a fixed-window per-IP + global packet rate limiter for
// the UDP echo loop.
type rateLimiter struct {
	mu      sync.Mutex
	window  time.Time
	perIP   map[string]int
	global  int
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

// RunServer starts a UDP echo responder on addr. Each accepted 24-byte
// datagram with a valid magic header is echoed back to its sender and
// counted in ServerProbesReceived under the remote IP. There is no
// connection lifecycle: loss is measured exactly because UDP does not
// retransmit. Blocks until ctx is cancelled, then closes the socket.
func RunServer(ctx context.Context, addr string, source string) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	slog.Info("Echo server listening (UDP)", "addr", addr)

	go func() {
		<-ctx.Done()
		pc.Close()
	}()

	return ServePacketConn(ctx, pc, source)
}

// ServePacketConn runs the UDP echo loop on pc. Datagrams of exactly
// PayloadSize bytes with a valid magic header are echoed and counted;
// everything else is dropped. Per-IP and global rate limits bound echo
// processing. Blocks until ctx is cancelled or pc is closed.
func ServePacketConn(ctx context.Context, pc net.PacketConn, source string) error {
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
		ip, _, err := net.SplitHostPort(raddr.String())
		if err != nil {
			continue
		}
		if !rl.allow(ip) {
			continue
		}

		ServerProbesReceived.WithLabelValues(source, ip).Inc()
		if _, err := pc.WriteTo(buf[:n], raddr); err != nil && ctx.Err() == nil {
			slog.Debug("UDP write error", "addr", raddr, "err", err)
		}
	}
}
