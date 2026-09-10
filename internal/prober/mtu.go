package prober

import (
	"context"
	"encoding/binary"
	"log/slog"
	"net"
	"time"
)

// runMTUSweep periodically discovers the largest probe frame the path
// carries with the DF bit set ("largest survives", no ICMP involved):
// a no-echo at size N (after the one retry sweepOnce applies) means the
// path does not survive N. Results feed link_path_mtu_bytes and /status.
// DF probes that vanish are counted in link_mtu_probes_lost_total —
// deliberately OUTSIDE the main sent/rtt/timed_out/corrupted balance so
// MTU probing never pollutes the loss ratio. Each sweep opens its own DF
// socket so the main probe socket's fragmentation behavior is untouched.
func runMTUSweep(ctx context.Context, t Target, cfg Config, m targetMetrics, state *probeLoopState, logger *slog.Logger) {
	// NewTimer(0): the first sweep fires immediately so path_mtu_bytes
	// is populated on startup instead of after the first full interval.
	timer := time.NewTimer(0)
	defer timer.Stop()
	headerSize := PayloadSize
	if cfg.EchoSecret != "" {
		headerSize = PayloadSizeWithHMAC
	}
	var warnedDF bool
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		conn, err := dialUDP(ctx, "udp", t.Address)
		if err != nil {
			// Transient dial failure: the main loop's handling governs
			// link_up; the sweep just waits for the next tick.
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(cfg.MTUSweep)
			continue
		}
		if err := setDontFragment(conn); err != nil {
			conn.Close()
			if !warnedDF {
				warnedDF = true
				logger.Warn("MTU sweep disabled: cannot set DF on this platform", "err", err)
			}
			return
		}
		largest, ok := sweepOnce(conn, cfg, m, headerSize)
		conn.Close()
		if ok {
			// Report the full probe frame size (header + payload);
			// add 28 elsewhere for IP/UDP overhead when comparing to
			// interface MTUs.
			frame := int64(headerSize + largest)
			m.pathMTU.Set(float64(frame))
			state.pathMTU.Store(frame)
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(cfg.MTUSweep)
	}
}

// sweepOnce binary-searches [0, MaxPayloadBytes] for the largest payload
// that echoes back on the DF socket. A failed size is retried once
// before it counts as "does not survive": a single dropped probe on a
// lossy path would otherwise converge far below the real MTU and make
// path_mtu_bytes flap (e.g. 1424 → 1248 at 1% loss). A success
// short-circuits its retry, so a healthy path still costs one probe per
// size. ~2*log2(MaxPayloadBytes) probes when the path is smaller; 3 when
// the link is down (the full-size probe and its retry fail, then the
// header-only probe aborts, leaving the gauge at its last known value).
// Each failed probe costs one base timeout of wait, so a sweep is
// milliseconds on healthy links.
func sweepOnce(conn net.Conn, cfg Config, m targetMetrics, headerSize int) (int, bool) {
	deadline := cfg.BaseTimeout
	buf := make([]byte, headerSize+MaxPayloadBytes)
	var seq uint64
	probe := func(payload int) bool {
		seq++
		ts := uint64(time.Now().UnixNano())
		copy(buf[0:8], MagicBytes)
		binary.LittleEndian.PutUint64(buf[8:16], seq)
		binary.LittleEndian.PutUint64(buf[16:24], ts)
		if cfg.EchoSecret != "" {
			h := computeHMAC(cfg.EchoSecret, seq, ts)
			copy(buf[24:32], h[:])
		}
		if payload > 0 {
			// Pattern fill: keep the probe indistinguishable from real
			// opaque traffic for middleboxes (dedup/compression).
			fillPayload(buf[headerSize:headerSize+payload], seq, ts)
		}
		m.mtuSent.Inc()
		if _, err := conn.Write(buf[:headerSize+payload]); err != nil {
			m.mtuLost.Inc()
			return false
		}
		if err := conn.SetReadDeadline(time.Now().Add(deadline)); err != nil {
			m.mtuLost.Inc()
			return false
		}
		n, err := conn.Read(buf)
		if err != nil || n != headerSize+payload {
			m.mtuLost.Inc()
			return false
		}
		return true
	}
	// probeSurvives retries one loss before believing it: on a lossy path
	// (1% is enough) a single dropped probe would otherwise step the search
	// down from a size that actually fits, and path_mtu_bytes would flap
	// between sweeps.
	probeSurvives := func(payload int) bool {
		return probe(payload) || probe(payload)
	}

	// Fast path: a healthy full-size path answers on the first probe — the
	// retry only fires after a loss, so the healthy case still costs one.
	if probeSurvives(MaxPayloadBytes) {
		return MaxPayloadBytes, true
	}
	if !probe(0) {
		// Even the header-only DF probe dies: link down or DF-blocked
		// path. Leave the last known gauge value untouched. No retry here:
		// this is the abort path, and a dead link must not pay the loser's
		// timeout twice.
		return -1, false
	}
	lo, hi := 1, MaxPayloadBytes-1
	best := 0
	for lo <= hi {
		mid := int(uint(lo+hi) >> 1)
		if probeSurvives(mid) {
			best = mid
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	return best, true
}
