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
// Echoes are held to the same identity checks as the main reader's
// responses (see readEcho): echoed sequence, echoed timestamp byte-equality,
// and the echoed HMAC tag when -echo-secret is set — the sweep socket is a
// connected socket on the same public frame layout, so an echo that the
// prober did not send must not steer the search.
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
	var warnedDSCP bool
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
		// Mark the sweep socket like the main probes: -dscp exists so QoS-managed
		// networks treat probes as the traffic class they emulate, and on a policed
		// path an unmarked DF probe can be shaped or dropped differently from the
		// marked main probes — the sweep would then report a smaller MTU than the
		// path actually provides. Best effort, warned once.
		if cfg.DSCP > 0 {
			if err := setDSCP(conn, cfg.DSCP, conn.RemoteAddr()); err != nil {
				if !warnedDSCP {
					warnedDSCP = true
					logger.Warn("MTU sweep probes cannot be DSCP-marked; sweep continues unmarked", "dscp", cfg.DSCP, "err", err)
				}
			}
		}
		largest, ok := sweepOnce(ctx, conn, cfg, m, state, headerSize)
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

// mtuDeadline is the wait a single DF probe gets: the timeout the main loop is
// currently applying. In adaptive mode that is the smoothed RTO, NOT the
// configured -timeout — on a link whose RTT exceeds -timeout (the long-haul
// case the dynamic RTO floor exists for) a static deadline would make every DF
// probe time out, so the sweep could never discover anything and
// MtuSweepUnresolved would blame DF blocking for a path that carries
// full-size frames fine. The main loop publishes the applied timeout into
// state.rtoNs after each tick (atomic); it is 0 before the first tick, which
// falls back to cfg.BaseTimeout.
func mtuDeadline(cfg Config, state *probeLoopState) time.Duration {
	deadline := cfg.BaseTimeout
	if ns := state.rtoNs.Load(); ns > 0 {
		if rto := time.Duration(ns); rto > deadline {
			deadline = rto
		}
	}
	return deadline
}

// readEcho waits for an echo of exactly size bytes whose sequence is one of
// seqs, whose timestamp byte-equals the ts this sweep sent for that sequence
// (sent maps seq -> ts), and — when the sweep runs with -echo-secret — whose
// trailing 8-byte tag matches computeHMAC(secret, seq, ts), compared
// constant-time (validHMAC). The main reader applies the same identity
// checks to its responses; without them a peer able to inject into the
// connected DF socket could fabricate an echo for the currently probed size
// (sequence numbers are deterministic) and steer the binary search.
// Foreign datagrams and echoes of another size are SKIPPED rather than
// taken as this probe's answer: one socket serves the whole sweep, so a late
// echo of a larger size would otherwise be consumed as a failure of a smaller
// size that may well survive, stepping the binary search below the real MTU.
// Forged or stale frames are skipped the same way, and the deadline is
// absolute, so skipping cannot extend the wait (and a stream of foreign
// datagrams cannot spin the loop past it).
func readEcho(conn net.Conn, buf []byte, size int, seqs []uint64, sent map[uint64]uint64, secret string, deadline time.Time) error {
	if err := conn.SetReadDeadline(deadline); err != nil {
		return err
	}
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return err
		}
		if n != size || string(buf[0:8]) != MagicBytes {
			continue // a foreign or other-size datagram: keep waiting for ours
		}
		got := binary.LittleEndian.Uint64(buf[8:16])
		var awaited uint64
		awaitedOK := false
		for _, s := range seqs {
			if got == s {
				awaited, awaitedOK = s, true
				break
			}
		}
		if !awaitedOK {
			continue // a foreign sequence: keep waiting for ours
		}
		wantSent, ok := sent[awaited]
		if !ok {
			// The caller awaited this sequence but never recorded its
			// timestamp: the frame layout is known but the echo cannot be
			// authenticated against what we sent — treat as foreign.
			continue
		}
		if binary.LittleEndian.Uint64(buf[16:24]) != wantSent {
			// Echoed payload does not match what we sent: corruption,
			// replay, or spoofing. Skip it exactly like the main reader;
			// the probe stays lost at the absolute deadline.
			continue
		}
		if secret != "" && !validHMAC(secret, got, wantSent, buf[24:32]) {
			// buf[24:32] is in bounds here: secret set means size is at
			// least PayloadSizeWithHMAC, and the size gate above already
			// matched n == size.
			continue // wrong tag: not an echo the prober sent
		}
		return nil
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
// Each failed probe costs one probe deadline of wait, so a sweep is
// milliseconds on healthy links.
func sweepOnce(ctx context.Context, conn net.Conn, cfg Config, m targetMetrics, state *probeLoopState, headerSize int) (int, bool) {
	deadline := mtuDeadline(cfg, state)
	buf := make([]byte, headerSize+MaxPayloadBytes)
	var seq uint64
	// sent maps each sequence this sweep actually wrote to the timestamp it
	// carried: readEcho needs both to authenticate an echoed frame (echoed
	// ts must byte-equal what we sent, and the echoed tag must match the
	// HMAC over that pair when -echo-secret is set). Bounded by one sweep's
	// probe count (~2*log2(MaxPayloadBytes)+2).
	sent := make(map[uint64]uint64)

	// send writes one DF probe carrying payload bytes and returns the
	// sequence it used; 0 means the write failed (already counted lost).
	send := func(payload int) uint64 {
		if ctx.Err() != nil {
			return 0
		}
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
			return 0
		}
		sent[seq] = ts
		return seq
	}

	// waitEcho waits for an echo of THIS payload size whose sequence is one we
	// actually sent for it and whose echoed timestamp and (when configured)
	// HMAC tag match what we sent (see readEcho). Accepting every sequence
	// sent for this payload keeps the retry semantics: an echo of the first
	// attempt arriving during the retry still proves survival.
	waitEcho := func(payload int, seqs ...uint64) bool {
		if err := readEcho(conn, buf, headerSize+payload, seqs, sent, cfg.EchoSecret, time.Now().Add(deadline)); err != nil {
			m.mtuLost.Inc()
			return false
		}
		return true
	}
	// probeOnce is a single attempt with no retry: used for the header-only
	// abort probe, where paying the loser's timeout twice would be pointless.
	probeOnce := func(payload int) bool {
		s := send(payload)
		return s != 0 && waitEcho(payload, s)
	}
	// probeSurvives retries one loss before believing it: on a lossy path
	// (1% is enough) a single dropped probe would otherwise step the search
	// down from a size that actually fits, and path_mtu_bytes would flap
	// between sweeps.
	probeSurvives := func(payload int) bool {
		s1 := send(payload)
		if s1 == 0 {
			return false
		}
		if waitEcho(payload, s1) {
			return true
		}
		// Cancelled mid-sweep: do not pay the retry timeout after the
		// caller asked us to stop.
		if ctx.Err() != nil {
			return false
		}
		s2 := send(payload)
		if s2 == 0 {
			return false
		}
		return waitEcho(payload, s1, s2)
	}

	// Fast path: a healthy full-size path answers on the first probe — the
	// retry only fires after a loss, so the healthy case still costs one.
	if probeSurvives(MaxPayloadBytes) {
		return MaxPayloadBytes, true
	}
	if !probeOnce(0) {
		// Even the header-only DF probe dies: link down or DF-blocked
		// path. Leave the last known gauge value untouched. No retry here:
		// this is the abort path, and a dead link must not pay the loser's
		// timeout twice.
		return -1, false
	}
	lo, hi := 1, MaxPayloadBytes-1
	best := 0
	for lo <= hi {
		if ctx.Err() != nil {
			return -1, false
		}
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
