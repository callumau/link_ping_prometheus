package prober

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
)

// Wire protocol constants.
const (
	MagicBytes          = "LNKPING\x00"
	PayloadSize         = 24
	PayloadSizeWithHMAC = 32
	// MaxPayloadBytes caps the optional client payload beyond the header.
	// Frames stay well under MaxDatagramSize (1500) so a probe is never
	// IP-fragmented: header (24, or 32 with -echo-secret) + payload, i.e.
	// at most 1424 bytes normally and 1432 with HMAC.
	MaxPayloadBytes = 1400
)

// HmacCoverage selects which frame bytes the client's HMAC tag covers.
type HmacCoverage int

const (
	// HMACHeaderCoverage tags only the 24-byte header (magic+seq+ts): the
	// v0.7 behavior, the Go zero value, and the -hmac-coverage=header
	// escape hatch for v0.7 peers; the wire bytes are unchanged.
	HMACHeaderCoverage HmacCoverage = iota
	// HMACFullFrameCoverage tags the header AND the pattern payload while
	// skipping the 8-byte tag slot itself, closing the substitution gap
	// where a payload tampered in flight — or a different payload riding a
	// captured header tag — still authenticated.
	HMACFullFrameCoverage
)

// ParseHMACCoverage maps the -hmac-coverage flag value onto the enum.
func ParseHMACCoverage(s string) (HmacCoverage, error) {
	switch s {
	case "header":
		return HMACHeaderCoverage, nil
	case "full-frame":
		return HMACFullFrameCoverage, nil
	default:
		return 0, fmt.Errorf("invalid -hmac-coverage %q: must be \"header\" or \"full-frame\"", s)
	}
}

// probeHeaderSize is the frame header length: 32 bytes when an HMAC tag is
// present, 24 otherwise. One spelling for the sweep's buffer/write length
// and the path-MTU frame size; buildProbeFrame derives the same value from
// its MACer, which is created under the identical condition.
func probeHeaderSize(echoSecret string) int {
	if echoSecret != "" {
		return PayloadSizeWithHMAC
	}
	return PayloadSize
}

// fillPayload writes a deterministic pattern into the probe payload,
// derived from the frame's own seq/ts. The client regenerates the
// pattern from the echoed header and compares byte-for-byte: any
// in-flight corruption (or reflection of a wrong frame) surfaces as a
// corrupted frame — counted separately from loss — instead of as a
// valid-but-wrong RTT sample.
func fillPayload(buf []byte, seq, ts uint64) {
	// xorshift64* keyed by seq/ts: cheap, deterministic, well spread.
	x := seq*0x9E3779B97F4A7C15 ^ ts
	for i := range buf {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		buf[i] = byte(x >> 24)
	}
}

// tagsPayload reports whether the tag must cover the payload: full-frame
// coverage with at least one payload byte. With no payload the two coverages
// produce byte-identical tags, so the header tag is the same tag. One
// spelling of the condition for the send and read paths.
func tagsPayload(coverage HmacCoverage, payload int) bool {
	return coverage == HMACFullFrameCoverage && payload > 0
}

// buildProbeFrame writes one probe frame into buf: magic, sequence number,
// wire timestamp, the optional deterministic payload, and — when mac is
// non-nil — the 8-byte tag under coverage. The header size is derived from
// mac so a caller cannot pair a 24-byte header with a tag slot; payload is
// the number of pattern bytes after the header. buf must have room for the
// header plus payload (24+payload without a tag, 32+payload with one). This
// is the single spelling of the wire layout, shared by the main prober and
// the MTU sweep: two spellings could tag differently on a full-frame
// deployment and silently stop authenticating.
func buildProbeFrame(buf []byte, seq, ts uint64, payload int, mac *probeMACer, coverage HmacCoverage) {
	headerSize := PayloadSize
	if mac != nil {
		headerSize = PayloadSizeWithHMAC
	}
	copy(buf[0:8], MagicBytes)
	binary.LittleEndian.PutUint64(buf[8:16], seq)
	binary.LittleEndian.PutUint64(buf[16:24], ts)
	if payload > 0 {
		fillPayload(buf[headerSize:headerSize+payload], seq, ts)
	}
	if mac == nil {
		return
	}
	var tag [8]byte
	if tagsPayload(coverage, payload) {
		tag = mac.digestFrame(buf[:headerSize+payload])
	} else {
		tag = mac.digestHeader(seq, ts)
	}
	copy(buf[24:32], tag[:])
}

// probeMACer wraps ONE reusable crypto/hmac state. Every hot HMAC site
// (client loop, reader, MTU sweep, server read loop) is single-goroutine,
// so a Reset()-per-frame marshaler avoids the per-frame hmac struct +
// sha256 digest + Sum(nil) slice (3 allocs / ~250B/frame - measured
// dominant at the server's 10k/s global cap) and the two identical pad
// block-compressions crypto/hmac re-runs fresh per frame. Tag bytes do not
// depend on prior use of the state (the round-trip tests exercise reuse), and
// scratch holds Sum's output so digesting allocates nothing.
type probeMACer struct {
	h       hash.Hash
	scratch [32]byte
}

// newProbeMACer builds a reusable HMAC-SHA256 state for secret.
func newProbeMACer(secret string) *probeMACer {
	return &probeMACer{h: hmac.New(sha256.New, []byte(secret))}
}

// digestHeader truncates the header HMAC (magic+seq+ts) to 8 bytes - the
// v0.7 wire tag. Reset/Write/Sum on the same state next call.
func (m *probeMACer) digestHeader(seq, ts uint64) [8]byte {
	m.h.Reset()
	m.h.Write([]byte(MagicBytes))
	var tmp [16]byte
	binary.LittleEndian.PutUint64(tmp[0:8], seq)
	binary.LittleEndian.PutUint64(tmp[8:16], ts)
	m.h.Write(tmp[:])
	var out [8]byte
	copy(out[:], m.h.Sum(m.scratch[:0])[:8])
	return out
}

// digestFrame truncates the full-frame HMAC (header + payload, tag slot
// skipped) to 8 bytes. For a zero-payload frame (len ==
// PayloadSizeWithHMAC) it is byte-identical to digestHeader over the
// header - the forwards-compatibility keystone. The frame must be at
// least PayloadSize bytes; every caller is size-gated to at least
// PayloadSizeWithHMAC.
func (m *probeMACer) digestFrame(frame []byte) [8]byte {
	m.h.Reset()
	m.h.Write(frame[0:PayloadSize])
	if len(frame) > PayloadSizeWithHMAC {
		m.h.Write(frame[PayloadSizeWithHMAC:])
	}
	var out [8]byte
	copy(out[:], m.h.Sum(m.scratch[:0])[:8])
	return out
}

// verifyHeader reports whether tag matches the expected header tag.
// Constant-time via hmac.Equal.
func (m *probeMACer) verifyHeader(seq, ts uint64, tag []byte) bool {
	want := m.digestHeader(seq, ts)
	return hmac.Equal(want[:], tag)
}

// verifyFullFrame reports whether frame[24:32] matches the expected
// full-frame tag. Constant-time via hmac.Equal.
func (m *probeMACer) verifyFullFrame(frame []byte) bool {
	want := m.digestFrame(frame)
	return hmac.Equal(want[:], frame[24:32])
}

// macAny reports whether the tag matches the primary secret or, during a
// zero-downtime rotation, the previous secret. nil entries are skipped
// (no rotation / no secret). Constant-time per attempt.
func macAny(cur, old *probeMACer, seq, ts uint64, tag []byte) bool {
	if cur != nil && cur.verifyHeader(seq, ts, tag) {
		return true
	}
	return old != nil && old.verifyHeader(seq, ts, tag)
}

// fullFrameAny mirrors macAny for the full-frame coverage fallback.
func fullFrameAny(cur, old *probeMACer, frame []byte) bool {
	if cur != nil && cur.verifyFullFrame(frame) {
		return true
	}
	return old != nil && old.verifyFullFrame(frame)
}
