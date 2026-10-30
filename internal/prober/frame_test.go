package prober

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

// TestBuildProbeFrame_WireLayout pins the one frame builder shared by the
// main prober and the MTU sweep: magic, seq, ts, the payload at the header
// boundary implied by the presence of a tag, and the tag computed over the
// coverage the caller selected. The tag is recomputed here from the wire
// layout, not through probeMACer, so a change to the digest or the offsets
// has to be made in two independent places.
func TestBuildProbeFrame_WireLayout(t *testing.T) {
	seq := uint64(7)
	ts := uint64(1727000000123456789)

	for _, tc := range []struct {
		name     string
		secret   string
		coverage HmacCoverage
		payload  int
	}{
		{"no secret, no payload", "", HMACHeaderCoverage, 0},
		{"no secret, payload", "", HMACHeaderCoverage, 64},
		{"secret, header, no payload", "s3cret", HMACHeaderCoverage, 0},
		{"secret, header, payload", "s3cret", HMACHeaderCoverage, 64},
		{"secret, full-frame, no payload", "s3cret", HMACFullFrameCoverage, 0},
		{"secret, full-frame, payload", "s3cret", HMACFullFrameCoverage, 64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			headerSize := PayloadSize
			var mac *probeMACer
			if tc.secret != "" {
				headerSize = PayloadSizeWithHMAC
				mac = newProbeMACer(tc.secret)
			}
			buf := make([]byte, headerSize+tc.payload)
			buildProbeFrame(buf, seq, ts, tc.payload, mac, tc.coverage)

			if got := string(buf[0:8]); got != MagicBytes {
				t.Fatalf("magic = %q, want %q", got, MagicBytes)
			}
			if got := binary.LittleEndian.Uint64(buf[8:16]); got != seq {
				t.Fatalf("seq = %d, want %d", got, seq)
			}
			if got := binary.LittleEndian.Uint64(buf[16:24]); got != ts {
				t.Fatalf("ts = %d, want %d", got, ts)
			}
			if tc.payload > 0 {
				want := make([]byte, tc.payload)
				x := seq*0x9E3779B97F4A7C15 ^ ts
				for i := range want {
					x ^= x << 13
					x ^= x >> 7
					x ^= x << 17
					want[i] = byte(x >> 24)
				}
				if !bytes.Equal(buf[headerSize:], want) {
					t.Fatalf("payload must start at offset %d (the header boundary): got %x, want %x",
						headerSize, buf[headerSize:], want)
				}
			}
			if tc.secret == "" {
				return
			}
			m := hmac.New(sha256.New, []byte(tc.secret))
			m.Write(buf[0:PayloadSize])
			if tc.coverage == HMACFullFrameCoverage && tc.payload > 0 {
				m.Write(buf[PayloadSizeWithHMAC:])
			}
			var want [8]byte
			copy(want[:], m.Sum(nil)[:8])
			if !hmac.Equal(want[:], buf[24:32]) {
				t.Fatalf("tag = %x, want %x (coverage %v, payload %d)", buf[24:32], want, tc.coverage, tc.payload)
			}
		})
	}
}
