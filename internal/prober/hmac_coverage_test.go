package prober

import (
	"encoding/binary"
	"testing"
	"time"
)

// HMAC tag coverage: the tag covers either the 24-byte header only
// (default, v0.7 wire format) or header+payload with the 8-byte tag slot
// skipped. The zero-payload equivalence pinned here is the
// forwards-compatibility keystone: it is what makes an old 32-byte frame
// a valid full-frame tag and lets one server accept both coverages.

// hmacCoverageFrame builds a payload-bearing frame with the given tag
// bytes in the tag slot; payload is filled with the deterministic
// (seq, ts) pattern. len(tag) must be 8 or nil.
func hmacCoverageFrame(seq, ts uint64, payload int, tag []byte) []byte {
	f := make([]byte, PayloadSizeWithHMAC+payload)
	copy(f[0:8], MagicBytes)
	binary.LittleEndian.PutUint64(f[8:16], seq)
	binary.LittleEndian.PutUint64(f[16:24], ts)
	if tag != nil {
		copy(f[24:32], tag)
	}
	if payload > 0 {
		fillPayload(f[PayloadSizeWithHMAC:], seq, ts)
	}
	return f
}

// TestHMACCoverageZeroPayloadEquivalence pins the keystone invariant:
// the full-frame digest over a zero-payload 32-byte frame is
// byte-identical to the header digest. That identity is why the
// server can keep its header-only check for bare 32-byte frames (the
// second coverage attempt could never change the outcome) and why
// empty-payload frames behave identically under both coverages — an old
// server and an old client still interoperate byte-for-byte with new
// builds that run full-frame coverage without -payload.
func TestHMACCoverageZeroPayloadEquivalence(t *testing.T) {
	keys := []string{"coverage-secret", "rotation-secret", "other"}
	ts := uint64(time.Now().UnixNano())
	for _, key := range keys {
		for _, seq := range []uint64{0, 1, 42, ^uint64(0)} {
			wantHeader := headerTag(key, seq, ts)
			frame := hmacCoverageFrame(seq, ts, 0, wantHeader[:])
			if got := frameTag(key, frame); got != wantHeader {
				t.Errorf("frameTag over a zero-payload frame must equal headerTag (key %q, seq %d)", key, seq)
			}
		}
	}
}

// TestValidHMACFullFrame pins the full-frame acceptance rule: a frame
// tagged over header+payload verifies; the same frame with the payload
// tampered AFTER tagging does not — that is the substitution gap this
// coverage closes (today a payload could ride a captured header tag).
func TestValidHMACFullFrame(t *testing.T) {
	const secret = "coverage-secret"
	const payload = 96
	seq := uint64(7)
	ts := uint64(1727000000123456789)

	frame := hmacCoverageFrame(seq, ts, payload, nil)
	tag := frameTag(secret, frame)
	copy(frame[24:32], tag[:])

	if !newProbeMACer(secret).verifyFullFrame(frame) {
		t.Error("a correctly full-frame-tagged payload frame must authenticate")
	}
	// Same (seq, ts, tag), different payload bytes: must NOT authenticate.
	tampered := make([]byte, len(frame))
	copy(tampered, frame)
	tampered[PayloadSizeWithHMAC] ^= 0xFF
	tampered[len(tampered)-1] ^= 0x01
	if newProbeMACer(secret).verifyFullFrame(tampered) {
		t.Error("a tampered payload riding the captured tag must NOT authenticate under full-frame coverage")
	}
	// Wrong secret rejected.
	if newProbeMACer("different-secret").verifyFullFrame(frame) {
		t.Error("a full-frame tag must not verify under a different secret")
	}
	// The header check (v0.7 path) still fails for this frame: a
	// full-frame tag is not a header tag when a payload exists.
	if newProbeMACer(secret).verifyHeader(seq, ts, frame[24:32]) {
		t.Error("a full-frame tag must not authenticate under the header-only check")
	}
}

// TestValidHMACHeaderPathUnchangedForOldFrames pins that the v0.7 wire
// format still authenticates exactly as before: a header-tagged 32-byte
// frame — with or without a payload extension — passes the header check
// under either configured coverage. Nothing about the old bytes moved.
func TestValidHMACHeaderPathUnchangedForOldFrames(t *testing.T) {
	const secret = "coverage-secret"
	ts := uint64(1727000000123456789)
	for _, seq := range []uint64{1, 99} {
		for _, payload := range []int{0, 64} {
			frame := hmacCoverageFrame(seq, ts, payload, nil)
			tag := headerTag(secret, seq, ts)
			copy(frame[24:32], tag[:])
			if !newProbeMACer(secret).verifyHeader(seq, ts, frame[24:32]) {
				t.Errorf("the v0.7 header-tag frame (seq %d, payload %d) must still authenticate via verifyHeader", seq, payload)
			}
			if !macAny(macerOrNil(secret), macerOrNil("stale-rotation-secret"), seq, ts, frame[24:32]) {
				t.Errorf("macAny must accept the primary secret's header tag (seq %d, payload %d)", seq, payload)
			}
		}
	}
}

// TestValidHMACFullFrameAny pins the rotation path for the full-frame
// coverage: the previous secret authenticates during a rotation, the
// same way the header path does.
func TestValidHMACFullFrameAny(t *testing.T) {
	const secret = "new-secret"
	const secretOld = "old-secret"
	ts := uint64(1727000000123456789)

	for _, secretOf := range []string{secret, secretOld} {
		frame := hmacCoverageFrame(11, ts, 32, nil)
		tag := frameTag(secretOf, frame)
		copy(frame[24:32], tag[:])
		if !fullFrameAny(macerOrNil(secret), macerOrNil(secretOld), frame) {
			t.Errorf("fullFrameAny must accept a %s-tagged frame during rotation", secretOf)
		}
	}
	// An unknown secret still fails both attempts.
	frame := hmacCoverageFrame(12, ts, 32, nil)
	tag := frameTag("unknown", frame)
	copy(frame[24:32], tag[:])
	if fullFrameAny(macerOrNil(secret), macerOrNil(secretOld), frame) {
		t.Error("fullFrameAny must reject a tag from an unknown secret")
	}
	// No rotation in progress: only the primary secret is consulted.
	frame2 := hmacCoverageFrame(13, ts, 32, nil)
	tagOld := frameTag(secretOld, frame2)
	copy(frame2[24:32], tagOld[:])
	if fullFrameAny(macerOrNil(secret), macerOrNil(""), frame2) {
		t.Error("with no rotation, the old secret's tag must be rejected")
	}
	// The empty old secret must not install a verifier: a zero-length HMAC
	// key is a valid key, so a frame tagged under "" would otherwise pass.
	frameEmpty := hmacCoverageFrame(14, ts, 32, nil)
	tagEmpty := frameTag("", frameEmpty)
	copy(frameEmpty[24:32], tagEmpty[:])
	if fullFrameAny(macerOrNil(secret), macerOrNil(""), frameEmpty) {
		t.Error("the empty old secret must not be installed as a verifier")
	}
}

// TestParseHMACCoverage pins the flag grammar: the two documented values
// and everything else being an error (startup refuses to run).
func TestParseHMACCoverage(t *testing.T) {
	good := map[string]HmacCoverage{
		"header":     HMACHeaderCoverage,
		"full-frame": HMACFullFrameCoverage,
	}
	for value, want := range good {
		got, err := ParseHMACCoverage(value)
		if err != nil || got != want {
			t.Errorf("ParseHMACCoverage(%q) = %v, %v; want %v, nil", value, got, err, want)
		}
	}
	for _, value := range []string{"", "full", "HEADER", "frame", "header,full-frame"} {
		if _, err := ParseHMACCoverage(value); err == nil {
			t.Errorf("ParseHMACCoverage(%q) must be an error", value)
		}
	}
}
