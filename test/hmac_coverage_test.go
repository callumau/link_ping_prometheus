package prober_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"link_ping_prometheus/internal/prober"
)

// Server dual-accept rule for HMAC tag coverage (round-2 audit): a server
// running -echo-secret accepts a payload frame tagged EITHER over the
// 24-byte header (v0.7 clients) or over header+payload with the tag slot
// skipped (clients on -hmac-coverage=full-frame). The bare 32-byte frame
// keeps its header-only check: the two coverages coincide byte-for-byte
// there, so nothing changes for zero-payload fleets. The tag builders
// here are deliberately reimplemented from the wire layout, not called
// into the prober, so the security contract is validated independently.

// hmacFullFrameTag computes the 8-byte full-frame tag independently of
// the prober package: truncated HMAC-SHA256 over frame[0:24] || frame[32:]
// (header, then payload — skipping the tag slot itself).
func hmacFullFrameTag(secret string, frame []byte) [8]byte {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(frame[0:24])
	mac.Write(frame[32:])
	var out [8]byte
	copy(out[:], mac.Sum(nil)[:8])
	return out
}

// buildPayloadFrame assembles a 32-byte header + payloadLen pattern bytes;
// fillPayload is reimplemented too (xorshift64*, keyed by seq/ts) so the
// test's tampering acts on frame bytes alone.
func buildPayloadFrame(seq, ts uint64, payloadLen int) []byte {
	f := make([]byte, prober.PayloadSizeWithHMAC+payloadLen)
	copy(f[0:8], prober.MagicBytes)
	binary.LittleEndian.PutUint64(f[8:16], seq)
	binary.LittleEndian.PutUint64(f[16:24], ts)
	x := seq*0x9E3779B97F4A7C15 ^ ts
	for i := prober.PayloadSizeWithHMAC; i < len(f); i++ {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		f[i] = byte(x >> 24)
	}
	return f
}

// TestServer_HMACCoverageDualAccept pins the server accept rule under a
// single secret: old-style header-tag + payload frames (v0.7 client pin),
// full-frame tag + payload frames (new pin), and bare 32-byte frames
// under either coverage all echo; a full-frame tag over a TAMPERED
// payload is rejected as an hmac drop (the substitution this coverage
// closes), while an old-style header tag over a tampered payload is still
// accepted — today's behavior, deliberate: the header tag cannot see the
// payload. That gap closes only when CLIENTS flip to
// -hmac-coverage=full-frame; until then the payload pattern check on the
// client is what surfaces tampering as link_probes_corrupted_total.
func TestServer_HMACCoverageDualAccept(t *testing.T) {
	prober.InitMetrics()
	ctx := t.Context()

	const secret = "dual-accept-secret"
	addr := startHMACServer(t, ctx, secret)

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	now := uint64(time.Now().UnixNano())
	const payloadLen = 96

	frame := buildPayloadFrame(1, now, payloadLen)
	headerTag := hmacTag(secret, 1, now)
	copy(frame[24:32], headerTag[:])

	full := buildPayloadFrame(2, now, payloadLen)
	fullTag := hmacFullFrameTag(secret, full)
	copy(full[24:32], fullTag[:])

	fullTampered := make([]byte, len(full))
	copy(fullTampered, full)
	fullTampered[len(fullTampered)-1] ^= 0x01 // payload tampered after tagging

	headerTampered := buildPayloadFrame(4, now, payloadLen)
	headerTamperedTag := hmacTag(secret, 4, now)
	copy(headerTampered[24:32], headerTamperedTag[:])
	headerTampered[len(headerTampered)-1] ^= 0x01 // payload tampered, header tag blind to it

	bareHeader := buildPayloadFrame(5, now, 0)
	bareHeaderTag := hmacTag(secret, 5, now)
	copy(bareHeader[24:32], bareHeaderTag[:])

	bareFull := buildPayloadFrame(6, now, 0)
	bareFullTag := hmacFullFrameTag(secret, bareFull)
	copy(bareFull[24:32], bareFullTag[:])

	cases := []struct {
		name     string
		frame    []byte
		wantEcho bool
	}{
		{"v0.7 client: header tag + payload is accepted", frame, true},
		{"full-frame client: full-frame tag + payload is accepted", full, true},
		{"full-frame tag + tampered payload is dropped", fullTampered, false},
		{"v0.7 behavior pin: header tag + tampered payload is still accepted", headerTampered, true},
		{"bare 32-byte frame, header tag, is accepted", bareHeader, true},
		{"bare 32-byte frame under full-frame coverage is accepted", bareFull, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := getCounterValue(prober.ServerProbesDropped, "hmac")
			conn.Write(tc.frame)
			conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
			n, _ := conn.Read(make([]byte, 1500))
			if tc.wantEcho && n != len(tc.frame) {
				t.Fatalf("frame must be echoed unmodified, got %d of %d bytes", n, len(tc.frame))
			}
			if !tc.wantEcho && n != 0 {
				t.Fatalf("frame must be dropped, got %d bytes back", n)
			}
			// The hmac drop counter must move exactly for the rejected
			// case — no new drop reason exists (one failure cause, two
			// coverages attempted).
			dropped := !tc.wantEcho
			if dropped {
				deadline := time.Now().Add(2 * time.Second)
				for getCounterValue(prober.ServerProbesDropped, "hmac") == before && time.Now().Before(deadline) {
					time.Sleep(10 * time.Millisecond)
				}
			}
			if got := getCounterValue(prober.ServerProbesDropped, "hmac") - before; dropped != (got > 0) {
				t.Errorf("hmac drop counter delta %v but wantEcho=%v (drop reason mis-routed)", got, tc.wantEcho)
			}
		})
	}
}

// TestClient_HMACCoverageWireBytes pins the wire bytes the CLIENT emits
// per coverage, against tag builders reimplemented from the layout:
//
//   - header (the Config zero value, i.e. the library default; the
//     BINARY flag default is full-frame — the -hmac-coverage=header
//     escape hatch yields this emission): the 32-byte frame's tag equals
//     the v0.7 header tag byte-for-byte;
//   - full-frame: the tag equals the full-frame tag over header+payload
//     (tag slot skipped) — and for a zero-payload frame it equals the
//     header tag, so empty-payload frames are identical under both
//     coverages.
//
// The responder captures then echoes unmodified, so the client's reader
// must accept every echo: RTT samples appear and corrupted stays 0 under
// the coverage the client sent with (no fallback is needed — see the
// client reader comment).
func TestClient_HMACCoverageWireBytes(t *testing.T) {
	prober.InitMetrics()

	cases := []struct {
		name     string
		coverage prober.HmacCoverage
		payload  int
	}{
		{"default_header_coverage_payload", prober.HMACHeaderCoverage, 64},
		{"full_frame_coverage_payload", prober.HMACFullFrameCoverage, 64},
		{"full_frame_coverage_no_payload", prober.HMACFullFrameCoverage, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			const secret = "wire-bytes-secret"
			var capMu sync.Mutex
			var captured [][]byte
			addr := udpEcho(t, ctx, func(buf []byte, w func([]byte)) {
				if len(buf) != prober.PayloadSizeWithHMAC+tc.payload || string(buf[0:8]) != prober.MagicBytes {
					return
				}
				capMu.Lock()
				captured = append(captured, append([]byte(nil), buf...))
				capMu.Unlock()
				w(buf) // echo unmodified
			})

			name := tc.name
			cfg := prober.Config{
				Source:       testSource,
				BaseInterval: 30 * time.Millisecond,
				BaseTimeout:  300 * time.Millisecond,
				EchoSecret:   secret,
				Payload:      tc.payload,
				HmacCoverage: tc.coverage,
			}
			cfg.Targets = []prober.Target{{Name: name, Address: addr}}
			runClientAsync(t, ctx, cancel, cfg)
			// pi-lens-ignore: go-time-sleep-test
			time.Sleep(400 * time.Millisecond)

			capMu.Lock()
			defer capMu.Unlock()
			if len(captured) == 0 {
				t.Fatal("no probe frame was captured from the client")
			}
			f := captured[0]
			seq := binary.LittleEndian.Uint64(f[8:16])
			ts := binary.LittleEndian.Uint64(f[16:24])
			switch tc.coverage {
			case prober.HMACHeaderCoverage:
				want := hmacTag(secret, seq, ts)
				if string(f[24:32]) != string(want[:]) {
					t.Error("default coverage must emit the byte-identical v0.7 header tag")
				}
			case prober.HMACFullFrameCoverage:
				want := hmacFullFrameTag(secret, f)
				if string(f[24:32]) != string(want[:]) {
					t.Error("full-frame coverage must emit the full-frame tag over header+payload")
				}
				if tc.payload == 0 {
					if also := hmacTag(secret, seq, ts); string(f[24:32]) != string(also[:]) {
						t.Error("a zero-payload full-frame tag must equal the header tag byte-for-byte")
					}
				}
			}
			if corrupted := getCounterValue(prober.CorruptedProbes, name, addr); corrupted != 0 {
				t.Errorf("an intact echo must not be flagged corrupted, got %v", corrupted)
			}
			if rtt := getHistogramCount(prober.RTTSeconds, name, addr); rtt <= 0 {
				t.Error("the client must accept its own intact echo and sample RTT")
			}
		})
	}
}

// TestClient_HMACFullFrameRejectsTamperedEcho pins the reader-side
// rejection: a responder that flips one payload byte before echoing
// breaks the full-frame tag, so the client must silently drop the echo
// (counted as timeout loss — the frame is treated as foreign exactly like
// today's wrong-tag path), observe no RTT, and NOT count it as payload
// corruption (the frame failed authentication before the pattern check).
func TestClient_HMACFullFrameRejectsTamperedEcho(t *testing.T) {
	prober.InitMetrics()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const secret = "tampered-echo-secret"
	addr := udpEcho(t, ctx, func(buf []byte, w func([]byte)) {
		if len(buf) <= prober.PayloadSizeWithHMAC || string(buf[0:8]) != prober.MagicBytes {
			return
		}
		tampered := append([]byte(nil), buf...)
		tampered[len(tampered)-1] ^= 0xFF
		w(tampered)
	})

	const name = "full_frame_tampered_echo"
	cfg := prober.Config{
		Source:       testSource,
		BaseInterval: 30 * time.Millisecond,
		BaseTimeout:  300 * time.Millisecond,
		EchoSecret:   secret,
		Payload:      64,
		HmacCoverage: prober.HMACFullFrameCoverage,
	}
	cfg.Targets = []prober.Target{{Name: name, Address: addr}}
	runClientAsync(t, ctx, cancel, cfg)
	// pi-lens-ignore: go-time-sleep-test
	time.Sleep(600 * time.Millisecond)

	if rtt := getHistogramCount(prober.RTTSeconds, name, addr); rtt != 0 {
		t.Errorf("a tampered echo must never produce RTT samples, got %v", rtt)
	}
	if corrupted := getCounterValue(prober.CorruptedProbes, name, addr); corrupted != 0 {
		t.Errorf("a frame that fails its full-frame tag check is foreign, not corrupted, got %v", corrupted)
	}
	if tout := getCounterValue(prober.ProbesTimedOut, name, addr); tout <= 0 {
		t.Error("tampered echoes must resolve as loss (timeouts)")
	}
}
