package prober

import (
	"encoding/binary"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// scriptedReadConn hands out a fixed queue of datagrams, then reports a read
// deadline. It makes readEcho's matching rules testable without a socket or a
// sleeping peer: the whole point is which queued datagrams are accepted and
// which are skipped.
type scriptedReadConn struct {
	frames [][]byte
	calls  atomic.Int64
}

func (c *scriptedReadConn) Read(p []byte) (int, error) {
	i := int(c.calls.Add(1)) - 1
	if i >= len(c.frames) {
		return 0, os.ErrDeadlineExceeded
	}
	return copy(p, c.frames[i]), nil
}

func (c *scriptedReadConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *scriptedReadConn) Close() error                     { return nil }
func (c *scriptedReadConn) LocalAddr() net.Addr              { return nil }
func (c *scriptedReadConn) RemoteAddr() net.Addr             { return nil }
func (c *scriptedReadConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptedReadConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptedReadConn) SetWriteDeadline(time.Time) error { return nil }

// dfFrame builds a well-formed echo frame of the given total size with the
// given seq and ts, appending tag when non-nil (HMAC frames are 8 bytes
// longer; callers pass size accordingly).
func dfFrameFull(seq, ts uint64, size int, tag []byte) []byte {
	b := make([]byte, size)
	copy(b[0:8], MagicBytes)
	binary.LittleEndian.PutUint64(b[8:16], seq)
	binary.LittleEndian.PutUint64(b[16:24], ts)
	if tag != nil {
		copy(b[24:32], tag)
	}
	return b
}

// dfFrame builds a ts-zero echo frame of the given total size.
func dfFrame(seq uint64, size int) []byte {
	return dfFrameFull(seq, 0, size, nil)
}

// TestReadEcho_SkipsForeignAndOtherSizedDatagrams pins the matching rule that
// the DF sweep relies on: one socket serves the whole sweep, and a late echo of
// a LARGER size must not be consumed as this probe's answer (the old
// length-only check scored it as "this smaller size does not survive" and
// stepped the binary search below the real MTU). Only an echo of exactly the
// expected size carrying a sequence this size actually sent counts; everything
// else is skipped, and skipping is bounded by the absolute deadline.
func TestReadEcho_SkipsForeignAndOtherSizedDatagrams(t *testing.T) {
	const wantSize, wantSeq = 124, uint64(7)
	wantTS := uint64(1727000000123456789)
	deadline := time.Now().Add(time.Second)
	// sent is what the sweep recorded for the sequences it actually wrote:
	// readEcho authenticates an echo against it.
	sent := map[uint64]uint64{wantSeq: wantTS, 41: wantTS, 42: wantTS}
	const secret = "" // no-secret sweep: size is header-only, frames carry no tag

	cases := []struct {
		name    string
		frames  [][]byte
		wantErr bool
	}{
		{
			"matching echo is accepted",
			[][]byte{dfFrameFull(wantSeq, wantTS, wantSize, nil)},
			false,
		},
		{
			"a late echo of a LARGER size is skipped, ours is accepted",
			[][]byte{dfFrameFull(99, wantTS, 1024, nil), dfFrameFull(wantSeq, wantTS, wantSize, nil)},
			false,
		},
		{
			"a late echo of a SMALLER size is skipped too",
			[][]byte{dfFrameFull(99, wantTS, 24, nil), dfFrameFull(wantSeq, wantTS, wantSize, nil)},
			false,
		},
		{
			"a foreign sequence is skipped",
			[][]byte{dfFrameFull(98, wantTS, wantSize, nil), dfFrameFull(wantSeq, wantTS, wantSize, nil)},
			false,
		},
		{
			"a foreign magic header is skipped",
			func() [][]byte {
				junk := dfFrameFull(wantSeq, wantTS, wantSize, nil)
				junk[0] ^= 0xFF
				return [][]byte{junk, dfFrameFull(wantSeq, wantTS, wantSize, nil)}
			}(),
			false,
		},
		{
			"an echoed timestamp that does not match what we sent is skipped (spoof/replay)",
			[][]byte{dfFrameFull(wantSeq, wantTS+1, wantSize, nil), dfFrameFull(wantSeq, wantTS, wantSize, nil)},
			false,
		},
		{
			"only mismatched-timestamp datagrams: the probe is lost at the deadline",
			[][]byte{dfFrameFull(wantSeq, wantTS+1, wantSize, nil), dfFrameFull(99, wantTS, wantSize, nil)},
			true,
		},
		{
			"only stale datagrams: the probe is lost at the deadline",
			[][]byte{dfFrameFull(99, wantTS, 1024, nil), dfFrameFull(98, wantTS, wantSize, nil)},
			true,
		},
		{
			"nothing at all: lost",
			nil,
			true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := &scriptedReadConn{frames: tc.frames}
			buf := make([]byte, MaxDatagramSize)
			err := readEcho(conn, buf, wantSize, []uint64{wantSeq}, sent, secret, deadline)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected the probe to be lost, readEcho accepted a datagram that was not ours")
				}
				return
			}
			if err != nil {
				t.Fatalf("readEcho must accept the matching echo after skipping foreign datagrams, got %v", err)
			}
		})
	}

	// Any sequence sent for this size is accepted, so an echo of attempt 1
	// arriving during attempt 2 still proves survival (the retry contract).
	conn := &scriptedReadConn{frames: [][]byte{dfFrameFull(41, wantTS, wantSize, nil)}}
	if err := readEcho(conn, make([]byte, MaxDatagramSize), wantSize, []uint64{41, 42}, sent, secret, deadline); err != nil {
		t.Errorf("an echo of either attempt's sequence must be accepted, got %v", err)
	}
}

// TestReadEcho_VerifiesHMACTag pins the sweep-side echo authentication when
// -echo-secret is set: the echoed tag must match computeHMAC over the
// (sequence, echoed-timestamp) pair the sweep actually sent, compared
// constant-time, and a frame without the tag is skipped by the size gate.
// Mirrors the main reader's acceptance (client.go validHMAC) so an
// off-path injector cannot steer the binary search.
func TestReadEcho_VerifiesHMACTag(t *testing.T) {
	const secret = "audit-secret"
	const wantSeq = uint64(9)
	const wantSize = PayloadSizeWithHMAC // 32: header + tag
	wantTS := uint64(1727000000987654321)
	deadline := time.Now().Add(time.Second)
	goodTag := computeHMAC(secret, wantSeq, wantTS)
	sent := map[uint64]uint64{wantSeq: wantTS}

	cases := []struct {
		name    string
		frames  [][]byte
		wantErr bool
	}{
		{
			"good echo with valid tag is accepted",
			[][]byte{dfFrameFull(wantSeq, wantTS, wantSize, goodTag[:])},
			false,
		},
		{
			"correct seq/ts with a garbage tag is skipped",
			func() [][]byte {
				bad := dfFrameFull(wantSeq, wantTS, wantSize, goodTag[:])
				bad[24] ^= 0xFF
				return [][]byte{bad, dfFrameFull(wantSeq, wantTS, wantSize, goodTag[:])}
			}(),
			false,
		},
		{
			"only wrong-tag frames: the probe is lost at the deadline",
			func() [][]byte {
				bad := dfFrameFull(wantSeq, wantTS, wantSize, goodTag[:])
				bad[31] ^= 0xFF
				return [][]byte{bad}
			}(),
			true,
		},
		{
			"a header-only frame without a tag is skipped by the size gate",
			[][]byte{dfFrameFull(wantSeq, wantTS, PayloadSize, nil)},
			true,
		},
		{
			"a tag forged for a different timestamp is skipped",
			func() [][]byte {
				forged := computeHMAC(secret, wantSeq, wantTS+1)
				return [][]byte{dfFrameFull(wantSeq, wantTS, wantSize, forged[:])}
			}(),
			true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := &scriptedReadConn{frames: tc.frames}
			buf := make([]byte, MaxDatagramSize)
			err := readEcho(conn, buf, wantSize, []uint64{wantSeq}, sent, secret, deadline)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected the probe to be lost, readEcho accepted a frame that was not ours")
				}
				return
			}
			if err != nil {
				t.Fatalf("readEcho must accept the valid echo, got %v", err)
			}
		})
	}

	// Retry contract still holds with a secret: an echo of attempt 1 with
	// ITS OWN timestamp/tag arriving during attempt 2 proves survival.
	s1TS, s2TS := wantTS, wantTS+5
	both := map[uint64]uint64{41: s1TS, 42: s2TS}
	tag1 := computeHMAC(secret, 41, s1TS)
	conn2 := &scriptedReadConn{frames: [][]byte{dfFrameFull(41, s1TS, wantSize, tag1[:])}}
	if err := readEcho(conn2, make([]byte, MaxDatagramSize), wantSize, []uint64{41, 42}, both, secret, deadline); err != nil {
		t.Errorf("an echo of either attempt's (seq, ts) pair must be accepted, got %v", err)
	}
}
