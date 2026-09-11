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

// dfFrame builds a well-formed probe/echo frame of the given total size.
func dfFrame(seq uint64, size int) []byte {
	b := make([]byte, size)
	copy(b[0:8], MagicBytes)
	binary.LittleEndian.PutUint64(b[8:16], seq)
	return b
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
	deadline := time.Now().Add(time.Second)

	cases := []struct {
		name    string
		frames  [][]byte
		wantErr bool
	}{
		{
			"matching echo is accepted",
			[][]byte{dfFrame(wantSeq, wantSize)},
			false,
		},
		{
			"a late echo of a LARGER size is skipped, ours is accepted",
			[][]byte{dfFrame(99, 1024), dfFrame(wantSeq, wantSize)},
			false,
		},
		{
			"a late echo of a SMALLER size is skipped too",
			[][]byte{dfFrame(99, 24), dfFrame(wantSeq, wantSize)},
			false,
		},
		{
			"a foreign sequence is skipped",
			[][]byte{dfFrame(98, wantSize), dfFrame(wantSeq, wantSize)},
			false,
		},
		{
			"a foreign magic header is skipped",
			func() [][]byte {
				junk := dfFrame(wantSeq, wantSize)
				junk[0] ^= 0xFF
				return [][]byte{junk, dfFrame(wantSeq, wantSize)}
			}(),
			false,
		},
		{
			"only stale datagrams: the probe is lost at the deadline",
			[][]byte{dfFrame(99, 1024), dfFrame(98, wantSize)},
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
			err := readEcho(conn, buf, wantSize, []uint64{wantSeq}, deadline)
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
	conn := &scriptedReadConn{frames: [][]byte{dfFrame(41, wantSize)}}
	if err := readEcho(conn, make([]byte, MaxDatagramSize), wantSize, []uint64{41, 42}, deadline); err != nil {
		t.Errorf("an echo of either attempt's sequence must be accepted, got %v", err)
	}
}
