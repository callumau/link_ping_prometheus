package prober

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

// TestEchoDupGuardRingEviction: the guard must track a bounded FIFO
// window of dupRingSize identities — entry 0 is evicted exactly when
// entry dupRingSize is recorded, while newer entries stay remembered.
// This pins the eviction ORDER (not just the map size), which the
// integration suite cannot do without sending >8192 rate-limited frames.
func TestEchoDupGuardRingEviction(t *testing.T) {
	g := newEchoDupGuard()
	for i := range dupRingSize {
		g.record(uint64(i))
	}
	for i := range dupRingSize {
		if _, ok := g.seen[uint64(i)]; !ok {
			t.Fatalf("key %d must be remembered before the ring wraps", i)
		}
	}
	if g.count != dupRingSize {
		t.Fatalf("guard must hold exactly %d entries, holds %d", dupRingSize, g.count)
	}

	// Recording one more key evicts the OLDEST (ring position of key 0)
	// and only that one.
	g.record(dupRingSize)
	if _, ok := g.seen[uint64(0)]; ok {
		t.Error("key 0 must be FIFO-evicted when the ring wraps")
	}
	if _, ok := g.seen[dupRingSize]; !ok {
		t.Error("the newly recorded key must be remembered")
	}
	for i := 1; i < dupRingSize; i++ {
		if _, ok := g.seen[uint64(i)]; !ok {
			t.Errorf("key %d must survive the wrap", i)
		}
	}
	if g.count != dupRingSize {
		t.Errorf("guard must stay at %d entries after wrap, holds %d", dupRingSize, g.count)
	}

	// Steady state: every record evicts exactly one old key.
	for i := range 100 {
		g.record(uint64(dupRingSize + 1 + i))
	}
	if g.count != dupRingSize {
		t.Errorf("guard must stay bounded at %d entries, holds %d", dupRingSize, g.count)
	}
	if _, ok := g.seen[uint64(100)]; ok {
		t.Error("key 100 (evicted late in the sweep) must be gone")
	}
	if _, ok := g.seen[uint64(dupRingSize+100)]; !ok {
		t.Error("the most recently recorded key must be remembered")
	}
}

// TestEchoFrameKey: the identity must be a pure function of (source IP,
// source port, seq, ts) and must distinguish every dimension the dup
// guard relies on — a different source address, port, seq or timestamp
// is a different probe, and only the exact repeat is a bounce.
func TestEchoFrameKey(t *testing.T) {
	ip := netip.MustParseAddr("10.0.0.1")
	frame := func(seq, ts uint64) []byte {
		f := make([]byte, PayloadSize)
		copy(f[0:8], MagicBytes)
		binary.LittleEndian.PutUint64(f[8:16], seq)
		binary.LittleEndian.PutUint64(f[16:24], ts)
		return f
	}
	base := frame(7, uint64(time.Now().UnixNano()))
	want := echoFrameKey(ip, 5000, base)

	if got := echoFrameKey(ip, 5000, base); got != want {
		t.Error("identity must be deterministic for identical inputs")
	}
	if got := echoFrameKey(netip.MustParseAddr("10.0.0.2"), 5000, base); got == want {
		t.Error("a different source IP must change the identity")
	}
	if got := echoFrameKey(ip, 5001, base); got == want {
		t.Error("a different source port must change the identity")
	}
	if got := echoFrameKey(ip, 5000, frame(8, binary.LittleEndian.Uint64(base[16:24]))); got == want {
		t.Error("a different seq must change the identity")
	}
	if got := echoFrameKey(ip, 5000, frame(7, binary.LittleEndian.Uint64(base[16:24])+1)); got == want {
		t.Error("a different timestamp must change the identity")
	}
}
