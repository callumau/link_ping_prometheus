package prober

import "encoding/binary"

// buildFrame assembles one wire probe frame: magic, little-endian sequence,
// little-endian unix-ns timestamp, an optional 8-byte tag at offset 24, and
// payloadLen zero-filled payload bytes. headerSize is PayloadSize or
// PayloadSizeWithHMAC; callers pass nil when the frame carries no tag. Tag
// computation and payload filling stay with the caller so each test keeps its
// independent spec instead of validating the contract against itself.
func buildFrame(headerSize int, seq, ts uint64, payloadLen int, tag []byte) []byte {
	f := make([]byte, headerSize+payloadLen)
	copy(f[0:8], MagicBytes)
	binary.LittleEndian.PutUint64(f[8:16], seq)
	binary.LittleEndian.PutUint64(f[16:24], ts)
	if tag != nil {
		copy(f[24:32], tag)
	}
	return f
}
