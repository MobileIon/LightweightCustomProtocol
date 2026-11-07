package protocol

import (
	"bytes"
	"testing"
)

func TestBaseHeaderSize(t *testing.T) {
	if BaseHeaderSize != 40 {
		t.Fatalf("BaseHeaderSize must strictly be 40 bytes, got %d", BaseHeaderSize)
	}
}

func TestBaseHeaderEncodeDecode(t *testing.T) {
	src := BaseHeader{
		Magic:        LcpMagic,
		Version:      1,
		TrafficClass: 8,
		FlowLabel:    0x1234,
		PayloadLen:   1024,
		NextHeader:   ExtTypeChunk,
		CustomFlags:  0xAB,
		SourceID:     [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		DestID:       [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
	}

	buf := make([]byte, BaseHeaderSize)
	if err := src.EncodeFast(buf); err != nil {
		t.Fatalf("EncodeFast failed: %v", err)
	}

	// Verify big-endian wire bytes
	if buf[0] != LcpMagic {
		t.Fatalf("Magic mismatch: got 0x%X", buf[0])
	}
	if buf[1] != 0x18 { // (1 << 4) | 8
		t.Fatalf("Version/Class mismatch: got 0x%X", buf[1])
	}
	if buf[2] != 0x12 || buf[3] != 0x34 {
		t.Fatalf("FlowLabel Big-Endian mismatch: got 0x%X 0x%X", buf[2], buf[3])
	}
	if buf[4] != 0x04 || buf[5] != 0x00 { // 1024 = 0x0400
		t.Fatalf("PayloadLen Big-Endian mismatch: got 0x%X 0x%X", buf[4], buf[5])
	}
	if buf[6] != ExtTypeChunk {
		t.Fatalf("NextHeader mismatch: got 0x%X", buf[6])
	}
	if buf[7] != 0xAB {
		t.Fatalf("CustomFlags mismatch: got 0x%X", buf[7])
	}

	var dst BaseHeader
	if err := DecodeFast(buf, &dst); err != nil {
		t.Fatalf("DecodeFast failed: %v", err)
	}

	if src != dst {
		t.Fatalf("Decoded header does not match original: %+v vs %+v", dst, src)
	}
}

func TestJumboHeader(t *testing.T) {
	j := JumboHeader{
		NextHeader: NextHeaderPayload,
		Length:     1024 * 1024, // 1MB
	}

	buf := make([]byte, JumboHeaderSize)
	if err := j.Encode(buf); err != nil {
		t.Fatalf("JumboHeader.Encode failed: %v", err)
	}

	if len(buf)%8 != 0 {
		t.Fatalf("JumboHeader must be multiple of 8 bytes, got %d", len(buf))
	}

	var decoded JumboHeader
	if err := DecodeJumbo(buf, &decoded); err != nil {
		t.Fatalf("DecodeJumbo failed: %v", err)
	}

	if decoded != j {
		t.Fatalf("Decoded JumboHeader mismatch: %+v vs %+v", decoded, j)
	}
}

func TestChunkHeader(t *testing.T) {
	c := ChunkHeader{
		NextHeader:  NextHeaderPayload,
		Flags:       ChunkFlagData | ChunkFlagEOF,
		ChunkIndex:  42,
		TotalChunks: 100,
		Offset:      42 * 1024 * 1024,
	}

	buf := make([]byte, ChunkHeaderSize)
	if err := c.Encode(buf); err != nil {
		t.Fatalf("ChunkHeader.Encode failed: %v", err)
	}

	if len(buf)%8 != 0 {
		t.Fatalf("ChunkHeader must be multiple of 8 bytes, got %d", len(buf))
	}

	var decoded ChunkHeader
	if err := DecodeChunk(buf, &decoded); err != nil {
		t.Fatalf("DecodeChunk failed: %v", err)
	}

	if decoded != c {
		t.Fatalf("Decoded ChunkHeader mismatch: %+v vs %+v", decoded, c)
	}
}

func TestIntegrityHeader(t *testing.T) {
	i := IntegrityHeader{
		NextHeader: NextHeaderPayload,
		Algorithm:  1, // SHA256
		Hash:       [32]byte{0xDE, 0xAD, 0xBE, 0xEF},
	}

	buf := make([]byte, IntegrityHeaderSize)
	if err := i.Encode(buf); err != nil {
		t.Fatalf("IntegrityHeader.Encode failed: %v", err)
	}

	if len(buf)%8 != 0 {
		t.Fatalf("IntegrityHeader must be multiple of 8 bytes, got %d", len(buf))
	}

	var decoded IntegrityHeader
	if err := DecodeIntegrity(buf, &decoded); err != nil {
		t.Fatalf("DecodeIntegrity failed: %v", err)
	}

	if decoded.NextHeader != i.NextHeader || decoded.Algorithm != i.Algorithm || !bytes.Equal(decoded.Hash[:], i.Hash[:]) {
		t.Fatalf("Decoded IntegrityHeader mismatch: %+v vs %+v", decoded, i)
	}
}
