package protocol

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestPacketRoundtripSmall(t *testing.T) {
	pkt := &Packet{
		Header: BaseHeader{
			Magic:        LcpMagic,
			Version:      1,
			TrafficClass: 4,
			FlowLabel:    100,
			CustomFlags:  0x0F,
			SourceID:     [16]byte{1, 2, 3, 4},
			DestID:       [16]byte{5, 6, 7, 8},
		},
		Payload: []byte("Hello, Lightweight Custom Protocol!"),
	}

	var buf bytes.Buffer
	if err := WritePacket(&buf, pkt); err != nil {
		t.Fatalf("WritePacket failed: %v", err)
	}

	decoded, err := ReadPacket(&buf)
	if err != nil {
		t.Fatalf("ReadPacket failed: %v", err)
	}

	if decoded.Header.FlowLabel != pkt.Header.FlowLabel {
		t.Fatalf("FlowLabel mismatch: %d vs %d", decoded.Header.FlowLabel, pkt.Header.FlowLabel)
	}
	if !bytes.Equal(decoded.Payload, pkt.Payload) {
		t.Fatalf("Payload mismatch: %s vs %s", string(decoded.Payload), string(pkt.Payload))
	}
	if len(decoded.Extensions) != 0 {
		t.Fatalf("Expected 0 extensions, got %d", len(decoded.Extensions))
	}
}

func TestPacketRoundtripWithExtensions(t *testing.T) {
	hash := sha256.Sum256([]byte("chunk content"))

	pkt := &Packet{
		Header: BaseHeader{
			Magic:        LcpMagic,
			Version:      1,
			TrafficClass: 8,
			FlowLabel:    200,
			SourceID:     [16]byte{0xAA},
			DestID:       [16]byte{0xBB},
		},
		Extensions: []Extension{
			&ChunkHeader{
				Flags:       ChunkFlagData | ChunkFlagAck,
				ChunkIndex:  5,
				TotalChunks: 20,
				Offset:      5 * 1024 * 1024,
			},
			&IntegrityHeader{
				Algorithm: 1, // SHA256
				Hash:      hash,
			},
			&MetaHeader{
				Entries: map[string][]byte{
					"filename": []byte("game_patch.zip"),
					"author":   []byte("MobileIon"),
				},
			},
		},
		Payload: []byte("chunk content"),
	}

	var buf bytes.Buffer
	if err := WritePacket(&buf, pkt); err != nil {
		t.Fatalf("WritePacket failed: %v", err)
	}

	decoded, err := ReadPacket(&buf)
	if err != nil {
		t.Fatalf("ReadPacket failed: %v", err)
	}

	if len(decoded.Extensions) != 3 {
		t.Fatalf("Expected 3 extensions, got %d", len(decoded.Extensions))
	}

	chunk, ok := decoded.Extensions[0].(*ChunkHeader)
	if !ok || chunk.ChunkIndex != 5 || chunk.TotalChunks != 20 {
		t.Fatalf("ChunkHeader mismatch: %+v", decoded.Extensions[0])
	}

	integ, ok := decoded.Extensions[1].(*IntegrityHeader)
	if !ok || integ.Hash != hash {
		t.Fatalf("IntegrityHeader mismatch: %+v", decoded.Extensions[1])
	}

	meta, ok := decoded.Extensions[2].(*MetaHeader)
	if !ok || string(meta.Entries["author"]) != "MobileIon" {
		t.Fatalf("MetaHeader mismatch: %+v", decoded.Extensions[2])
	}

	if !bytes.Equal(decoded.Payload, pkt.Payload) {
		t.Fatalf("Payload mismatch")
	}
}

func TestPacketRoundtripJumbogram(t *testing.T) {
	// Generate 1MB payload (larger than 64KB)
	largePayload := make([]byte, 1024*1024)
	for i := range largePayload {
		largePayload[i] = byte(i % 256)
	}

	pkt := &Packet{
		Header: BaseHeader{
			Magic:        LcpMagic,
			Version:      1,
			TrafficClass: 0,
			FlowLabel:    300,
		},
		Extensions: []Extension{
			&ChunkHeader{
				Flags:       ChunkFlagData,
				ChunkIndex:  0,
				TotalChunks: 1,
				Offset:      0,
			},
		},
		Payload: largePayload,
	}

	var buf bytes.Buffer
	if err := WritePacket(&buf, pkt); err != nil {
		t.Fatalf("WritePacket failed: %v", err)
	}

	// Verify that on the wire, the base header PayloadLen is 0 (Jumbogram)
	wireBytes := buf.Bytes()
	if wireBytes[4] != 0 || wireBytes[5] != 0 {
		t.Fatalf("Expected base header PayloadLen == 0 for Jumbogram, got %X %X", wireBytes[4], wireBytes[5])
	}
	if wireBytes[6] != ExtTypeJumbo {
		t.Fatalf("Expected NextHeader == ExtTypeJumbo (0x05), got 0x%X", wireBytes[6])
	}

	decoded, err := ReadPacket(&buf)
	if err != nil {
		t.Fatalf("ReadPacket failed for Jumbogram: %v", err)
	}

	if len(decoded.Payload) != 1024*1024 {
		t.Fatalf("Expected 1MB payload, got %d bytes", len(decoded.Payload))
	}
	if !bytes.Equal(decoded.Payload, largePayload) {
		t.Fatalf("Jumbogram payload data corrupted")
	}
}
