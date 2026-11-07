package chunking

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/MobileIon/LightweightCustomProtocol/pkg/protocol"
)

func TestCheckpointManager(t *testing.T) {
	var sessionID [16]byte
	sessionID[0] = 0xAA

	cm := NewCheckpointManager(sessionID, "file123", 1024*1024*5, 1024*1024) // 5 chunks: 0, 1, 2, 3, 4
	if cm.checkpoint.TotalChunks != 5 {
		t.Fatalf("Expected 5 chunks, got %d", cm.checkpoint.TotalChunks)
	}

	// Commit chunk 0
	if err := cm.MarkCommitted(0); err != nil {
		t.Fatalf("MarkCommitted(0) failed: %v", err)
	}
	if cm.GetContiguousAck() != 1 {
		t.Fatalf("Expected ContiguousAck=1, got %d", cm.GetContiguousAck())
	}

	// Commit chunk 2 out of order (0, 2 committed, 1 missing)
	if err := cm.MarkCommitted(2); err != nil {
		t.Fatalf("MarkCommitted(2) failed: %v", err)
	}
	if cm.GetContiguousAck() != 1 {
		t.Fatalf("ContiguousAck should still be 1 (chunk 1 missing), got %d", cm.GetContiguousAck())
	}
	if !cm.IsCommitted(2) {
		t.Fatalf("Chunk 2 should be marked committed")
	}
	if cm.IsCommitted(1) {
		t.Fatalf("Chunk 1 should not be committed yet")
	}

	// Now commit chunk 1 -> contiguous cursor should jump to 3!
	if err := cm.MarkCommitted(1); err != nil {
		t.Fatalf("MarkCommitted(1) failed: %v", err)
	}
	if cm.GetContiguousAck() != 3 {
		t.Fatalf("ContiguousAck should jump to 3, got %d", cm.GetContiguousAck())
	}

	// Save and reload from disk
	tmpJson := filepath.Join(t.TempDir(), "checkpoint.json")
	if err := cm.SaveToFile(tmpJson); err != nil {
		t.Fatalf("SaveToFile failed: %v", err)
	}

	reloaded, err := LoadCheckpointFromFile(tmpJson)
	if err != nil {
		t.Fatalf("LoadCheckpointFromFile failed: %v", err)
	}
	if reloaded.GetContiguousAck() != 3 {
		t.Fatalf("Reloaded ContiguousAck mismatch: %d vs 3", reloaded.GetContiguousAck())
	}
	if !reloaded.IsCommitted(2) {
		t.Fatalf("Reloaded should have chunk 2 committed")
	}
}

func TestChunkPipelineRoundtrip(t *testing.T) {
	tempDir := t.TempDir()
	srcFile := filepath.Join(tempDir, "source.bin")
	dstFile := filepath.Join(tempDir, "output.bin")

	// Create 2.5 MB random test file
	fileSize := int64(2500 * 1024)
	srcData := make([]byte, fileSize)
	if _, err := rand.Read(srcData); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}
	if err := os.WriteFile(srcFile, srcData, 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	chunkSize := 512 * 1024 // 512 KB chunks -> 5 chunks
	reader, err := NewChunkReader(srcFile, chunkSize)
	if err != nil {
		t.Fatalf("NewChunkReader failed: %v", err)
	}
	defer reader.Close()

	var sessionID [16]byte
	sessionID[0] = 0x42

	writer, err := NewChunkWriter(dstFile, sessionID, "test-file", fileSize, chunkSize)
	if err != nil {
		t.Fatalf("NewChunkWriter failed: %v", err)
	}
	defer writer.Close()

	// Read chunks and feed to writer
	for i := uint32(0); i < reader.total; i++ {
		pkt, err := reader.ReadChunkPacket(i)
		if err != nil {
			t.Fatalf("ReadChunkPacket(%d) failed: %v", i, err)
		}

		chunkHdr := pkt.Extensions[0].(*protocol.ChunkHeader)
		integHdr := pkt.Extensions[1].(*protocol.IntegrityHeader)

		if err := writer.WriteChunk(chunkHdr, &integHdr.Hash, pkt.Payload); err != nil {
			t.Fatalf("WriteChunk(%d) failed: %v", i, err)
		}
	}

	if !writer.Checkpoint.IsComplete() {
		t.Fatalf("Writer checkpoint should be complete")
	}

	if err := writer.Finish(); err != nil {
		t.Fatalf("Finish failed: %v", err)
	}

	// Verify restored output matches source byte-for-byte
	restoredData, err := os.ReadFile(dstFile)
	if err != nil {
		t.Fatalf("ReadFile dst failed: %v", err)
	}

	if !bytes.Equal(restoredData, srcData) {
		t.Fatalf("Restored file data does not match source file!")
	}
}
