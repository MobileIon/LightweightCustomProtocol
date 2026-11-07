package chunking

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
)

var (
	ErrInvalidChunkIndex = errors.New("lcp: chunk index out of bounds")
)

// Checkpoint represents the persistable state of a resumable transfer.
type Checkpoint struct {
	SessionID   [16]byte `json:"session_id"`
	FileID      string   `json:"file_id"`
	FileSize    int64    `json:"file_size"`
	ChunkSize   int      `json:"chunk_size"`
	TotalChunks uint32   `json:"total_chunks"`
	LastAcked   uint32   `json:"last_acked"`
	Committed   []byte   `json:"committed_bitmask"` // 1 bit per chunk
}

// CheckpointManager provides thread-safe cursor tracking and persistence for resumable transfers.
type CheckpointManager struct {
	mu         sync.RWMutex
	checkpoint Checkpoint
	dirty      bool
}

// NewCheckpointManager initializes a new checkpoint for a file transfer.
func NewCheckpointManager(sessionID [16]byte, fileID string, fileSize int64, chunkSize int) *CheckpointManager {
	totalChunks := uint32((fileSize + int64(chunkSize) - 1) / int64(chunkSize))
	if totalChunks == 0 {
		totalChunks = 1
	}
	bitmaskLen := (totalChunks + 7) / 8

	return &CheckpointManager{
		checkpoint: Checkpoint{
			SessionID:   sessionID,
			FileID:      fileID,
			FileSize:    fileSize,
			ChunkSize:   chunkSize,
			TotalChunks: totalChunks,
			LastAcked:   0,
			Committed:   make([]byte, bitmaskLen),
		},
		dirty: true,
	}
}

// MarkCommitted marks a chunk as received and persisted to storage.
func (cm *CheckpointManager) MarkCommitted(chunkIndex uint32) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if chunkIndex >= cm.checkpoint.TotalChunks {
		return ErrInvalidChunkIndex
	}

	byteIdx := chunkIndex / 8
	bitIdx := chunkIndex % 8
	cm.checkpoint.Committed[byteIdx] |= (1 << bitIdx)
	cm.dirty = true

	// Update contiguous last acked cursor
	for cm.checkpoint.LastAcked < cm.checkpoint.TotalChunks {
		b := cm.checkpoint.LastAcked / 8
		bit := cm.checkpoint.LastAcked % 8
		if (cm.checkpoint.Committed[b] & (1 << bit)) != 0 {
			cm.checkpoint.LastAcked++
		} else {
			break
		}
	}

	return nil
}

// IsCommitted checks if a chunk has already been persisted.
func (cm *CheckpointManager) IsCommitted(chunkIndex uint32) bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	if chunkIndex >= cm.checkpoint.TotalChunks {
		return false
	}
	byteIdx := chunkIndex / 8
	bitIdx := chunkIndex % 8
	return (cm.checkpoint.Committed[byteIdx] & (1 << bitIdx)) != 0
}

// GetContiguousAck returns the contiguous last acked chunk index (e.g. for RESUME_ACK).
func (cm *CheckpointManager) GetContiguousAck() uint32 {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.checkpoint.LastAcked
}

// IsComplete returns true if all chunks have been received and persisted.
func (cm *CheckpointManager) IsComplete() bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.checkpoint.LastAcked >= cm.checkpoint.TotalChunks
}

// SaveToFile serializes the checkpoint to disk.
func (cm *CheckpointManager) SaveToFile(path string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	data, err := json.MarshalIndent(&cm.checkpoint, "", "  ")
	if err != nil {
		return err
	}
	cm.dirty = false
	return os.WriteFile(path, data, 0644)
}

// LoadFromFile restores a checkpoint from disk.
func LoadCheckpointFromFile(path string) (*CheckpointManager, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cp Checkpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		return nil, err
	}

	return &CheckpointManager{
		checkpoint: cp,
		dirty:      false,
	}, nil
}
