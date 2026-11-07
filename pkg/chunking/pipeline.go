package chunking

import (
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/MobileIon/LightweightCustomProtocol/pkg/protocol"
)

var (
	ErrHashMismatch = errors.New("lcp: chunk sha256 hash mismatch")
)

// ChunkWriter writes incoming LCP chunk packets directly into a destination file.
type ChunkWriter struct {
	mu         sync.Mutex
	destPath   string
	tempPath   string
	file       *os.File
	Checkpoint *CheckpointManager
}

// NewChunkWriter opens a target file (using a .tmp path) and prepares it for chunked writing.
func NewChunkWriter(destPath string, sessionID [16]byte, fileID string, fileSize int64, chunkSize int) (*ChunkWriter, error) {
	tempPath := destPath + ".lcp.tmp"
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return nil, err
	}

	f, err := os.OpenFile(tempPath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return nil, err
	}

	// Truncate to pre-allocate full file size (optimizes disk fragmentation)
	if err := f.Truncate(fileSize); err != nil {
		_ = f.Close()
		return nil, err
	}

	cm := NewCheckpointManager(sessionID, fileID, fileSize, chunkSize)

	return &ChunkWriter{
		destPath:   destPath,
		tempPath:   tempPath,
		file:       f,
		Checkpoint: cm,
	}, nil
}

// WriteChunk writes a verified chunk packet to the appropriate file offset.
func (cw *ChunkWriter) WriteChunk(chunk *protocol.ChunkHeader, expectedHash *[32]byte, data []byte) error {
	cw.mu.Lock()
	defer cw.mu.Unlock()

	// Verify SHA-256 integrity if hash provided
	if expectedHash != nil {
		actualHash := sha256.Sum256(data)
		if actualHash != *expectedHash {
			return ErrHashMismatch
		}
	}

	// Write at exact offset
	if _, err := cw.file.WriteAt(data, int64(chunk.Offset)); err != nil {
		return err
	}

	// Mark chunk as committed in checkpoint
	return cw.Checkpoint.MarkCommitted(chunk.ChunkIndex)
}

// Finish flushes, closes, and atomically renames the temporary file to destPath.
func (cw *ChunkWriter) Finish() error {
	cw.mu.Lock()
	defer cw.mu.Unlock()

	if err := cw.file.Sync(); err != nil {
		return err
	}
	if err := cw.file.Close(); err != nil {
		return err
	}

	return os.Rename(cw.tempPath, cw.destPath)
}

// Close closes the file handle without atomic rename (e.g. on abort or pause).
func (cw *ChunkWriter) Close() error {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	if cw.file != nil {
		_ = cw.file.Sync()
		return cw.file.Close()
	}
	return nil
}

// ChunkReader reads a file in fixed-size chunks and produces LCP packets.
type ChunkReader struct {
	file      *os.File
	fileSize  int64
	chunkSize int
	total     uint32
}

// NewChunkReader opens an existing file for reading into chunks.
func NewChunkReader(path string, chunkSize int) (*ChunkReader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}

	fileSize := fi.Size()
	totalChunks := uint32((fileSize + int64(chunkSize) - 1) / int64(chunkSize))
	if totalChunks == 0 {
		totalChunks = 1
	}

	return &ChunkReader{
		file:      f,
		fileSize:  fileSize,
		chunkSize: chunkSize,
		total:     totalChunks,
	}, nil
}

// ReadChunkPacket reads a single chunk by index and formats it into an LCP Packet.
func (cr *ChunkReader) ReadChunkPacket(chunkIndex uint32) (*protocol.Packet, error) {
	offset := int64(chunkIndex) * int64(cr.chunkSize)
	if offset >= cr.fileSize && cr.fileSize > 0 {
		return nil, io.EOF
	}

	toRead := cr.chunkSize
	if offset+int64(toRead) > cr.fileSize {
		toRead = int(cr.fileSize - offset)
	}

	buf := make([]byte, toRead)
	n, err := cr.file.ReadAt(buf, offset)
	if err != nil && err != io.EOF {
		return nil, err
	}
	buf = buf[:n]

	// Compute chunk hash
	hash := sha256.Sum256(buf)

	var flags uint16 = protocol.ChunkFlagData
	if chunkIndex == cr.total-1 {
		flags |= protocol.ChunkFlagEOF
	}

	chunkHeader := &protocol.ChunkHeader{
		Flags:       flags,
		ChunkIndex:  chunkIndex,
		TotalChunks: cr.total,
		Offset:      uint64(offset),
	}

	integrityHeader := &protocol.IntegrityHeader{
		Algorithm: 1, // SHA256
		Hash:      hash,
	}

	pkt := &protocol.Packet{
		Header: protocol.BaseHeader{
			Magic:        protocol.LcpMagic,
			Version:      protocol.LcpVersion,
			TrafficClass: 0,
			FlowLabel:    1,
		},
		Extensions: []protocol.Extension{
			chunkHeader,
			integrityHeader,
		},
		Payload: buf,
	}

	return pkt, nil
}

// Close closes the underlying reader.
func (cr *ChunkReader) Close() error {
	return cr.file.Close()
}
