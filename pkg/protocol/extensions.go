package protocol

import (
	"encoding/binary"
	"errors"
)

// Standard Extension Header Types
const (
	ExtTypeMeta      byte = 0x01 // General key-value metadata
	ExtTypeChunk     byte = 0x02 // Chunking and checkpointing
	ExtTypeCompress  byte = 0x03 // Compression information
	ExtTypeIntegrity byte = 0x04 // Integrity signature / hash
	ExtTypeJumbo     byte = 0x05 // RFC 2675 Jumbo payload length
)

// Chunk Flags
const (
	ChunkFlagData   uint16 = 0x0001 // Chunk payload data
	ChunkFlagAck    uint16 = 0x0002 // Checkpoint /落盘确认
	ChunkFlagNack   uint16 = 0x0004 // Retransmission request
	ChunkFlagResume uint16 = 0x0008 // Resume checkpoint probe
	ChunkFlagEOF    uint16 = 0x0010 // End of file/stream
)

var (
	ErrExtensionTooSmall = errors.New("lcp: extension header buffer too small")
	ErrUnalignedExtension= errors.New("lcp: extension header length must be a multiple of 8 bytes")
)

// JumboHeader (EXT_JUMBO 0x05): strictly 8 bytes (NextHeader(1B) + HdrExtLen(1B, 0) + Reserved(2B) + Length(4B))
type JumboHeader struct {
	NextHeader byte
	Length     uint32
}

const JumboHeaderSize = 8

func (j *JumboHeader) Encode(dst []byte) error {
	if len(dst) < JumboHeaderSize {
		return ErrExtensionTooSmall
	}
	dst[0] = j.NextHeader
	dst[1] = 0 // (8 / 8) - 1 = 0
	binary.BigEndian.PutUint16(dst[2:4], 0)
	binary.BigEndian.PutUint32(dst[4:8], j.Length)
	return nil
}

func DecodeJumbo(src []byte, j *JumboHeader) error {
	if len(src) < JumboHeaderSize {
		return ErrExtensionTooSmall
	}
	j.NextHeader = src[0]
	j.Length = binary.BigEndian.Uint32(src[4:8])
	return nil
}

// ChunkHeader (EXT_CHUNK 0x02): strictly 24 bytes (NextHdr(1B) + ExtLen(1B, 2) + Flags(2B) + ChunkIdx(4B) + TotalChunks(4B) + Reserved(4B) + Offset(8B))
type ChunkHeader struct {
	NextHeader  byte
	Flags       uint16
	ChunkIndex  uint32
	TotalChunks uint32
	Offset      uint64
}

const ChunkHeaderSize = 24

func (c *ChunkHeader) Encode(dst []byte) error {
	if len(dst) < ChunkHeaderSize {
		return ErrExtensionTooSmall
	}
	dst[0] = c.NextHeader
	dst[1] = 2 // (24 / 8) - 1 = 2
	binary.BigEndian.PutUint16(dst[2:4], c.Flags)
	binary.BigEndian.PutUint32(dst[4:8], c.ChunkIndex)
	binary.BigEndian.PutUint32(dst[8:12], c.TotalChunks)
	binary.BigEndian.PutUint32(dst[12:16], 0) // Reserved
	binary.BigEndian.PutUint64(dst[16:24], c.Offset)
	return nil
}

func DecodeChunk(src []byte, c *ChunkHeader) error {
	if len(src) < ChunkHeaderSize {
		return ErrExtensionTooSmall
	}
	c.NextHeader = src[0]
	c.Flags = binary.BigEndian.Uint16(src[2:4])
	c.ChunkIndex = binary.BigEndian.Uint32(src[4:8])
	c.TotalChunks = binary.BigEndian.Uint32(src[8:12])
	c.Offset = binary.BigEndian.Uint64(src[16:24])
	return nil
}

// CompressHeader (EXT_COMPRESS 0x03): strictly 8 bytes (NextHdr(1B) + ExtLen(1B, 0) + Algorithm(1B) + Reserved(1B) + UncompressedSize(4B))
type CompressHeader struct {
	NextHeader       byte
	Algorithm        byte // 1: LZ4, 2: ZSTD
	UncompressedSize uint32
}

const CompressHeaderSize = 8

func (comp *CompressHeader) Encode(dst []byte) error {
	if len(dst) < CompressHeaderSize {
		return ErrExtensionTooSmall
	}
	dst[0] = comp.NextHeader
	dst[1] = 0 // (8 / 8) - 1 = 0
	dst[2] = comp.Algorithm
	dst[3] = 0 // Reserved
	binary.BigEndian.PutUint32(dst[4:8], comp.UncompressedSize)
	return nil
}

func DecodeCompress(src []byte, comp *CompressHeader) error {
	if len(src) < CompressHeaderSize {
		return ErrExtensionTooSmall
	}
	comp.NextHeader = src[0]
	comp.Algorithm = src[2]
	comp.UncompressedSize = binary.BigEndian.Uint32(src[4:8])
	return nil
}

// IntegrityHeader (EXT_INTEGRITY 0x04): strictly 40 bytes (NextHdr(1B) + ExtLen(1B, 4) + Algorithm(1B) + Reserved(5B) + HashBytes(32B))
type IntegrityHeader struct {
	NextHeader byte
	Algorithm  byte // 1: SHA256, 2: BLAKE3
	Hash       [32]byte
}

const IntegrityHeaderSize = 40

func (i *IntegrityHeader) Encode(dst []byte) error {
	if len(dst) < IntegrityHeaderSize {
		return ErrExtensionTooSmall
	}
	dst[0] = i.NextHeader
	dst[1] = 4 // (40 / 8) - 1 = 4
	dst[2] = i.Algorithm
	// 5 bytes Reserved
	dst[3] = 0
	dst[4] = 0
	dst[5] = 0
	dst[6] = 0
	dst[7] = 0
	copy(dst[8:40], i.Hash[:])
	return nil
}

func DecodeIntegrity(src []byte, i *IntegrityHeader) error {
	if len(src) < IntegrityHeaderSize {
		return ErrExtensionTooSmall
	}
	i.NextHeader = src[0]
	i.Algorithm = src[2]
	copy(i.Hash[:], src[8:40])
	return nil
}
