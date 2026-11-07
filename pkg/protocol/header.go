package protocol

import (
	"encoding/binary"
	"errors"
)

const (
	// BaseHeaderSize is strictly 40 bytes (320 bits, 5x 64-bit QWORDs)
	BaseHeaderSize = 40

	// LcpMagic is ASCII 'L' (0x4C)
	LcpMagic = 0x4C

	// LcpVersion is 1
	LcpVersion = 0x01

	// NextHeader terminator
	NextHeaderPayload = 0xFF

	// NextHeaderJumbo is RFC 2675 style Jumbogram extension
	NextHeaderJumbo = 0x05
)

var (
	ErrBufferTooSmall = errors.New("lcp: buffer too small for base header")
	ErrInvalidMagic   = errors.New("lcp: invalid protocol magic byte")
	ErrInvalidVersion = errors.New("lcp: unsupported protocol version")
)

// BaseHeader strictly 40-byte fixed header aligned to 8-byte boundaries.
type BaseHeader struct {
	Magic        byte     // 0x00: 0x4C ('L')
	Version      byte     // 0x01 [7:4]: 4-bit version (0x1)
	TrafficClass byte     // 0x01 [3:0]: 4-bit QoS traffic class
	FlowLabel    uint16   // 0x02..0x03: 16-bit task/flow label
	PayloadLen   uint16   // 0x04..0x05: 16-bit payload length (0 = Jumbogram in EXT_JUMBO)
	NextHeader   byte     // 0x06: First extension header or 0xFF (Payload)
	CustomFlags  byte     // 0x07: 8-bit user customizable flags
	SourceID     [16]byte // 0x08..0x17: 128-bit source UUID / Node identifier
	DestID       [16]byte // 0x18..0x27: 128-bit destination UUID / Service identifier
}

// EncodeFast serializes the BaseHeader into dst using Big-Endian without heap allocation.
func (h *BaseHeader) EncodeFast(dst []byte) error {
	if len(dst) < BaseHeaderSize {
		return ErrBufferTooSmall
	}

	dst[0] = h.Magic
	dst[1] = (h.Version << 4) | (h.TrafficClass & 0x0F)
	binary.BigEndian.PutUint16(dst[2:4], h.FlowLabel)
	binary.BigEndian.PutUint16(dst[4:6], h.PayloadLen)
	dst[6] = h.NextHeader
	dst[7] = h.CustomFlags
	copy(dst[8:24], h.SourceID[:])
	copy(dst[24:40], h.DestID[:])

	return nil
}

// DecodeFast deserializes the BaseHeader from src using Big-Endian without heap allocation.
func DecodeFast(src []byte, h *BaseHeader) error {
	if len(src) < BaseHeaderSize {
		return ErrBufferTooSmall
	}
	if src[0] != LcpMagic {
		return ErrInvalidMagic
	}

	h.Magic = src[0]
	h.Version = (src[1] >> 4) & 0x0F
	h.TrafficClass = src[1] & 0x0F
	h.FlowLabel = binary.BigEndian.Uint16(src[2:4])
	h.PayloadLen = binary.BigEndian.Uint16(src[4:6])
	h.NextHeader = src[6]
	h.CustomFlags = src[7]
	copy(h.SourceID[:], src[8:24])
	copy(h.DestID[:], src[24:40])

	return nil
}

// IsJumbogram returns true if the base header indicates an RFC 2675 style Jumbogram (PayloadLen == 0 && NextHeader == 0x05).
func (h *BaseHeader) IsJumbogram() bool {
	return h.PayloadLen == 0 && h.NextHeader == NextHeaderJumbo
}
