package protocol

import (
	"encoding/binary"
	"errors"
	"io"
)

var (
	ErrExtensionChainCorrupted = errors.New("lcp: extension header chain is corrupted or exceeds limit")
	ErrPayloadTooLarge         = errors.New("lcp: payload exceeds supported limit")
)

// Extension is an interface implemented by all LCP extension headers.
type Extension interface {
	Type() byte
	TotalLength() int
	Encode(dst []byte) error
}

func (j *JumboHeader) Type() byte      { return ExtTypeJumbo }
func (j *JumboHeader) TotalLength() int { return JumboHeaderSize }

func (c *ChunkHeader) Type() byte      { return ExtTypeChunk }
func (c *ChunkHeader) TotalLength() int { return ChunkHeaderSize }

func (comp *CompressHeader) Type() byte      { return ExtTypeCompress }
func (comp *CompressHeader) TotalLength() int { return CompressHeaderSize }

func (i *IntegrityHeader) Type() byte      { return ExtTypeIntegrity }
func (i *IntegrityHeader) TotalLength() int { return IntegrityHeaderSize }

// MetaHeader (EXT_META 0x01): Key-Value metadata with 8-byte padding alignment.
type MetaHeader struct {
	NextHeader byte
	Entries    map[string][]byte
}

func (m *MetaHeader) Type() byte { return ExtTypeMeta }

func (m *MetaHeader) TotalLength() int {
	// 2B (NextHdr + ExtLen) + 2B Count
	rawLen := 4
	for k, v := range m.Entries {
		rawLen += 1 + len(k) + 2 + len(v)
	}
	// Round up to multiple of 8
	padded := (rawLen + 7) &^ 7
	return padded
}

func (m *MetaHeader) Encode(dst []byte) error {
	totalLen := m.TotalLength()
	if len(dst) < totalLen {
		return ErrExtensionTooSmall
	}
	// Zero out padding
	for i := 0; i < totalLen; i++ {
		dst[i] = 0
	}

	dst[0] = m.NextHeader
	dst[1] = byte((totalLen / 8) - 1)
	binary.BigEndian.PutUint16(dst[2:4], uint16(len(m.Entries)))

	offset := 4
	for k, v := range m.Entries {
		dst[offset] = byte(len(k))
		offset++
		copy(dst[offset:], k)
		offset += len(k)

		binary.BigEndian.PutUint16(dst[offset:offset+2], uint16(len(v)))
		offset += 2
		copy(dst[offset:], v)
		offset += len(v)
	}

	return nil
}

func DecodeMeta(src []byte, m *MetaHeader) error {
	if len(src) < 4 {
		return ErrExtensionTooSmall
	}
	m.NextHeader = src[0]
	count := int(binary.BigEndian.Uint16(src[2:4]))
	m.Entries = make(map[string][]byte, count)

	offset := 4
	for i := 0; i < count; i++ {
		if offset >= len(src) {
			break
		}
		kLen := int(src[offset])
		offset++
		if offset+kLen > len(src) {
			return ErrExtensionChainCorrupted
		}
		key := string(src[offset : offset+kLen])
		offset += kLen

		if offset+2 > len(src) {
			return ErrExtensionChainCorrupted
		}
		vLen := int(binary.BigEndian.Uint16(src[offset : offset+2]))
		offset += 2
		if offset+vLen > len(src) {
			return ErrExtensionChainCorrupted
		}
		val := make([]byte, vLen)
		copy(val, src[offset:offset+vLen])
		offset += vLen

		m.Entries[key] = val
	}
	return nil
}

// RawExtension represents an unknown or user-defined extension header preserving 8-byte alignment.
type RawExtension struct {
	ExtType    byte
	NextHdr    byte
	Payload    []byte // Payload excluding the first 2 bytes
}

func (r *RawExtension) Type() byte      { return r.ExtType }
func (r *RawExtension) TotalLength() int { return (2 + len(r.Payload) + 7) &^ 7 }

func (r *RawExtension) Encode(dst []byte) error {
	totalLen := r.TotalLength()
	if len(dst) < totalLen {
		return ErrExtensionTooSmall
	}
	dst[0] = r.NextHdr
	dst[1] = byte((totalLen / 8) - 1)
	copy(dst[2:], r.Payload)
	// Clear padding
	for i := 2 + len(r.Payload); i < totalLen; i++ {
		dst[i] = 0
	}
	return nil
}

// Packet represents a complete LCP data unit.
type Packet struct {
	Header     BaseHeader
	Extensions []Extension
	Payload    []byte
}

// ReadPacket reads and decodes an LCP Packet from an io.Reader (e.g. QuicStream).
func ReadPacket(r io.Reader) (*Packet, error) {
	var baseBuf [BaseHeaderSize]byte
	if _, err := io.ReadFull(r, baseBuf[:]); err != nil {
		return nil, err
	}

	var p Packet
	if err := DecodeFast(baseBuf[:], &p.Header); err != nil {
		return nil, err
	}

	// Traverse extension header chain
	nextHdr := p.Header.NextHeader
	var effectivePayloadLen uint32 = uint32(p.Header.PayloadLen)
	var isFirstExt = true

	for nextHdr != NextHeaderPayload {
		// Read first 2 bytes of extension header: [NextHeader (1B), HdrExtLen (1B)]
		var extPreamble [2]byte
		if _, err := io.ReadFull(r, extPreamble[:]); err != nil {
			return nil, err
		}

		currentExtType := nextHdr
		nextHdr = extPreamble[0]
		hdrExtLen := extPreamble[1]
		totalExtLen := (int(hdrExtLen) + 1) * 8

		// Read the remainder of the extension header
		extBuf := make([]byte, totalExtLen)
		extBuf[0] = extPreamble[0]
		extBuf[1] = extPreamble[1]
		if _, err := io.ReadFull(r, extBuf[2:]); err != nil {
			return nil, err
		}

		// Decode strongly-typed extension
		switch currentExtType {
		case ExtTypeJumbo:
			var jumbo JumboHeader
			if err := DecodeJumbo(extBuf, &jumbo); err != nil {
				return nil, err
			}
			p.Extensions = append(p.Extensions, &jumbo)
			// Enforce RFC 2675 constraint: Jumbo must be first extension when PayloadLen == 0
			if isFirstExt && p.Header.PayloadLen == 0 {
				effectivePayloadLen = jumbo.Length
			}
		case ExtTypeChunk:
			var chunk ChunkHeader
			if err := DecodeChunk(extBuf, &chunk); err != nil {
				return nil, err
			}
			p.Extensions = append(p.Extensions, &chunk)
		case ExtTypeCompress:
			var comp CompressHeader
			if err := DecodeCompress(extBuf, &comp); err != nil {
				return nil, err
			}
			p.Extensions = append(p.Extensions, &comp)
		case ExtTypeIntegrity:
			var integ IntegrityHeader
			if err := DecodeIntegrity(extBuf, &integ); err != nil {
				return nil, err
			}
			p.Extensions = append(p.Extensions, &integ)
		case ExtTypeMeta:
			var meta MetaHeader
			if err := DecodeMeta(extBuf, &meta); err != nil {
				return nil, err
			}
			p.Extensions = append(p.Extensions, &meta)
		default:
			// Raw / unknown extension
			raw := RawExtension{
				ExtType: currentExtType,
				NextHdr: nextHdr,
				Payload: extBuf[2:],
			}
			p.Extensions = append(p.Extensions, &raw)
		}

		isFirstExt = false
	}

	// Read effective payload bytes if any
	if effectivePayloadLen > 0 {
		p.Payload = make([]byte, effectivePayloadLen)
		if _, err := io.ReadFull(r, p.Payload); err != nil {
			return nil, err
		}
	}

	return &p, nil
}

// WritePacket serializes and writes an LCP Packet to an io.Writer (e.g. QuicStream).
func WritePacket(w io.Writer, p *Packet) error {
	payloadLen := uint32(len(p.Payload))

	// Link extension headers NextHeader chain
	if len(p.Extensions) > 0 {
		p.Header.NextHeader = p.Extensions[0].Type()
	} else {
		p.Header.NextHeader = NextHeaderPayload
	}

	// Handle Jumbogram check
	if payloadLen > 65535 {
		p.Header.PayloadLen = 0
		// Ensure EXT_JUMBO is mounted as the first extension
		if len(p.Extensions) == 0 || p.Extensions[0].Type() != ExtTypeJumbo {
			jumbo := &JumboHeader{
				NextHeader: p.Header.NextHeader,
				Length:     payloadLen,
			}
			// Prepend jumbo header
			p.Extensions = append([]Extension{jumbo}, p.Extensions...)
			p.Header.NextHeader = ExtTypeJumbo
		} else {
			// Update existing jumbo header length
			if j, ok := p.Extensions[0].(*JumboHeader); ok {
				j.Length = payloadLen
			}
		}
	} else {
		p.Header.PayloadLen = uint16(payloadLen)
	}

	// Update NextHeader links between extensions
	for i := 0; i < len(p.Extensions); i++ {
		var next byte = NextHeaderPayload
		if i+1 < len(p.Extensions) {
			next = p.Extensions[i+1].Type()
		}
		switch ext := p.Extensions[i].(type) {
		case *JumboHeader:
			ext.NextHeader = next
		case *ChunkHeader:
			ext.NextHeader = next
		case *CompressHeader:
			ext.NextHeader = next
		case *IntegrityHeader:
			ext.NextHeader = next
		case *MetaHeader:
			ext.NextHeader = next
		case *RawExtension:
			ext.NextHdr = next
		}
	}

	// Encode and write BaseHeader
	var baseBuf [BaseHeaderSize]byte
	if err := p.Header.EncodeFast(baseBuf[:]); err != nil {
		return err
	}
	if _, err := w.Write(baseBuf[:]); err != nil {
		return err
	}

	// Encode and write all extensions
	for _, ext := range p.Extensions {
		extBuf := make([]byte, ext.TotalLength())
		if err := ext.Encode(extBuf); err != nil {
			return err
		}
		if _, err := w.Write(extBuf); err != nil {
			return err
		}
	}

	// Write payload
	if payloadLen > 0 {
		if _, err := w.Write(p.Payload); err != nil {
			return err
		}
	}

	return nil
}
