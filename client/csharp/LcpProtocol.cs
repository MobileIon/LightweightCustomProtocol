using System;
using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace LightweightCustomProtocol.Client
{
    public static class LcpConstants
    {
        public const byte Magic = 0x4C; // 'L'
        public const byte Version = 0x01;
        public const byte NextHeaderPayload = 0xFF;
        public const byte NextHeaderJumbo = 0x05;
        public const byte NextHeaderChunk = 0x02;
        public const byte NextHeaderCompress = 0x03;
        public const byte NextHeaderIntegrity = 0x04;
        public const byte NextHeaderMeta = 0x01;

        public const ushort ChunkFlagData = 0x0001;
        public const ushort ChunkFlagAck = 0x0002;
        public const ushort ChunkFlagNack = 0x0004;
        public const ushort ChunkFlagResume = 0x0008;
        public const ushort ChunkFlagEOF = 0x0010;

        public const int BaseHeaderSize = 40;
        public const int JumboHeaderSize = 8;
        public const int ChunkHeaderSize = 24;
        public const int CompressHeaderSize = 8;
        public const int IntegrityHeaderSize = 40;

        public const int DefaultPortStrict = 856;
        public const int DefaultPortDisaster = 855;
        public const string AlpnProtocol = "lcp-v1";
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1, Size = 40)]
    public unsafe struct LcpBaseHeaderRaw
    {
        public byte Magic;
        public byte VersionAndClass;
        public ushort FlowLabel;      // Big-Endian on wire
        public ushort PayloadLength;  // Big-Endian on wire (0 = Jumbogram)
        public byte NextHeader;
        public byte CustomFlags;
        
        // Fixed 16-byte arrays to prevent .NET System.Guid mixed-endian corruption
        public fixed byte SourceId[16];
        public fixed byte DestId[16];
    }

    public static class LcpCodec
    {
        public static uint ReadEffectivePayloadLength(ReadOnlySpan<byte> buffer)
        {
            if (buffer.Length < 40) return 0;
            ushort baseLen = BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(4, 2));
            if (baseLen > 0) return baseLen;

            // If baseLen == 0 and NextHeader is EXT_JUMBO (0x05), read 32-bit length
            byte nextHdr = buffer[6];
            if (nextHdr == LcpConstants.NextHeaderJumbo && buffer.Length >= 48)
            {
                return BinaryPrimitives.ReadUInt32BigEndian(buffer.Slice(44, 4));
            }
            return 0;
        }

        public static Guid ReadSourceGuid(ReadOnlySpan<byte> buffer)
        {
            // .NET 8 big-endian Guid construction strictly matching Go [16]byte
            return new Guid(buffer.Slice(8, 16), bigEndian: true);
        }

        public static void WriteSourceGuid(Span<byte> buffer, Guid guid)
        {
            guid.TryWriteBytes(buffer.Slice(8, 16), bigEndian: true, out _);
        }

        public static Guid ReadDestGuid(ReadOnlySpan<byte> buffer)
        {
            return new Guid(buffer.Slice(24, 16), bigEndian: true);
        }

        public static void WriteDestGuid(Span<byte> buffer, Guid guid)
        {
            guid.TryWriteBytes(buffer.Slice(24, 16), bigEndian: true, out _);
        }
    }
}
