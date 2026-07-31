namespace FileInspectorX;

/// <summary>
/// Scientific and structured-data container detection.
/// </summary>
internal static partial class Signatures {
    private static readonly byte[] Hdf5Signature = { 0x89, (byte)'H', (byte)'D', (byte)'F', 0x0D, 0x0A, 0x1A, 0x0A };

    internal static bool TryMatchHdf5(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result) {
        result = null;
        for (long offset = 0; offset <= src.Length - Hdf5Signature.Length; offset = NextHdf5Offset(offset)) {
            if (MatchesHdf5Signature(src, (int)offset) &&
                TryValidateHdf5Superblock(src.Slice((int)offset), offset, src.Length)) {
                result = Hdf5Result(offset);
                return true;
            }
            if (offset > int.MaxValue / 2) break;
        }
        return false;
    }

    internal static bool TryMatchHdf5(Stream stream, long minimumOffset, out ContentTypeDetectionResult? result) {
        result = null;
        if (!stream.CanSeek || !stream.CanRead) return false;
        long originalPosition;
        long length;
        try {
            originalPosition = stream.Position;
            length = stream.Length;
        } catch {
            return false;
        }

        var superblock = new byte[128];
        try {
            for (long offset = 0; offset <= length - Hdf5Signature.Length; offset = NextHdf5Offset(offset)) {
                if (offset < minimumOffset) {
                    if (offset > long.MaxValue / 2) break;
                    continue;
                }
                stream.Seek(offset, SeekOrigin.Begin);
                int read = 0;
                int requested = (int)Math.Min(superblock.Length, length - offset);
                while (read < requested) {
                    int current = stream.Read(superblock, read, requested - read);
                    if (current <= 0) break;
                    read += current;
                }
                var candidate = new ReadOnlySpan<byte>(superblock, 0, read);
                if (read >= Hdf5Signature.Length && MatchesHdf5Signature(candidate, 0) &&
                    TryValidateHdf5Superblock(candidate, offset, length)) {
                    result = Hdf5Result(offset);
                    return true;
                }
                if (offset > long.MaxValue / 2) break;
            }
            return false;
        } catch {
            result = null;
            return false;
        } finally {
            try { stream.Seek(originalPosition, SeekOrigin.Begin); } catch { }
        }
    }

    internal static bool TryMatchNetCdf(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result) {
        result = null;
        if (src.Length < 16 || src[0] != (byte)'C' || src[1] != (byte)'D' || src[2] != (byte)'F' ||
            (src[3] != 1 && src[3] != 2 && src[3] != 5))
            return false;

        bool isCdf5 = src[3] == 5;
        if (isCdf5 && src.Length < 24) return false;
        int dimensionTagOffset = isCdf5 ? 12 : 8;
        int dimensionCountOffset = dimensionTagOffset + 4;
        uint dimensionTag = ReadUInt32BigEndian(src, dimensionTagOffset);
        if (dimensionTag == 0) {
            int countBytes = isCdf5 ? 8 : 4;
            for (int i = 0; i < countBytes; i++)
                if (src[dimensionCountOffset + i] != 0) return false;
        } else if (dimensionTag != 10) {
            return false;
        }

        result = new ContentTypeDetectionResult {
            Extension = "nc",
            MimeType = "application/x-netcdf",
            Confidence = "High",
            Reason = src[3] == 1 ? "netcdf:classic" : src[3] == 2 ? "netcdf:64-bit-offset" : "netcdf:64-bit-data"
        };
        return true;
    }

    private static long NextHdf5Offset(long offset) => offset == 0 ? 512 : offset * 2;

    private static bool MatchesHdf5Signature(ReadOnlySpan<byte> src, int offset) {
        for (int i = 0; i < Hdf5Signature.Length; i++)
            if (src[offset + i] != Hdf5Signature[i]) return false;
        return true;
    }

    private static bool TryValidateHdf5Superblock(ReadOnlySpan<byte> src, long signatureOffset, long fileLength) {
        if (src.Length < 12) return false;
        byte version = src[8];
        if (version is 0 or 1) {
            if (src.Length < 24 || src[9] != 0 || src[10] != 0 || src[11] != 0 || src[12] != 0 || src[15] != 0) return false;
            byte offsetSize = src[13];
            byte lengthSize = src[14];
            if (!IsValidHdfIntegerSize(offsetSize) || !IsValidHdfIntegerSize(lengthSize) ||
                ReadUInt16LittleEndian(src, 16) == 0 || ReadUInt16LittleEndian(src, 18) == 0 ||
                (ReadUInt32LittleEndian(src, 20) & ~3u) != 0) return false;
            int cursor = 24;
            if (version == 1) {
                if (src.Length < 28 || ReadUInt16LittleEndian(src, 24) == 0 || src[26] != 0 || src[27] != 0) return false;
                cursor = 28;
            }
            if (!TryReadHdfAddress(src, ref cursor, offsetSize, out ulong baseAddress, out bool baseUndefined) ||
                !TryReadHdfAddress(src, ref cursor, offsetSize, out ulong freeAddress, out bool freeUndefined) ||
                !TryReadHdfAddress(src, ref cursor, offsetSize, out ulong eofAddress, out bool eofUndefined) ||
                !TryReadHdfAddress(src, ref cursor, offsetSize, out ulong driverAddress, out bool driverUndefined)) return false;
            if (baseUndefined || eofUndefined || baseAddress != (ulong)signatureOffset ||
                eofAddress <= (ulong)(signatureOffset + cursor) || eofAddress > (ulong)fileLength ||
                (!freeUndefined && (!TryAddHdfRelativeAddress(baseAddress, freeAddress, out ulong absoluteFree) || absoluteFree >= eofAddress)) ||
                (!driverUndefined && (!TryAddHdfRelativeAddress(baseAddress, driverAddress, out ulong absoluteDriver) || absoluteDriver >= eofAddress))) return false;
            if (!TryReadHdfAddress(src, ref cursor, offsetSize, out _, out bool linkNameUndefined) ||
                !TryReadHdfAddress(src, ref cursor, offsetSize, out ulong objectHeaderAddress, out bool objectHeaderUndefined) ||
                cursor + 24 > src.Length || linkNameUndefined || objectHeaderUndefined ||
                !TryAddHdfRelativeAddress(baseAddress, objectHeaderAddress, out ulong absoluteObjectHeader) ||
                absoluteObjectHeader < (ulong)(signatureOffset + cursor + 24) || absoluteObjectHeader >= eofAddress) return false;
            uint cacheType = ReadUInt32LittleEndian(src, cursor);
            if (cacheType > 1 || ReadUInt32LittleEndian(src, cursor + 4) != 0) return false;
            return true;
        }

        if (version is not (2 or 3)) return false;
        byte modernOffsetSize = src[9];
        byte modernLengthSize = src[10];
        byte allowedFlags = version == 3 ? (byte)0x07 : (byte)0x03;
        if (!IsValidHdfIntegerSize(modernOffsetSize) || !IsValidHdfIntegerSize(modernLengthSize) ||
            (src[11] & ~allowedFlags) != 0) return false;
        int modernCursor = 12;
        if (!TryReadHdfAddress(src, ref modernCursor, modernOffsetSize, out ulong modernBase, out bool modernBaseUndefined) ||
            !TryReadHdfAddress(src, ref modernCursor, modernOffsetSize, out ulong extensionAddress, out bool extensionUndefined) ||
            !TryReadHdfAddress(src, ref modernCursor, modernOffsetSize, out ulong modernEof, out bool modernEofUndefined) ||
            !TryReadHdfAddress(src, ref modernCursor, modernOffsetSize, out ulong rootAddress, out bool rootUndefined) ||
            modernCursor + 4 > src.Length) return false;
        uint expectedChecksum = ReadUInt32LittleEndian(src, modernCursor);
        if (expectedChecksum != ComputeHdf5SuperblockChecksum(src.Slice(0, modernCursor)) ||
            modernBaseUndefined || modernEofUndefined || rootUndefined || modernBase != (ulong)signatureOffset ||
            modernEof <= (ulong)(signatureOffset + modernCursor + 4) || modernEof > (ulong)fileLength ||
            !TryAddHdfRelativeAddress(modernBase, rootAddress, out ulong absoluteRoot) ||
            absoluteRoot < (ulong)(signatureOffset + modernCursor + 4) || absoluteRoot >= modernEof ||
            (!extensionUndefined && (!TryAddHdfRelativeAddress(modernBase, extensionAddress, out ulong absoluteExtension) ||
                                     absoluteExtension < (ulong)(signatureOffset + modernCursor + 4) || absoluteExtension >= modernEof))) return false;
        return true;
    }

    private static bool TryAddHdfRelativeAddress(ulong baseAddress, ulong relativeAddress, out ulong absoluteAddress) {
        if (ulong.MaxValue - baseAddress < relativeAddress) {
            absoluteAddress = 0;
            return false;
        }
        absoluteAddress = baseAddress + relativeAddress;
        return true;
    }

    // HDF5 superblock versions 2 and 3 use Bob Jenkins' lookup3/hashlittle checksum.
    private static uint ComputeHdf5SuperblockChecksum(ReadOnlySpan<byte> src) {
        unchecked {
            uint a = 0xDEADBEEF + (uint)src.Length;
            uint b = a;
            uint c = a;
            int cursor = 0;
            int remaining = src.Length;
            while (remaining > 12) {
                a += ReadUInt32LittleEndian(src, cursor);
                b += ReadUInt32LittleEndian(src, cursor + 4);
                c += ReadUInt32LittleEndian(src, cursor + 8);
                MixHdf5Checksum(ref a, ref b, ref c);
                cursor += 12;
                remaining -= 12;
            }

            switch (remaining) {
                case 12: c += (uint)src[cursor + 11] << 24; goto case 11;
                case 11: c += (uint)src[cursor + 10] << 16; goto case 10;
                case 10: c += (uint)src[cursor + 9] << 8; goto case 9;
                case 9: c += src[cursor + 8]; goto case 8;
                case 8: b += (uint)src[cursor + 7] << 24; goto case 7;
                case 7: b += (uint)src[cursor + 6] << 16; goto case 6;
                case 6: b += (uint)src[cursor + 5] << 8; goto case 5;
                case 5: b += src[cursor + 4]; goto case 4;
                case 4: a += (uint)src[cursor + 3] << 24; goto case 3;
                case 3: a += (uint)src[cursor + 2] << 16; goto case 2;
                case 2: a += (uint)src[cursor + 1] << 8; goto case 1;
                case 1: a += src[cursor]; break;
                case 0: return c;
            }

            FinalizeHdf5Checksum(ref a, ref b, ref c);
            return c;
        }
    }

    private static void MixHdf5Checksum(ref uint a, ref uint b, ref uint c) {
        unchecked {
            a -= c; a ^= RotateLeft(c, 4); c += b;
            b -= a; b ^= RotateLeft(a, 6); a += c;
            c -= b; c ^= RotateLeft(b, 8); b += a;
            a -= c; a ^= RotateLeft(c, 16); c += b;
            b -= a; b ^= RotateLeft(a, 19); a += c;
            c -= b; c ^= RotateLeft(b, 4); b += a;
        }
    }

    private static void FinalizeHdf5Checksum(ref uint a, ref uint b, ref uint c) {
        unchecked {
            c ^= b; c -= RotateLeft(b, 14);
            a ^= c; a -= RotateLeft(c, 11);
            b ^= a; b -= RotateLeft(a, 25);
            c ^= b; c -= RotateLeft(b, 16);
            a ^= c; a -= RotateLeft(c, 4);
            b ^= a; b -= RotateLeft(a, 14);
            c ^= b; c -= RotateLeft(b, 24);
        }
    }

    private static uint RotateLeft(uint value, int count) => (value << count) | (value >> (32 - count));

    private static bool TryReadHdfAddress(ReadOnlySpan<byte> src, ref int cursor, int size, out ulong value, out bool undefined) {
        value = 0;
        undefined = false;
        if (cursor < 0 || cursor + size > src.Length) return false;
        undefined = true;
        int valueBytes = Math.Min(size, 8);
        for (int i = 0; i < size; i++) {
            byte current = src[cursor + i];
            if (current != 0xFF) undefined = false;
            if (i < valueBytes) value |= (ulong)current << (i * 8);
        }
        if (size == 16 && !undefined)
            for (int i = 8; i < 16; i++) if (src[cursor + i] != 0) return false;
        cursor += size;
        return true;
    }

    private static bool IsValidHdfIntegerSize(byte size) => size is 2 or 4 or 8 or 16;

    private static ContentTypeDetectionResult Hdf5Result(long offset) => new() {
        Extension = "h5",
        MimeType = "application/x-hdf5",
        Confidence = "High",
        Reason = "hdf5:signature@" + offset
    };
}
