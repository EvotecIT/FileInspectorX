namespace FileInspectorX;

/// <summary>
/// OpenType and Web Open Font Format detection.
/// </summary>
internal static partial class Signatures {
    internal static bool TryMatchFont(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
        => TryMatchFont(src, src.Length, out result);

    internal static bool TryMatchFont(Stream stream, out ContentTypeDetectionResult? result) {
        result = null;
        if (!stream.CanRead || !stream.CanSeek) return false;
        long originalPosition = stream.Position;
        try {
            if (stream.Length < 4 || !TryReadAt(stream, 0, (int)Math.Min(64, stream.Length), out var prefix)) return false;
            var src = new ReadOnlySpan<byte>(prefix);
            if (src.Length >= 4 && src.Slice(0, 4).SequenceEqual("wOF2"u8))
                return TryMatchWoff2(stream, src, out result);
            if (!src.Slice(0, 4).SequenceEqual("ttcf"u8))
                return TryMatchFont(src, stream.Length, out result);

            if (src.Length < 12) return false;
            uint version = ReadUInt32BigEndian(src, 4);
            uint fontCount = ReadUInt32BigEndian(src, 8);
            long collectionHeaderLength = 12L + fontCount * 4L;
            if (version is not (0x00010000u or 0x00020000u) || fontCount is < 1 or > 4095 ||
                collectionHeaderLength > stream.Length || !TryReadAt(stream, 0, (int)collectionHeaderLength, out var collectionHeader)) return false;

            var header = new ReadOnlySpan<byte>(collectionHeader);
            bool anyCff = false;
            for (uint i = 0; i < fontCount; i++) {
                uint directoryOffset = ReadUInt32BigEndian(header, checked(12 + (int)i * 4));
                if (directoryOffset + 28L > stream.Length || !TryReadAt(stream, directoryOffset, 28, out var directoryBytes)) return false;
                var directory = new ReadOnlySpan<byte>(directoryBytes);
                if (!TryValidateCollectionFontDirectory(directory, directoryOffset, stream.Length, out bool isCff)) return false;
                anyCff |= isCff;
            }

            result = FontCollectionResult(version, fontCount, anyCff);
            return true;
        } catch {
            result = null;
            return false;
        } finally {
            try { stream.Seek(originalPosition, SeekOrigin.Begin); } catch { }
        }
    }

    private static bool TryMatchWoff2(Stream stream, ReadOnlySpan<byte> header, out ContentTypeDetectionResult? result) {
        result = null;
        if (header.Length < 48 || stream.Length > uint.MaxValue) return false;
        uint declaredLength = ReadUInt32BigEndian(header, 8);
        ushort tableCount = ReadUInt16BigEndian(header, 12);
        if (declaredLength != stream.Length || tableCount is < 1 or > 4095) return false;

        long cursor = 48;
        stream.Seek(cursor, SeekOrigin.Begin);
        Span<byte> tag = stackalloc byte[4];
        for (int table = 0; table < tableCount; table++) {
            if (!TryReadWoff2Byte(stream, declaredLength, ref cursor, out byte flags)) return false;
            int tagIndex = flags & 0x3F;
            int transformVersion = flags >> 6;
            bool isGlyfOrLoca = tagIndex is 10 or 11;
            if (tagIndex == 0x3F) {
                for (int i = 0; i < tag.Length; i++) {
                    if (!TryReadWoff2Byte(stream, declaredLength, ref cursor, out tag[i]) || tag[i] < 0x20 || tag[i] > 0x7E)
                        return false;
                }
                isGlyfOrLoca = tag.SequenceEqual("glyf"u8) || tag.SequenceEqual("loca"u8);
            }
            if (!TryReadWoff2UIntBase128(stream, declaredLength, ref cursor, out uint originalLength) || originalLength == 0)
                return false;
            bool transformed = isGlyfOrLoca ? transformVersion != 3 : transformVersion != 0;
            if (transformed && !TryReadWoff2UIntBase128(stream, declaredLength, ref cursor, out _)) return false;
        }

        if (ReadUInt32BigEndian(header, 4) == 0x74746366 &&
            !TryReadWoff2CollectionDirectory(stream, declaredLength, ref cursor, tableCount)) return false;
        if (cursor > int.MaxValue || !TryReadAt(stream, 0, (int)cursor, out var directory)) return false;
        return TryMatchFont(new ReadOnlySpan<byte>(directory), stream.Length, out result);
    }

    private static bool TryReadWoff2CollectionDirectory(Stream stream, uint declaredLength, ref long cursor, ushort tableCount) {
        if (!TryReadWoff2UInt32(stream, declaredLength, ref cursor, out uint version) ||
            version is not (0x00010000u or 0x00020000u) ||
            !TryReadWoff2255UInt16(stream, declaredLength, ref cursor, out ushort fontCount) || fontCount == 0) return false;

        for (int font = 0; font < fontCount; font++) {
            if (!TryReadWoff2255UInt16(stream, declaredLength, ref cursor, out ushort fontTableCount) ||
                fontTableCount == 0 || fontTableCount > tableCount ||
                !TryReadWoff2UInt32(stream, declaredLength, ref cursor, out uint flavor) ||
                !TryGetSfntFlavor(flavor, out _, out _)) return false;
            for (int table = 0; table < fontTableCount; table++)
                if (!TryReadWoff2255UInt16(stream, declaredLength, ref cursor, out ushort index) || index >= tableCount) return false;
        }
        return true;
    }

    private static bool TryReadWoff2Byte(Stream stream, uint declaredLength, ref long cursor, out byte value) {
        value = 0;
        if (cursor >= declaredLength) return false;
        int current = stream.ReadByte();
        if (current < 0) return false;
        cursor++;
        value = (byte)current;
        return true;
    }

    private static bool TryReadWoff2UInt32(Stream stream, uint declaredLength, ref long cursor, out uint value) {
        value = 0;
        for (int i = 0; i < 4; i++) {
            if (!TryReadWoff2Byte(stream, declaredLength, ref cursor, out byte current)) return false;
            value = (value << 8) | current;
        }
        return true;
    }

    private static bool TryReadWoff2UIntBase128(Stream stream, uint declaredLength, ref long cursor, out uint value) {
        value = 0;
        for (int i = 0; i < 5; i++) {
            if (!TryReadWoff2Byte(stream, declaredLength, ref cursor, out byte current) ||
                (i == 0 && current == 0x80) || (value & 0xFE000000u) != 0) return false;
            value = (value << 7) | (uint)(current & 0x7F);
            if ((current & 0x80) == 0) return true;
        }
        return false;
    }

    private static bool TryReadWoff2255UInt16(Stream stream, uint declaredLength, ref long cursor, out ushort value) {
        value = 0;
        if (!TryReadWoff2Byte(stream, declaredLength, ref cursor, out byte code)) return false;
        if (code == 253) {
            if (!TryReadWoff2Byte(stream, declaredLength, ref cursor, out byte high) ||
                !TryReadWoff2Byte(stream, declaredLength, ref cursor, out byte low)) return false;
            value = (ushort)(high << 8 | low);
            return true;
        }
        if (code is 254 or 255) {
            if (!TryReadWoff2Byte(stream, declaredLength, ref cursor, out byte tail)) return false;
            value = (ushort)(tail + (code == 255 ? 253 : 506));
            return true;
        }
        value = code;
        return true;
    }

    internal static bool TryMatchFont(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result) {
        result = null;
        if (src.Length < 4) return false;

        if (src[0] == (byte)'w' && src[1] == (byte)'O' && src[2] == (byte)'F' && src[3] == (byte)'F')
            return TryMatchWoff(src, completeLength, isWoff2: false, out result);
        if (src[0] == (byte)'w' && src[1] == (byte)'O' && src[2] == (byte)'F' && src[3] == (byte)'2')
            return TryMatchWoff(src, completeLength, isWoff2: true, out result);
        if (src.Slice(0, 4).SequenceEqual("ttcf"u8))
            return TryMatchFontCollection(src, completeLength, out result);

        if (src.Length < 28) return false;
        uint flavor = ReadUInt32BigEndian(src, 0);
        if (!TryGetSfntFlavor(flavor, out var extension, out var mime)) return false;

        ushort tableCount = ReadUInt16BigEndian(src, 4);
        ushort searchRange = ReadUInt16BigEndian(src, 6);
        ushort entrySelector = ReadUInt16BigEndian(src, 8);
        ushort rangeShift = ReadUInt16BigEndian(src, 10);
        if (tableCount < 1 || tableCount > 4095) return false;

        int maximumPowerOfTwo = 1;
        ushort expectedSelector = 0;
        while ((maximumPowerOfTwo << 1) <= tableCount) {
            maximumPowerOfTwo <<= 1;
            expectedSelector++;
        }
        int expectedSearchRange = maximumPowerOfTwo * 16;
        int expectedRangeShift = tableCount * 16 - expectedSearchRange;
        if (searchRange != expectedSearchRange || entrySelector != expectedSelector || rangeShift != expectedRangeShift)
            return false;

        for (int i = 12; i < 16; i++)
            if (src[i] < 0x20 || src[i] > 0x7E) return false;
        uint firstTableOffset = ReadUInt32BigEndian(src, 20);
        uint firstTableLength = ReadUInt32BigEndian(src, 24);
        long directoryEnd = 12L + tableCount * 16L;
        if (firstTableOffset < directoryEnd || firstTableLength == 0 || (firstTableOffset & 3) != 0 ||
            (completeLength.HasValue && (ulong)firstTableOffset + firstTableLength > (ulong)completeLength.Value)) return false;

        result = new ContentTypeDetectionResult {
            Extension = extension,
            MimeType = mime,
            Confidence = "High",
            Reason = extension == "otf" ? "sfnt:opentype-cff" : "sfnt:truetype"
        };
        return true;
    }

    private static bool TryMatchFontCollection(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result) {
        result = null;
        if (src.Length < 16) return false;
        uint version = ReadUInt32BigEndian(src, 4);
        uint fontCount = ReadUInt32BigEndian(src, 8);
        if (version is not (0x00010000u or 0x00020000u) || fontCount is < 1 or > 4095 || 12L + fontCount * 4L > src.Length)
            return false;

        bool anyCff = false;
        for (uint i = 0; i < fontCount; i++) {
            uint directoryOffset = ReadUInt32BigEndian(src, checked(12 + (int)i * 4));
            if (directoryOffset > int.MaxValue || directoryOffset + 28L > src.Length) return false;
            int offset = (int)directoryOffset;
            if (!TryValidateCollectionFontDirectory(src.Slice(offset, 28), directoryOffset, completeLength, out bool isCff)) return false;
            anyCff |= isCff;
        }

        result = FontCollectionResult(version, fontCount, anyCff);
        return true;
    }

    private static bool TryValidateCollectionFontDirectory(ReadOnlySpan<byte> directory, long directoryOffset, long? completeLength, out bool isCff) {
        isCff = false;
        if (directory.Length < 28 || directoryOffset < 0 || completeLength < 0) return false;
        uint flavor = ReadUInt32BigEndian(directory, 0);
        if (!TryGetSfntFlavor(flavor, out var extension, out _)) return false;
        isCff = extension == "otf";
        ushort tableCount = ReadUInt16BigEndian(directory, 4);
        if (tableCount < 1 || tableCount > 4095 ||
            (completeLength.HasValue && directoryOffset + 12L + tableCount * 16L > completeLength.Value)) return false;
        int maximumPowerOfTwo = 1;
        ushort expectedSelector = 0;
        while ((maximumPowerOfTwo << 1) <= tableCount) {
            maximumPowerOfTwo <<= 1;
            expectedSelector++;
        }
        if (ReadUInt16BigEndian(directory, 6) != maximumPowerOfTwo * 16 ||
            ReadUInt16BigEndian(directory, 8) != expectedSelector ||
            ReadUInt16BigEndian(directory, 10) != tableCount * 16 - maximumPowerOfTwo * 16) return false;
        for (int tag = 12; tag < 16; tag++)
            if (directory[tag] < 0x20 || directory[tag] > 0x7E) return false;
        uint firstTableOffset = ReadUInt32BigEndian(directory, 20);
        uint firstTableLength = ReadUInt32BigEndian(directory, 24);
        return firstTableLength > 0 && (firstTableOffset & 3) == 0 &&
               (!completeLength.HasValue || (ulong)firstTableOffset + firstTableLength <= (ulong)completeLength.Value);
    }

    private static ContentTypeDetectionResult FontCollectionResult(uint version, uint fontCount, bool anyCff) => new() {
        Extension = anyCff ? "otc" : "ttc",
        MimeType = "font/collection",
        Confidence = "High",
        Reason = $"font-collection:v{version >> 16};fonts={fontCount}"
    };

    private static bool TryMatchWoff(ReadOnlySpan<byte> src, long? completeLength, bool isWoff2, out ContentTypeDetectionResult? result) {
        result = null;
        int headerSize = isWoff2 ? 48 : 44;
        if (src.Length < headerSize) return false;

        uint flavor = ReadUInt32BigEndian(src, 4);
        bool isCollection = isWoff2 && flavor == 0x74746366;
        if (!isCollection && !TryGetSfntFlavor(flavor, out _, out _)) return false;
        uint declaredLength = ReadUInt32BigEndian(src, 8);
        ushort tableCount = ReadUInt16BigEndian(src, 12);
        ushort reserved = ReadUInt16BigEndian(src, 14);
        uint totalSfntSize = ReadUInt32BigEndian(src, 16);
        if (tableCount < 1 || tableCount > 4095 || (!isWoff2 && reserved != 0) || declaredLength < headerSize ||
            (completeLength.HasValue && declaredLength != completeLength.Value))
            return false;
        if (totalSfntSize < 12L + tableCount * 16L) return false;

        if (isWoff2) {
            uint compressedSize = ReadUInt32BigEndian(src, 20);
            int cursor = 48;
            for (int table = 0; table < tableCount; table++)
            {
                if (cursor >= src.Length) return false;
                byte flags = src[cursor++];
                int tagIndex = flags & 0x3F;
                int transformVersion = flags >> 6;
                bool isGlyfOrLoca = tagIndex is 10 or 11;
                if (tagIndex == 0x3F) {
                    if (src.Length < cursor + 4) return false;
                    for (int i = 0; i < 4; i++)
                        if (src[cursor + i] < 0x20 || src[cursor + i] > 0x7E) return false;
                    isGlyfOrLoca = src.Slice(cursor, 4).SequenceEqual("glyf"u8) ||
                                   src.Slice(cursor, 4).SequenceEqual("loca"u8);
                    cursor += 4;
                }
                if (!TryReadUIntBase128(src, ref cursor, out uint originalLength) || originalLength == 0) return false;
                bool transformed = isGlyfOrLoca ? transformVersion != 3 : transformVersion != 0;
                if (transformed && !TryReadUIntBase128(src, ref cursor, out _)) return false;
            }

            if (isCollection && !TryValidateWoff2CollectionDirectory(src, ref cursor, tableCount)) return false;
            if (compressedSize == 0 || (ulong)cursor + compressedSize > declaredLength) return false;
            if (!IsOptionalBlockValid(declaredLength, ReadUInt32BigEndian(src, 28), ReadUInt32BigEndian(src, 32))) return false;
            if (!IsOptionalBlockValid(declaredLength, ReadUInt32BigEndian(src, 40), ReadUInt32BigEndian(src, 44))) return false;
        } else {
            if (src.Length < 64) return false;
            long minimumLength = 44L + tableCount * 20L;
            if (declaredLength < minimumLength || (declaredLength & 3) != 0 || (totalSfntSize & 3) != 0) return false;
            for (int i = 44; i < 48; i++)
                if (src[i] < 0x20 || src[i] > 0x7E) return false;
            uint firstTableOffset = ReadUInt32BigEndian(src, 48);
            uint firstCompressedLength = ReadUInt32BigEndian(src, 52);
            uint firstOriginalLength = ReadUInt32BigEndian(src, 56);
            if ((firstTableOffset & 3) != 0 || firstTableOffset < minimumLength ||
                firstCompressedLength == 0 || firstOriginalLength < firstCompressedLength ||
                (ulong)firstTableOffset + firstCompressedLength > declaredLength)
                return false;
            if (!IsOptionalBlockValid(declaredLength, ReadUInt32BigEndian(src, 24), ReadUInt32BigEndian(src, 28))) return false;
            if (!IsOptionalBlockValid(declaredLength, ReadUInt32BigEndian(src, 36), ReadUInt32BigEndian(src, 40))) return false;
        }

        string extension = isWoff2 ? "woff2" : "woff";
        result = new ContentTypeDetectionResult {
            Extension = extension,
            MimeType = "font/" + extension,
            Confidence = "High",
            Reason = "font:" + extension
        };
        return true;
    }

    private static bool TryValidateWoff2CollectionDirectory(ReadOnlySpan<byte> src, ref int cursor, ushort tableCount)
    {
        if (cursor + 4 > src.Length) return false;
        uint version = ReadUInt32BigEndian(src, cursor);
        cursor += 4;
        if (version is not (0x00010000u or 0x00020000u) ||
            !TryRead255UInt16(src, ref cursor, out ushort fontCount) || fontCount == 0) return false;

        for (int font = 0; font < fontCount; font++)
        {
            if (!TryRead255UInt16(src, ref cursor, out ushort fontTableCount) ||
                fontTableCount == 0 || fontTableCount > tableCount || cursor + 4 > src.Length) return false;
            uint flavor = ReadUInt32BigEndian(src, cursor);
            cursor += 4;
            if (!TryGetSfntFlavor(flavor, out _, out _)) return false;
            for (int table = 0; table < fontTableCount; table++)
                if (!TryRead255UInt16(src, ref cursor, out ushort index) || index >= tableCount) return false;
        }
        return true;
    }

    private static bool TryRead255UInt16(ReadOnlySpan<byte> src, ref int cursor, out ushort value)
    {
        value = 0;
        if (cursor >= src.Length) return false;
        byte code = src[cursor++];
        if (code == 253)
        {
            if (cursor + 2 > src.Length) return false;
            value = (ushort)(src[cursor] << 8 | src[cursor + 1]);
            cursor += 2;
            return true;
        }
        if (code is 254 or 255)
        {
            if (cursor >= src.Length) return false;
            value = (ushort)(src[cursor++] + (code == 255 ? 253 : 506));
            return true;
        }
        value = code;
        return true;
    }

    private static bool IsOptionalBlockValid(uint fileLength, uint offset, uint length) {
        if (offset == 0) return length == 0;
        return length > 0 && (ulong)offset + length <= fileLength;
    }

    private static bool TryReadUIntBase128(ReadOnlySpan<byte> src, ref int cursor, out uint value) {
        value = 0;
        for (int i = 0; i < 5; i++) {
            if (cursor >= src.Length) return false;
            byte current = src[cursor++];
            if (i == 0 && current == 0x80) return false;
            if ((value & 0xFE000000u) != 0) return false;
            value = (value << 7) | (uint)(current & 0x7F);
            if ((current & 0x80) == 0) return true;
        }
        return false;
    }

    private static bool TryGetSfntFlavor(uint flavor, out string extension, out string mime) {
        if (flavor is 0x00010000 or 0x74727565) {
            extension = "ttf";
            mime = "font/ttf";
            return true;
        }
        if (flavor == 0x4F54544F) {
            extension = "otf";
            mime = "font/otf";
            return true;
        }
        extension = string.Empty;
        mime = string.Empty;
        return false;
    }

    private static uint ReadUInt32BigEndian(ReadOnlySpan<byte> src, int offset)
        => (uint)(src[offset] << 24 | src[offset + 1] << 16 | src[offset + 2] << 8 | src[offset + 3]);
}
