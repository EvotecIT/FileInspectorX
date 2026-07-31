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

    internal static bool TryMatchFont(ReadOnlySpan<byte> src, long completeLength, out ContentTypeDetectionResult? result) {
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
            (ulong)firstTableOffset + firstTableLength > (ulong)completeLength) return false;

        result = new ContentTypeDetectionResult {
            Extension = extension,
            MimeType = mime,
            Confidence = "High",
            Reason = extension == "otf" ? "sfnt:opentype-cff" : "sfnt:truetype"
        };
        return true;
    }

    private static bool TryMatchFontCollection(ReadOnlySpan<byte> src, long completeLength, out ContentTypeDetectionResult? result) {
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

    private static bool TryValidateCollectionFontDirectory(ReadOnlySpan<byte> directory, long directoryOffset, long completeLength, out bool isCff) {
        isCff = false;
        if (directory.Length < 28 || directoryOffset < 0 || completeLength < 0) return false;
        uint flavor = ReadUInt32BigEndian(directory, 0);
        if (!TryGetSfntFlavor(flavor, out var extension, out _)) return false;
        isCff = extension == "otf";
        ushort tableCount = ReadUInt16BigEndian(directory, 4);
        if (tableCount < 1 || tableCount > 4095 || directoryOffset + 12L + tableCount * 16L > completeLength) return false;
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
               (ulong)firstTableOffset + firstTableLength <= (ulong)completeLength;
    }

    private static ContentTypeDetectionResult FontCollectionResult(uint version, uint fontCount, bool anyCff) => new() {
        Extension = anyCff ? "otc" : "ttc",
        MimeType = "font/collection",
        Confidence = "High",
        Reason = $"font-collection:v{version >> 16};fonts={fontCount}"
    };

    private static bool TryMatchWoff(ReadOnlySpan<byte> src, long completeLength, bool isWoff2, out ContentTypeDetectionResult? result) {
        result = null;
        int headerSize = isWoff2 ? 48 : 44;
        if (src.Length < headerSize) return false;

        uint flavor = ReadUInt32BigEndian(src, 4);
        if (!TryGetSfntFlavor(flavor, out _, out _)) return false;
        uint declaredLength = ReadUInt32BigEndian(src, 8);
        ushort tableCount = ReadUInt16BigEndian(src, 12);
        ushort reserved = ReadUInt16BigEndian(src, 14);
        uint totalSfntSize = ReadUInt32BigEndian(src, 16);
        if (tableCount < 1 || tableCount > 4095 || reserved != 0 || declaredLength < headerSize || declaredLength != completeLength)
            return false;
        if (totalSfntSize < 12L + tableCount * 16L) return false;

        if (isWoff2) {
            if (src.Length < 50) return false;
            uint compressedSize = ReadUInt32BigEndian(src, 20);
            long minimumLength = 48L + tableCount * 2L + compressedSize;
            if (compressedSize == 0 || declaredLength < minimumLength) return false;
            int cursor = 48;
            byte flags = src[cursor++];
            if ((flags & 0x3F) == 0x3F) {
                if (src.Length < cursor + 4) return false;
                for (int i = 0; i < 4; i++)
                    if (src[cursor + i] < 0x20 || src[cursor + i] > 0x7E) return false;
                cursor += 4;
            }
            if (!TryReadUIntBase128(src, ref cursor, out uint firstTableLength) || firstTableLength == 0) return false;
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
