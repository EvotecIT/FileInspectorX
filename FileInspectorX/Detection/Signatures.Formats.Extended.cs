namespace FileInspectorX;

/// <summary>
/// Structurally validated package, media, medical, graphics, and data-container formats.
/// </summary>
internal static partial class Signatures
{
    internal static bool TryMatchExtendedHeaderFormats(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        if (TryMatchRpm(src, out result)) return true;
        if (TryMatchQcow2(src, out result)) return true;
        if (TryMatchMidi(src, out result)) return true;
        if (TryMatchDds(src, out result)) return true;
        if (TryMatchQoi(src, out result)) return true;
        if (TryMatchDicom(src, out result)) return true;
        if (TryMatchPst(src, out result)) return true;
        if (TryMatchMatroska(src, out result)) return true;
        result = null;
        return false;
    }

    internal static bool TryMatchRpm(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 112 || !src.Slice(0, 4).SequenceEqual(new byte[] { 0xED, 0xAB, 0xEE, 0xDB })) return false;
        if (src[4] != 3 || src[5] != 0 || ReadUInt16BigEndian(src, 6) > 1 || ReadUInt16BigEndian(src, 78) != 5) return false;
        for (int i = 80; i < 96; i++) if (src[i] != 0) return false;
        if (!src.Slice(96, 4).SequenceEqual(new byte[] { 0x8E, 0xAD, 0xE8, 0x01 })) return false;
        for (int i = 100; i < 104; i++) if (src[i] != 0) return false;
        uint indexCount = ReadUInt32BigEndian(src, 104);
        uint dataLength = ReadUInt32BigEndian(src, 108);
        if (indexCount is < 1 or > 65535 || dataLength > 0x40000000 ||
            112L + indexCount * 16L + dataLength > src.Length) return false;
        result = BinaryResult("rpm", "application/x-rpm", "rpm:lead+signature-header");
        return true;
    }

    internal static bool TryMatchQcow2(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 72 || !src.Slice(0, 4).SequenceEqual(new byte[] { (byte)'Q', (byte)'F', (byte)'I', 0xFB })) return false;
        uint version = ReadUInt32BigEndian(src, 4);
        ulong backingOffset = ReadUInt64(src, 8, littleEndian: false);
        uint backingSize = ReadUInt32BigEndian(src, 16);
        uint clusterBits = ReadUInt32BigEndian(src, 20);
        ulong virtualSize = ReadUInt64(src, 24, littleEndian: false);
        uint cryptMethod = ReadUInt32BigEndian(src, 32);
        uint l1Size = ReadUInt32BigEndian(src, 36);
        ulong l1Offset = ReadUInt64(src, 40, littleEndian: false);
        ulong refcountOffset = ReadUInt64(src, 48, littleEndian: false);
        uint refcountClusters = ReadUInt32BigEndian(src, 56);
        if (version is not (2u or 3u) || clusterBits is < 9 or > 21 || virtualSize == 0 || cryptMethod > 1 ||
            l1Size == 0 || l1Offset == 0 || refcountOffset == 0 || refcountClusters == 0) return false;
        ulong clusterSize = 1UL << (int)clusterBits;
        if ((l1Offset & (clusterSize - 1)) != 0 || (refcountOffset & (clusterSize - 1)) != 0) return false;
        if ((backingOffset == 0) != (backingSize == 0)) return false;
        if (version == 3)
        {
            if (src.Length < 104 || ReadUInt32BigEndian(src, 100) < 104) return false;
        }
        result = BinaryResult("qcow2", "application/x-qemu-disk", $"qcow2:version={version}");
        return true;
    }

    internal static bool TryMatchMidi(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 22 || !src.Slice(0, 4).SequenceEqual("MThd"u8) || ReadUInt32BigEndian(src, 4) != 6) return false;
        ushort format = ReadUInt16BigEndian(src, 8);
        ushort tracks = ReadUInt16BigEndian(src, 10);
        ushort division = ReadUInt16BigEndian(src, 12);
        if (format > 2 || tracks == 0 || (format == 0 && tracks != 1) || division == 0 || !src.Slice(14, 4).SequenceEqual("MTrk"u8)) return false;
        result = BinaryResult("mid", "audio/midi", $"midi:format={format};tracks={tracks}");
        return true;
    }

    internal static bool TryMatchDds(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 128 || !src.Slice(0, 4).SequenceEqual("DDS "u8) || ReadUInt32LittleEndian(src, 4) != 124) return false;
        uint flags = ReadUInt32LittleEndian(src, 8);
        uint height = ReadUInt32LittleEndian(src, 12);
        uint width = ReadUInt32LittleEndian(src, 16);
        uint pixelFormatSize = ReadUInt32LittleEndian(src, 76);
        uint pixelFormatFlags = ReadUInt32LittleEndian(src, 80);
        uint fourCc = ReadUInt32LittleEndian(src, 84);
        uint caps = ReadUInt32LittleEndian(src, 108);
        if ((flags & 0x1007) != 0x1007 || height == 0 || width == 0 || pixelFormatSize != 32 || (caps & 0x1000) == 0) return false;
        if ((pixelFormatFlags & 0x4) != 0 && fourCc == 0x30315844 && src.Length < 148) return false;
        result = BinaryResult("dds", "image/vnd-ms.dds", "dds:header+pixel-format");
        return true;
    }

    internal static bool TryMatchQoi(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 14 || !src.Slice(0, 4).SequenceEqual("qoif"u8)) return false;
        uint width = ReadUInt32BigEndian(src, 4);
        uint height = ReadUInt32BigEndian(src, 8);
        byte channels = src[12];
        byte colorSpace = src[13];
        if (width == 0 || height == 0 || channels is not (3 or 4) || colorSpace > 1) return false;
        string confidence = "Medium";
        string reason = "qoi:header";
        if (src.Length >= 22 && src.Slice(src.Length - 8, 8).SequenceEqual(new byte[] { 0, 0, 0, 0, 0, 0, 0, 1 }))
        {
            confidence = "High";
            reason += "+end-marker";
        }
        result = new ContentTypeDetectionResult { Extension = "qoi", MimeType = "image/qoi", Confidence = confidence, Reason = reason };
        return true;
    }

    internal static bool TryMatchDicom(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 156 || !src.Slice(128, 4).SequenceEqual("DICM"u8)) return false;
        if (ReadUInt16LittleEndian(src, 132) != 0x0002 || ReadUInt16LittleEndian(src, 134) != 0x0000 ||
            src[136] != (byte)'U' || src[137] != (byte)'L' || ReadUInt16LittleEndian(src, 138) != 4)
            return false;
        uint metaLength = ReadUInt32LittleEndian(src, 140);
        if (metaLength < 12 || ReadUInt16LittleEndian(src, 144) != 0x0002 ||
            ReadUInt16LittleEndian(src, 146) == 0 || src[148] is < (byte)'A' or > (byte)'Z' ||
            src[149] is < (byte)'A' or > (byte)'Z') return false;
        result = BinaryResult("dcm", "application/dicom", "dicom:preamble+meta-header");
        return true;
    }

    internal static bool TryMatchPst(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 24 || !src.Slice(0, 4).SequenceEqual("!BDN"u8) || !src.Slice(8, 2).SequenceEqual("SM"u8)) return false;
        ushort version = ReadUInt16LittleEndian(src, 10);
        ushort clientVersion = ReadUInt16LittleEndian(src, 12);
        if (version is not (14 or 15) && version is not (>= 23 and <= 50)) return false;
        if (clientVersion == 0 || src[14] != 1 || src[15] != 1) return false;
        result = BinaryResult("pst", "application/vnd.ms-outlook", version < 23 ? "pst:ansi" : "pst:unicode");
        return true;
    }

    internal static bool TryMatchMatroska(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 16 || !src.Slice(0, 4).SequenceEqual(new byte[] { 0x1A, 0x45, 0xDF, 0xA3 })) return false;
        int cursor = 4;
        if (!TryReadEbmlVInt(src, ref cursor, stripMarker: true, out ulong headerLength) || headerLength > 4096 || headerLength > (ulong)(src.Length - cursor)) return false;
        int headerEnd = cursor + (int)headerLength;
        string? docType = null;
        while (cursor < headerEnd)
        {
            if (!TryReadEbmlVInt(src.Slice(0, headerEnd), ref cursor, stripMarker: false, out ulong id)) return false;
            if (!TryReadEbmlVInt(src.Slice(0, headerEnd), ref cursor, stripMarker: true, out ulong length) || length > (ulong)(headerEnd - cursor)) return false;
            if (id == 0x4282)
            {
                if (length is < 4 or > 8) return false;
                docType = System.Text.Encoding.ASCII.GetString(src.Slice(cursor, (int)length).ToArray());
            }
            cursor += (int)length;
        }
        if (docType is not ("matroska" or "webm")) return false;
        if (src.Length < headerEnd + 4 || !src.Slice(headerEnd, 4).SequenceEqual(new byte[] { 0x18, 0x53, 0x80, 0x67 })) return false;
        result = BinaryResult(docType == "webm" ? "webm" : "mkv", docType == "webm" ? "video/webm" : "video/x-matroska", "ebml:doctype=" + docType);
        return true;
    }

    private static bool TryReadEbmlVInt(ReadOnlySpan<byte> src, ref int cursor, bool stripMarker, out ulong value)
    {
        value = 0;
        if (cursor >= src.Length) return false;
        byte first = src[cursor];
        int length = 1;
        byte marker = 0x80;
        while (length <= 8 && (first & marker) == 0) { marker >>= 1; length++; }
        if (length > 8 || cursor + length > src.Length) return false;
        value = stripMarker ? (ulong)(first & (marker - 1)) : first;
        for (int i = 1; i < length; i++) value = (value << 8) | src[cursor + i];
        cursor += length;
        if (stripMarker)
        {
            ulong unknown = length == 8 ? 0x00FFFFFFFFFFFFFFUL : (1UL << (7 * length)) - 1;
            if (value == unknown) return false;
        }
        return true;
    }
}
