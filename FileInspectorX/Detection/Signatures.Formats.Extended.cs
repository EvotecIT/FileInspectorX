namespace FileInspectorX;

/// <summary>
/// Structurally validated package, media, medical, graphics, and data-container formats.
/// </summary>
internal static partial class Signatures
{
    internal static bool TryMatchExtendedHeaderFormats(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
        => TryMatchExtendedHeaderFormats(src, src.Length, out result);

    internal static bool TryMatchExtendedHeaderFormats(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result)
    {
        if (TryMatchRpm(src, completeLength, out result)) return true;
        if (TryMatchQcow2(src, completeLength, out result)) return true;
        if (TryMatchMidi(src, completeLength, out result)) return true;
        if (TryMatchDds(src, out result)) return true;
        if (TryMatchQoi(src, out result)) return true;
        if (TryMatchDicom(src, out result)) return true;
        if (TryMatchOutlookNdb(src, out result)) return true;
        if (TryMatchMatroska(src, completeLength, out result)) return true;
        result = null;
        return false;
    }

    internal static bool TryMatchRpm(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
        => TryMatchRpm(src, src.Length, out result);

    internal static bool TryMatchRpm(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result)
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
            (completeLength.HasValue && 112L + indexCount * 16L + dataLength > completeLength.Value)) return false;
        result = BinaryResult("rpm", "application/x-rpm", "rpm:lead+signature-header");
        return true;
    }

    internal static bool TryMatchQcow2(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
        => TryMatchQcow2(src, src.Length, out result);

    internal static bool TryMatchQcow2(Stream stream, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (!stream.CanRead || !stream.CanSeek) return false;
        long originalPosition = stream.Position;
        try
        {
            if (stream.Length < 72 || !TryReadAt(stream, 0, (int)Math.Min(104, stream.Length), out var header)) return false;
            var headerSpan = new ReadOnlySpan<byte>(header);
            if (headerSpan.Length < 36 || ReadUInt32BigEndian(headerSpan, 32) != 2)
                return TryMatchQcow2(headerSpan, stream.Length, out result);
            if (headerSpan.Length < 104) return false;
            uint clusterBits = ReadUInt32BigEndian(headerSpan, 20);
            if (clusterBits is < 9 or > 21) return false;
            int extensionAreaLength = (int)Math.Min(1L << (int)clusterBits, stream.Length);
            if (!TryReadAt(stream, 0, extensionAreaLength, out var extensionArea)) return false;
            return TryMatchQcow2(new ReadOnlySpan<byte>(extensionArea), stream.Length, out result);
        }
        catch
        {
            result = null;
            return false;
        }
        finally
        {
            try { stream.Seek(originalPosition, SeekOrigin.Begin); } catch { }
        }
    }

    internal static bool TryMatchQcow2(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result)
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
        if (version is not (2u or 3u) || clusterBits is < 9 or > 21 || virtualSize == 0 || cryptMethod > 2 ||
            l1Size == 0 || l1Offset == 0 || refcountOffset == 0 || refcountClusters == 0) return false;
        ulong clusterSize = 1UL << (int)clusterBits;
        if ((l1Offset & (clusterSize - 1)) != 0 || (refcountOffset & (clusterSize - 1)) != 0) return false;
        if ((backingOffset == 0) != (backingSize == 0)) return false;
        if (version == 3)
        {
            if (src.Length < 104) return false;
            uint headerLength = ReadUInt32BigEndian(src, 100);
            if (headerLength < 104 || (headerLength & 7) != 0 ||
                (completeLength.HasValue && headerLength > completeLength.Value)) return false;
            if (cryptMethod == 2 && !TryValidateQcow2LuksExtension(src, headerLength, clusterSize, completeLength)) return false;
        }
        else if (cryptMethod == 2) return false;
        result = BinaryResult("qcow2", "application/x-qemu-disk", $"qcow2:version={version}");
        return true;
    }

    private static bool TryValidateQcow2LuksExtension(ReadOnlySpan<byte> src, uint headerLength, ulong clusterSize, long? completeLength)
    {
        int cursor = (int)headerLength;
        bool found = false;
        while (cursor + 8 <= src.Length && (ulong)cursor < clusterSize)
        {
            uint type = ReadUInt32BigEndian(src, cursor);
            uint length = ReadUInt32BigEndian(src, cursor + 4);
            cursor += 8;
            if (type == 0) return length == 0 && found;
            ulong paddedLength = ((ulong)length + 7) & ~7UL;
            if (paddedLength > int.MaxValue || (ulong)cursor + paddedLength > (ulong)src.Length ||
                (ulong)cursor + paddedLength > clusterSize) return false;
            if (type == 0x0537BE77)
            {
                if (found || length != 16) return false;
                ulong offset = ReadUInt64(src, cursor, littleEndian: false);
                ulong encryptionLength = ReadUInt64(src, cursor + 8, littleEndian: false);
                if (offset == 0 || encryptionLength < 592 || (offset & (clusterSize - 1)) != 0 ||
                    (completeLength.HasValue && (offset > (ulong)completeLength.Value ||
                                                 encryptionLength > (ulong)completeLength.Value - offset))) return false;
                found = true;
            }
            cursor += (int)paddedLength;
        }
        return false;
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
        ulong pixelCount = (ulong)width * height;
        if (src.Length >= 23 && src.Slice(src.Length - 8, 8).SequenceEqual(new byte[] { 0, 0, 0, 0, 0, 0, 0, 1 }) &&
            TryValidateQoiChunks(src.Slice(14, src.Length - 22), pixelCount))
        {
            confidence = "High";
            reason += "+pixel-stream+end-marker";
        }
        result = new ContentTypeDetectionResult { Extension = "qoi", MimeType = "image/qoi", Confidence = confidence, Reason = reason };
        return true;
    }

    private static bool TryValidateQoiChunks(ReadOnlySpan<byte> chunks, ulong expectedPixels)
    {
        ulong pixels = 0;
        int cursor = 0;
        while (cursor < chunks.Length && pixels < expectedPixels)
        {
            byte operation = chunks[cursor++];
            ulong produced = 1;
            if (operation == 0xFE)
            {
                if (cursor + 3 > chunks.Length) return false;
                cursor += 3;
            }
            else if (operation == 0xFF)
            {
                if (cursor + 4 > chunks.Length) return false;
                cursor += 4;
            }
            else if ((operation & 0xC0) == 0x80)
            {
                if (cursor >= chunks.Length) return false;
                cursor++;
            }
            else if ((operation & 0xC0) == 0xC0)
            {
                produced = (ulong)(operation & 0x3F) + 1;
            }
            if (produced > expectedPixels - pixels) return false;
            pixels += produced;
        }
        return pixels == expectedPixels && cursor == chunks.Length;
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

    internal static bool TryMatchOutlookNdb(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 24 || !src.Slice(0, 4).SequenceEqual("!BDN"u8) || !src.Slice(8, 2).SequenceEqual("SM"u8)) return false;
        ushort version = ReadUInt16LittleEndian(src, 10);
        ushort clientVersion = ReadUInt16LittleEndian(src, 12);
        if (version is not (14 or 15) && version is not (>= 23 and <= 50)) return false;
        if (clientVersion == 0 || src[14] != 1 || src[15] != 1) return false;
        result = BinaryResult("ndb", "application/vnd.ms-outlook", version < 23 ? "outlook-ndb:ansi" : "outlook-ndb:unicode");
        return true;
    }

    internal static bool TryMatchMatroska(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
        => TryMatchMatroska(src, src.Length, out result);

    internal static bool TryMatchMatroska(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (!TryReadMatroskaDocumentType(src, out string? docType, out int headerEnd) ||
            !TryFindMatroskaSegment(src, headerEnd, completeLength, out bool sampledRootVoid)) return false;
        result = MatroskaResult(docType!, sampledRootVoid);
        return true;
    }

    private static bool TryReadMatroskaDocumentType(ReadOnlySpan<byte> src, out string? docType, out int headerEnd)
    {
        docType = null;
        headerEnd = 0;
        if (src.Length < 12 || !src.Slice(0, 4).SequenceEqual(new byte[] { 0x1A, 0x45, 0xDF, 0xA3 })) return false;
        int cursor = 4;
        if (!TryReadEbmlVInt(src, ref cursor, stripMarker: true, out ulong headerLength) || headerLength > 4096 || headerLength > (ulong)(src.Length - cursor)) return false;
        headerEnd = cursor + (int)headerLength;
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
        return docType is "matroska" or "webm";
    }

    private static bool TryFindMatroskaSegment(ReadOnlySpan<byte> src, int cursor, long? completeLength, out bool sampledRootVoid)
    {
        sampledRootVoid = false;
        while (cursor < src.Length)
        {
            if (src.Length - cursor >= 4 && src.Slice(cursor, 4).SequenceEqual(new byte[] { 0x18, 0x53, 0x80, 0x67 })) return true;
            if (!TryReadEbmlVInt(src, ref cursor, stripMarker: false, out ulong id) || id != 0xEC ||
                !TryReadEbmlVInt(src, ref cursor, stripMarker: true, out ulong length)) return false;
            if (length > (ulong)(src.Length - cursor))
            {
                if (completeLength.HasValue) return false;
                sampledRootVoid = true;
                return true;
            }
            cursor += (int)length;
            if (cursor == src.Length && !completeLength.HasValue)
            {
                sampledRootVoid = true;
                return true;
            }
        }
        return false;
    }

    private static ContentTypeDetectionResult MatroskaResult(string docType, bool sampledRootVoid = false)
    {
        var result = docType == "webm"
            ? BinaryResult("webm", "application/webm", "ebml:doctype=webm")
            : BinaryResult("matroska", "application/x-matroska", "ebml:doctype=matroska");
        if (sampledRootVoid)
        {
            result.Confidence = "Medium";
            result.Reason += ";sampled-root-void";
        }
        return result;
    }

    internal static bool TryMatchMatroska(Stream stream, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (!stream.CanRead || !stream.CanSeek) return false;
        long originalPosition = stream.Position;
        try
        {
            if (stream.Length < 16) return false;
            int readLength = (int)Math.Min(stream.Length, 4L + 8L + 4096L);
            stream.Seek(0, SeekOrigin.Begin);
            var bytes = new byte[readLength];
            int read = ReadHeaderBytes(stream, bytes);
            if (!TryReadMatroskaDocumentType(new ReadOnlySpan<byte>(bytes, 0, read), out string? docType, out int headerEnd)) return false;
            long cursor = headerEnd;
            while (cursor < stream.Length)
            {
                if (stream.Length - cursor >= 4 && TryReadAt(stream, cursor, 4, out var idBytes) &&
                    new ReadOnlySpan<byte>(idBytes).SequenceEqual(new byte[] { 0x18, 0x53, 0x80, 0x67 }))
                {
                    result = MatroskaResult(docType!);
                    return true;
                }
                if (!TryReadAt(stream, cursor, 1, out var voidId) || voidId[0] != 0xEC) return false;
                stream.Seek(cursor + 1, SeekOrigin.Begin);
                if (!TryReadEbmlVInt(stream, out ulong voidLength)) return false;
                long payloadOffset = stream.Position;
                if (voidLength > (ulong)(stream.Length - payloadOffset)) return false;
                cursor = payloadOffset + (long)voidLength;
            }
            return false;
        }
        catch
        {
            result = null;
            return false;
        }
        finally
        {
            try { stream.Seek(originalPosition, SeekOrigin.Begin); } catch { }
        }
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

    private static bool TryReadEbmlVInt(Stream stream, out ulong value)
    {
        value = 0;
        int firstValue = stream.ReadByte();
        if (firstValue < 0) return false;
        byte first = (byte)firstValue;
        int length = 1;
        byte marker = 0x80;
        while (length <= 8 && (first & marker) == 0) { marker >>= 1; length++; }
        if (length > 8) return false;
        value = (ulong)(first & (marker - 1));
        for (int index = 1; index < length; index++)
        {
            int current = stream.ReadByte();
            if (current < 0) return false;
            value = (value << 8) | (byte)current;
        }
        ulong unknown = length == 8 ? 0x00FFFFFFFFFFFFFFUL : (1UL << (7 * length)) - 1;
        return value != unknown;
    }
}
