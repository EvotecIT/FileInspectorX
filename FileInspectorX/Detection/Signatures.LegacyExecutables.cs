namespace FileInspectorX;

/// <summary>
/// Structural detection for DOS MZ and the legacy NE, LE, and LX executable families.
/// </summary>
internal static partial class Signatures
{
    internal static bool TryMatchLegacyMz(ReadOnlySpan<byte> src, long? completeLength,
        out ContentTypeDetectionResult? result)
    {
        result = null;
        if (!completeLength.HasValue || completeLength.Value < 28) return false;
        int headerReadLength = (int)Math.Min(64, completeLength.Value);
        if (src.Length < headerReadLength ||
            !TryValidateDosExecutableHeader(src.Slice(0, headerReadLength), completeLength.Value, out uint secondaryOffset))
            return false;

        string family = "dos-executable";
        if (secondaryOffset >= 64 && secondaryOffset + 2L <= completeLength.Value)
        {
            if (secondaryOffset + 2L > src.Length) return false;
            ReadOnlySpan<byte> secondary = src.Slice((int)secondaryOffset);
            if (secondary[0] == (byte)'P' && secondary[1] == (byte)'E') return false;
            if (secondary[0] == (byte)'N' && secondary[1] == (byte)'E')
            {
                if (!TryValidateNeHeader(secondary, secondaryOffset, completeLength.Value)) return false;
                family = "ne";
            }
            else if (secondary[0] == (byte)'L' && secondary[1] is (byte)'E' or (byte)'X')
            {
                if (!TryValidateLinearExecutableHeader(secondary, secondaryOffset, completeLength.Value)) return false;
                family = secondary[1] == (byte)'E' ? "le" : "lx";
            }
        }

        result = LegacyExecutableResult(family);
        return true;
    }

    internal static bool TryMatchLegacyMz(Stream stream, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (!stream.CanRead || !stream.CanSeek) return false;
        long originalPosition = stream.Position;
        try
        {
            if (stream.Length < 28) return false;
            int headerReadLength = (int)Math.Min(64, stream.Length);
            if (!TryReadAt(stream, 0, headerReadLength, out byte[] dosBytes)) return false;
            ReadOnlySpan<byte> dos = new(dosBytes);
            if (!TryValidateDosExecutableHeader(dos, stream.Length, out uint secondaryOffset)) return false;

            string family = "dos-executable";
            if (secondaryOffset >= 64 && secondaryOffset + 2L <= stream.Length)
            {
                int readLength = (int)Math.Min(0xB0, stream.Length - secondaryOffset);
                if (!TryReadAt(stream, secondaryOffset, readLength, out byte[] secondaryBytes)) return false;
                ReadOnlySpan<byte> secondary = new(secondaryBytes);
                if (secondary[0] == (byte)'P' && secondary[1] == (byte)'E') return false;
                if (secondary[0] == (byte)'N' && secondary[1] == (byte)'E')
                {
                    if (!TryValidateNeHeader(secondary, secondaryOffset, stream.Length)) return false;
                    family = "ne";
                }
                else if (secondary[0] == (byte)'L' && secondary[1] is (byte)'E' or (byte)'X')
                {
                    if (!TryValidateLinearExecutableHeader(secondary, secondaryOffset, stream.Length)) return false;
                    family = secondary[1] == (byte)'E' ? "le" : "lx";
                }
            }

            result = LegacyExecutableResult(family);
            return true;
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

    private static bool TryValidateDosExecutableHeader(ReadOnlySpan<byte> header, long completeLength,
        out uint secondaryOffset)
    {
        secondaryOffset = 0;
        if (header.Length < 28 || completeLength < 28 || header[0] != (byte)'M' || header[1] != (byte)'Z')
            return false;

        ushort bytesInLastPage = ReadUInt16LittleEndian(header, 2);
        ushort pageCount = ReadUInt16LittleEndian(header, 4);
        ushort relocationCount = ReadUInt16LittleEndian(header, 6);
        ushort headerParagraphs = ReadUInt16LittleEndian(header, 8);
        ushort relocationOffset = ReadUInt16LittleEndian(header, 0x18);
        if (bytesInLastPage > 511 || pageCount == 0 || headerParagraphs < 2 || relocationOffset < 0x1C)
            return false;

        long declaredLength = bytesInLastPage == 0
            ? pageCount * 512L
            : (pageCount - 1L) * 512L + bytesInLastPage;
        long headerLength = headerParagraphs * 16L;
        long relocationEnd = relocationOffset + relocationCount * 4L;
        if (declaredLength < headerLength || declaredLength > completeLength || relocationEnd > headerLength)
            return false;

        if (header.Length >= 64) secondaryOffset = ReadUInt32LittleEndian(header, 0x3C);
        return true;
    }

    private static bool TryValidateNeHeader(ReadOnlySpan<byte> header, long offset, long completeLength)
    {
        if (header.Length < 0x40) return false;
        ushort entryOffset = ReadUInt16LittleEndian(header, 4);
        ushort entryLength = ReadUInt16LittleEndian(header, 6);
        ushort segmentCount = ReadUInt16LittleEndian(header, 0x1C);
        ushort segmentTableOffset = ReadUInt16LittleEndian(header, 0x22);
        byte targetOs = header[0x36];
        if (segmentCount is < 1 or > 4095 || segmentTableOffset < 0x40 || targetOs is < 1 or > 5)
            return false;
        if (offset + segmentTableOffset + segmentCount * 8L > completeLength) return false;
        return entryLength == 0 ||
               entryOffset >= 0x40 && offset + entryOffset + entryLength <= completeLength;
    }

    private static bool TryValidateLinearExecutableHeader(ReadOnlySpan<byte> header, long offset, long completeLength)
    {
        if (header.Length < 0xB0 || header[2] != 0 || header[3] != 0 ||
            ReadUInt32LittleEndian(header, 4) != 0) return false;
        ushort cpu = ReadUInt16LittleEndian(header, 8);
        uint pageCount = ReadUInt32LittleEndian(header, 20);
        uint pageSize = ReadUInt32LittleEndian(header, 40);
        uint objectTableOffset = ReadUInt32LittleEndian(header, 64);
        uint objectCount = ReadUInt32LittleEndian(header, 68);
        uint pageMapOffset = ReadUInt32LittleEndian(header, 72);
        uint dataPagesOffset = ReadUInt32LittleEndian(header, 128);
        if (cpu == 0 || pageCount == 0 || pageSize < 512 || pageSize > 65536 ||
            (pageSize & (pageSize - 1)) != 0 || objectCount is < 1 or > 4095 ||
            objectTableOffset < 0xB0 || pageMapOffset < objectTableOffset + objectCount * 24L)
            return false;
        if (offset + objectTableOffset + objectCount * 24L > completeLength ||
            offset + pageMapOffset > completeLength || dataPagesOffset > completeLength)
            return false;
        return true;
    }

    private static ContentTypeDetectionResult LegacyExecutableResult(string family) => new()
    {
        Extension = "exe",
        MimeType = "application/x-msdownload",
        Confidence = "Medium",
        Reason = "mz:" + family
    };
}
