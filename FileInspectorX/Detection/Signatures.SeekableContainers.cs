namespace FileInspectorX;

/// <summary>
/// Detectors that validate both ends of a file or structures at fixed offsets.
/// </summary>
internal static partial class Signatures
{
    private const long QoiPixelStreamScanBudget = 1L << 20;
    internal static bool TryMatchCompleteContainers(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        if (TryMatchParquet(src, out result)) return true;
        if (TryMatchArrow(src, out result)) return true;
        if (TryMatchDeb(src, out result)) return true;
        if (TryMatchVhdx(src, out result)) return true;
        if (TryMatchVhd(src, out result)) return true;
        if (TryMatchQoi(src, out result) && result?.Confidence == "High") return true;
        result = null;
        return false;
    }

    internal static bool TryMatchSeekableContainers(Stream stream, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (!stream.CanRead || !stream.CanSeek) return false;
        long originalPosition = stream.Position;
        try
        {
            if (TryMatchParquet(stream, out result)) return true;
            if (TryMatchArrow(stream, out result)) return true;
            if (TryMatchDeb(stream, out result)) return true;
            if (TryMatchVhdx(stream, out result)) return true;
            if (TryMatchVhd(stream, out result)) return true;
            if (TryMatchQoi(stream, out result)) return true;
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

    internal static bool TryMatchParquet(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 13) return false;
        bool encrypted = src.Slice(0, 4).SequenceEqual("PARE"u8);
        if (!encrypted && !src.Slice(0, 4).SequenceEqual("PAR1"u8)) return false;
        if (!src.Slice(src.Length - 4, 4).SequenceEqual(encrypted ? "PARE"u8 : "PAR1"u8)) return false;
        uint footerLength = ReadUInt32LittleEndian(src, src.Length - 8);
        if (footerLength == 0 || footerLength > src.Length - 12) return false;
        result = BinaryResult("parquet", "application/vnd.apache.parquet", encrypted ? "parquet:encrypted-footer" : "parquet:footer");
        return true;
    }

    internal static bool TryMatchArrow(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 26 || !src.Slice(0, 6).SequenceEqual("ARROW1"u8) || src[6] != 0 || src[7] != 0 ||
            !src.Slice(src.Length - 6, 6).SequenceEqual("ARROW1"u8)) return false;
        uint footerLength = ReadUInt32LittleEndian(src, src.Length - 10);
        if (footerLength < 8 || footerLength > src.Length - 18) return false;
        int footerStart = checked(src.Length - 10 - (int)footerLength);
        uint rootOffset = ReadUInt32LittleEndian(src, footerStart);
        if (footerStart < 8 || rootOffset < 4 || (ulong)rootOffset + 4 > footerLength) return false;
        result = BinaryResult("arrow", "application/vnd.apache.arrow.file", "arrow-ipc:file-footer");
        return true;
    }

    internal static bool TryMatchDeb(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 72 || !src.Slice(0, 8).SequenceEqual("!<arch>\n"u8)) return false;
        int cursor = 8;
        bool version = false;
        bool control = false;
        bool data = false;
        int member = 0;
        while (cursor + 60 <= src.Length && member < 4096)
        {
            ReadOnlySpan<byte> header = src.Slice(cursor, 60);
            if (header[58] != (byte)'`' || header[59] != (byte)'\n' || !TryParseArSize(header.Slice(48, 10), out long size)) return false;
            string name = ParseArName(header.Slice(0, 16));
            long dataOffset = cursor + 60L;
            long next = dataOffset + size + (size & 1);
            if (size < 0 || next > src.Length) return false;
            if (member == 0)
            {
                if (name != "debian-binary" || size != 4 || !src.Slice((int)dataOffset, 4).SequenceEqual("2.0\n"u8)) return false;
                version = true;
            }
            else if (name.StartsWith("control.tar", StringComparison.Ordinal) && size > 0) control = true;
            else if (name.StartsWith("data.tar", StringComparison.Ordinal) && size > 0) data = true;
            cursor = (int)next;
            member++;
            if (version && control && data) break;
        }
        if (!version || !control || !data) return false;
        result = BinaryResult("deb", "application/vnd.debian.binary-package", "deb:ar-members");
        return true;
    }

    internal static bool TryMatchVhdx(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 1024 * 1024 || !src.Slice(0, 8).SequenceEqual("vhdxfile"u8)) return false;
        bool header = src.Slice(64 * 1024, 4).SequenceEqual("head"u8) || src.Slice(128 * 1024, 4).SequenceEqual("head"u8);
        bool region = src.Slice(192 * 1024, 4).SequenceEqual("regi"u8) || src.Slice(256 * 1024, 4).SequenceEqual("regi"u8);
        if (!header || !region) return false;
        result = BinaryResult("vhdx", "application/x-vhdx", "vhdx:file+header+region");
        return true;
    }

    internal static bool TryMatchVhd(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 512) return false;
        return TryMatchVhdFooter(src.Slice(src.Length - 512, 512), out result);
    }

    private static bool TryMatchParquet(Stream stream, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (stream.Length < 13 || !TryReadAt(stream, 0, 4, out var start) || !TryReadAt(stream, stream.Length - 8, 8, out var tail)) return false;
        bool encrypted = new ReadOnlySpan<byte>(start).SequenceEqual("PARE"u8);
        if (!encrypted && !new ReadOnlySpan<byte>(start).SequenceEqual("PAR1"u8)) return false;
        var tailSpan = new ReadOnlySpan<byte>(tail);
        if (!tailSpan.Slice(4, 4).SequenceEqual(encrypted ? "PARE"u8 : "PAR1"u8)) return false;
        uint footerLength = ReadUInt32LittleEndian(tailSpan, 0);
        if (footerLength == 0 || footerLength > stream.Length - 12) return false;
        result = BinaryResult("parquet", "application/vnd.apache.parquet", encrypted ? "parquet:encrypted-footer" : "parquet:footer");
        return true;
    }

    private static bool TryMatchArrow(Stream stream, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (stream.Length < 26 || !TryReadAt(stream, 0, 8, out var start) || !TryReadAt(stream, stream.Length - 10, 10, out var tail)) return false;
        var tailSpan = new ReadOnlySpan<byte>(tail);
        var startSpan = new ReadOnlySpan<byte>(start);
        if (!startSpan.Slice(0, 6).SequenceEqual("ARROW1"u8) || startSpan[6] != 0 || startSpan[7] != 0 ||
            !tailSpan.Slice(4, 6).SequenceEqual("ARROW1"u8)) return false;
        uint footerLength = ReadUInt32LittleEndian(tailSpan, 0);
        if (footerLength < 8 || footerLength > stream.Length - 18) return false;
        long footerStart = stream.Length - 10 - footerLength;
        if (footerStart < 8 || !TryReadAt(stream, footerStart, 4, out var rootBytes)) return false;
        uint rootOffset = ReadUInt32LittleEndian(new ReadOnlySpan<byte>(rootBytes), 0);
        if (rootOffset < 4 || (ulong)rootOffset + 4 > footerLength) return false;
        result = BinaryResult("arrow", "application/vnd.apache.arrow.file", "arrow-ipc:file-footer");
        return true;
    }

    private static bool TryMatchDeb(Stream stream, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (stream.Length < 72 || !TryReadAt(stream, 0, 8, out var signature) || !new ReadOnlySpan<byte>(signature).SequenceEqual("!<arch>\n"u8)) return false;
        long cursor = 8;
        bool version = false;
        bool control = false;
        bool data = false;
        for (int member = 0; member < 4096 && cursor + 60 <= stream.Length; member++)
        {
            if (!TryReadAt(stream, cursor, 60, out var headerBytes)) return false;
            var header = new ReadOnlySpan<byte>(headerBytes);
            if (header[58] != (byte)'`' || header[59] != (byte)'\n' || !TryParseArSize(header.Slice(48, 10), out long size)) return false;
            string name = ParseArName(header.Slice(0, 16));
            long dataOffset = cursor + 60;
            long next = dataOffset + size + (size & 1);
            if (size < 0 || next > stream.Length) return false;
            if (member == 0)
            {
                if (name != "debian-binary" || size != 4 || !TryReadAt(stream, dataOffset, 4, out var value) || !new ReadOnlySpan<byte>(value).SequenceEqual("2.0\n"u8)) return false;
                version = true;
            }
            else if (name.StartsWith("control.tar", StringComparison.Ordinal) && size > 0) control = true;
            else if (name.StartsWith("data.tar", StringComparison.Ordinal) && size > 0) data = true;
            cursor = next;
            if (version && control && data) break;
        }
        if (!version || !control || !data) return false;
        result = BinaryResult("deb", "application/vnd.debian.binary-package", "deb:ar-members");
        return true;
    }

    private static bool TryMatchVhdx(Stream stream, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (stream.Length < 1024 * 1024 || !TryReadAt(stream, 0, 8, out var signature) || !new ReadOnlySpan<byte>(signature).SequenceEqual("vhdxfile"u8)) return false;
        bool header = MatchesAt(stream, 64 * 1024, "head"u8) || MatchesAt(stream, 128 * 1024, "head"u8);
        bool region = MatchesAt(stream, 192 * 1024, "regi"u8) || MatchesAt(stream, 256 * 1024, "regi"u8);
        if (!header || !region) return false;
        result = BinaryResult("vhdx", "application/x-vhdx", "vhdx:file+header+region");
        return true;
    }

    private static bool TryMatchVhd(Stream stream, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (stream.Length < 512 || !TryReadAt(stream, stream.Length - 512, 512, out var footer)) return false;
        return TryMatchVhdFooter(new ReadOnlySpan<byte>(footer), out result);
    }

    private static bool TryMatchQoi(Stream stream, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (stream.Length < 23 || !TryReadAt(stream, 0, 14, out var header) || !TryReadAt(stream, stream.Length - 8, 8, out var end)) return false;
        if (!TryMatchQoi(new ReadOnlySpan<byte>(header), out var headerResult) ||
            !new ReadOnlySpan<byte>(end).SequenceEqual(new byte[] { 0, 0, 0, 0, 0, 0, 0, 1 })) return false;
        var headerSpan = new ReadOnlySpan<byte>(header);
        ulong expectedPixels = (ulong)ReadUInt32BigEndian(headerSpan, 4) * ReadUInt32BigEndian(headerSpan, 8);
        long dataEnd = stream.Length - 8;
        if (dataEnd - 14 > QoiPixelStreamScanBudget) return false;
        long cursor = 14;
        ulong pixels = 0;
        stream.Seek(cursor, SeekOrigin.Begin);
        while (cursor < dataEnd && pixels < expectedPixels)
        {
            int current = stream.ReadByte();
            if (current < 0) return false;
            cursor++;
            byte operation = (byte)current;
            int payloadLength = operation == 0xFE ? 3 : operation == 0xFF ? 4 : (operation & 0xC0) == 0x80 ? 1 : 0;
            ulong produced = (operation & 0xC0) == 0xC0 && operation < 0xFE ? (ulong)(operation & 0x3F) + 1 : 1;
            if (cursor + payloadLength > dataEnd || produced > expectedPixels - pixels) return false;
            for (int index = 0; index < payloadLength; index++)
                if (stream.ReadByte() < 0) return false;
            cursor += payloadLength;
            pixels += produced;
        }
        if (pixels != expectedPixels || cursor != dataEnd) return false;
        result = headerResult;
        result!.Confidence = "High";
        result.Reason = "qoi:header+pixel-stream+end-marker";
        return true;
    }

    private static bool TryMatchVhdFooter(ReadOnlySpan<byte> footer, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (footer.Length != 512 || !footer.Slice(0, 8).SequenceEqual("conectix"u8) || ReadUInt32BigEndian(footer, 12) != 0x00010000) return false;
        uint diskType = ReadUInt32BigEndian(footer, 60);
        if (diskType is < 2 or > 4) return false;
        uint storedChecksum = ReadUInt32BigEndian(footer, 64);
        uint sum = 0;
        for (int i = 0; i < footer.Length; i++) if (i < 64 || i >= 68) sum += footer[i];
        if (~sum != storedChecksum) return false;
        result = BinaryResult("vhd", "application/x-vhd", $"vhd:footer;type={diskType}");
        return true;
    }

    private static bool TryReadAt(Stream stream, long offset, int count, out byte[] bytes)
    {
        bytes = new byte[count];
        if (offset < 0 || offset + count > stream.Length) return false;
        stream.Seek(offset, SeekOrigin.Begin);
        int total = 0;
        while (total < count)
        {
            int read = stream.Read(bytes, total, count - total);
            if (read <= 0) return false;
            total += read;
        }
        return true;
    }

    private static bool MatchesAt(Stream stream, long offset, ReadOnlySpan<byte> expected)
        => TryReadAt(stream, offset, expected.Length, out var bytes) && new ReadOnlySpan<byte>(bytes).SequenceEqual(expected);

    private static bool TryParseArSize(ReadOnlySpan<byte> field, out long value)
    {
        value = 0;
        bool digit = false;
        for (int i = 0; i < field.Length; i++)
        {
            byte current = field[i];
            if (current == (byte)' ') continue;
            if (current is < (byte)'0' or > (byte)'9') return false;
            digit = true;
            if (value > (long.MaxValue - (current - (byte)'0')) / 10) return false;
            value = value * 10 + current - (byte)'0';
        }
        return digit;
    }

    private static string ParseArName(ReadOnlySpan<byte> field)
    {
        int length = field.Length;
        while (length > 0 && field[length - 1] == (byte)' ') length--;
        if (length > 0 && field[length - 1] == (byte)'/') length--;
        return System.Text.Encoding.ASCII.GetString(field.Slice(0, length).ToArray());
    }
}
