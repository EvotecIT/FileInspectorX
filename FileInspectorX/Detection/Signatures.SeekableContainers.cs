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
        if (!encrypted && !TryValidateParquetMetadata(src.Slice(src.Length - 8 - (int)footerLength, (int)footerLength))) return false;
        result = BinaryResult("parquet", "application/vnd.apache.parquet", encrypted ? "parquet:encrypted-footer" : "parquet:footer");
        if (encrypted) result.Confidence = "Medium";
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
        if (footerStart < 8 || rootOffset < 4 || (ulong)rootOffset + 4 > footerLength ||
            !TryValidateArrowFooter(src.Slice(footerStart, (int)footerLength))) return false;
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
        bool controlTarValidated = false;
        bool dataTarValidated = false;
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
            else if (name.StartsWith("control.tar", StringComparison.Ordinal) && size > 0 &&
                     TryValidateDebTarMember(name, src.Slice((int)dataOffset, (int)size), out controlTarValidated)) control = true;
            else if (name.StartsWith("data.tar", StringComparison.Ordinal) && size > 0 &&
                     TryValidateDebTarMember(name, src.Slice((int)dataOffset, (int)size), out dataTarValidated)) data = true;
            cursor = (int)next;
            member++;
            if (version && control && data) break;
        }
        if (!version || !control || !data) return false;
        result = BinaryResult("deb", "application/vnd.debian.binary-package", "deb:ar-members");
        if (!controlTarValidated || !dataTarValidated)
        {
            result.Confidence = "Medium";
            result.Reason += ";compressed-member-signatures";
        }
        return true;
    }

    internal static bool TryMatchVhdx(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 1024 * 1024 || !src.Slice(0, 8).SequenceEqual("vhdxfile"u8)) return false;
        bool header = TryValidateVhdxHeader(src.Slice(64 * 1024, 4096)) || TryValidateVhdxHeader(src.Slice(128 * 1024, 4096));
        bool region = TryValidateVhdxRegionTable(src.Slice(192 * 1024, 64 * 1024), src.Length) ||
                      TryValidateVhdxRegionTable(src.Slice(256 * 1024, 64 * 1024), src.Length);
        if (!header || !region) return false;
        result = BinaryResult("vhdx", "application/x-vhdx", "vhdx:file+header+region");
        return true;
    }

    internal static bool TryMatchVhd(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 512) return false;
        return TryMatchVhdContainer(src, src.Slice(src.Length - 512, 512), out result);
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
        if (!encrypted)
        {
            if (footerLength > Math.Max(256, Settings.DetectionReadBudgetBytes))
            {
                result = BinaryResult("parquet", "application/vnd.apache.parquet", "parquet:framed;footer-budget");
                result.Confidence = "Medium";
                return true;
            }
            if (!TryReadAt(stream, stream.Length - 8 - footerLength, (int)footerLength, out var footer) ||
                !TryValidateParquetMetadata(new ReadOnlySpan<byte>(footer))) return false;
        }
        result = BinaryResult("parquet", "application/vnd.apache.parquet", encrypted ? "parquet:encrypted-footer" : "parquet:footer");
        if (encrypted) result.Confidence = "Medium";
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
        if (footerStart < 8) return false;
        if (footerLength > Math.Max(256, Settings.DetectionReadBudgetBytes))
        {
            result = BinaryResult("arrow", "application/vnd.apache.arrow.file", "arrow-ipc:framed;footer-budget");
            result.Confidence = "Medium";
            return true;
        }
        if (!TryReadAt(stream, footerStart, (int)footerLength, out var footerBytes) ||
            !TryValidateArrowFooter(new ReadOnlySpan<byte>(footerBytes))) return false;
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
        bool controlTarValidated = false;
        bool dataTarValidated = false;
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
            else if (name.StartsWith("control.tar", StringComparison.Ordinal) && size > 0 &&
                     TryValidateDebTarMember(stream, name, dataOffset, size, out controlTarValidated)) control = true;
            else if (name.StartsWith("data.tar", StringComparison.Ordinal) && size > 0 &&
                     TryValidateDebTarMember(stream, name, dataOffset, size, out dataTarValidated)) data = true;
            cursor = next;
            if (version && control && data) break;
        }
        if (!version || !control || !data) return false;
        result = BinaryResult("deb", "application/vnd.debian.binary-package", "deb:ar-members");
        if (!controlTarValidated || !dataTarValidated)
        {
            result.Confidence = "Medium";
            result.Reason += ";compressed-member-signatures";
        }
        return true;
    }

    private static bool TryValidateDebTarMember(Stream stream, string name, long offset, long length, out bool tarValidated)
    {
        tarValidated = false;
        int prefixLength = (int)Math.Min(length, 512);
        return prefixLength > 0 && TryReadAt(stream, offset, prefixLength, out var prefix) &&
               TryValidateDebTarMember(name, new ReadOnlySpan<byte>(prefix), out tarValidated, length);
    }

    private static bool TryValidateDebTarMember(string name, ReadOnlySpan<byte> payload, out bool tarValidated, long? completeLength = null)
    {
        tarValidated = false;
        long length = completeLength ?? payload.Length;
        if (name is "control.tar" or "data.tar")
        {
            if (length < 265 || payload.Length < 265 || !TryMatchTar(payload, out _)) return false;
            tarValidated = true;
            return true;
        }
        if (name.EndsWith(".tar.gz", StringComparison.Ordinal)) return length >= 10 && payload.Length >= 10 && TryMatchGzip(payload, out _);
        if (name.EndsWith(".tar.bz2", StringComparison.Ordinal)) return length >= 10 && payload.Length >= 10 && TryMatchBzip2(payload, out _);
        if (name.EndsWith(".tar.xz", StringComparison.Ordinal))
            return length >= 6 && payload.Length >= 6 && payload.Slice(0, 6).SequenceEqual(new byte[] { 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00 });
        if (name.EndsWith(".tar.zst", StringComparison.Ordinal))
            return length >= 4 && payload.Length >= 4 && ReadUInt32LittleEndian(payload, 0) == 0xFD2FB528;
        return false;
    }

    private static bool TryMatchVhdx(Stream stream, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (stream.Length < 1024 * 1024 || !TryReadAt(stream, 0, 8, out var signature) || !new ReadOnlySpan<byte>(signature).SequenceEqual("vhdxfile"u8)) return false;
        bool header = TryReadAt(stream, 64 * 1024, 4096, out var header1) && TryValidateVhdxHeader(new ReadOnlySpan<byte>(header1)) ||
                      TryReadAt(stream, 128 * 1024, 4096, out var header2) && TryValidateVhdxHeader(new ReadOnlySpan<byte>(header2));
        bool region = TryReadAt(stream, 192 * 1024, 64 * 1024, out var region1) && TryValidateVhdxRegionTable(new ReadOnlySpan<byte>(region1), stream.Length) ||
                      TryReadAt(stream, 256 * 1024, 64 * 1024, out var region2) && TryValidateVhdxRegionTable(new ReadOnlySpan<byte>(region2), stream.Length);
        if (!header || !region) return false;
        result = BinaryResult("vhdx", "application/x-vhdx", "vhdx:file+header+region");
        return true;
    }

    private static bool TryMatchVhd(Stream stream, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (stream.Length < 512 || !TryReadAt(stream, stream.Length - 512, 512, out var footer)) return false;
        return TryMatchVhdContainer(stream, new ReadOnlySpan<byte>(footer), out result);
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

    private static bool TryMatchVhdContainer(ReadOnlySpan<byte> file, ReadOnlySpan<byte> footer, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (!TryValidateVhdFooter(footer, out uint diskType, out ulong dataOffset, out ulong currentSize)) return false;
        if (diskType == 2)
        {
            if (dataOffset != ulong.MaxValue || currentSize > int.MaxValue || currentSize + 512UL != (ulong)file.Length) return false;
        }
        else
        {
            if (dataOffset > int.MaxValue || dataOffset + 1024UL > (ulong)file.Length ||
                !TryValidateVhdDynamicHeader(file.Slice((int)dataOffset, 1024), file.Length, diskType, currentSize)) return false;
        }
        result = BinaryResult("vhd", "application/x-vhd", $"vhd:footer;type={diskType}");
        return true;
    }

    private static bool TryMatchVhdContainer(Stream stream, ReadOnlySpan<byte> footer, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (!TryValidateVhdFooter(footer, out uint diskType, out ulong dataOffset, out ulong currentSize)) return false;
        if (diskType == 2)
        {
            if (dataOffset != ulong.MaxValue || currentSize > long.MaxValue || currentSize + 512UL != (ulong)stream.Length) return false;
        }
        else
        {
            if (dataOffset > long.MaxValue || dataOffset + 1024UL > (ulong)stream.Length ||
                !TryReadAt(stream, (long)dataOffset, 1024, out var dynamicHeader) ||
                !TryValidateVhdDynamicHeader(new ReadOnlySpan<byte>(dynamicHeader), stream.Length, diskType, currentSize)) return false;
        }
        result = BinaryResult("vhd", "application/x-vhd", $"vhd:footer;type={diskType}");
        return true;
    }

    private static bool TryValidateVhdFooter(ReadOnlySpan<byte> footer, out uint diskType, out ulong dataOffset, out ulong currentSize)
    {
        diskType = 0;
        dataOffset = 0;
        currentSize = 0;
        if (footer.Length != 512 || !footer.Slice(0, 8).SequenceEqual("conectix"u8) ||
            (ReadUInt32BigEndian(footer, 8) & 0xFFFFFFFCu) != 0 || (ReadUInt32BigEndian(footer, 8) & 2) == 0 ||
            ReadUInt32BigEndian(footer, 12) != 0x00010000 || footer[84] > 1) return false;
        dataOffset = ReadUInt64(footer, 16, littleEndian: false);
        ulong originalSize = ReadUInt64(footer, 40, littleEndian: false);
        currentSize = ReadUInt64(footer, 48, littleEndian: false);
        uint geometry = ReadUInt32BigEndian(footer, 56);
        diskType = ReadUInt32BigEndian(footer, 60);
        bool uniqueId = false;
        for (int index = 68; index < 84; index++) uniqueId |= footer[index] != 0;
        if (diskType is < 2 or > 4 || originalSize == 0 || currentSize == 0 ||
            (originalSize & 511) != 0 || (currentSize & 511) != 0 ||
            geometry == 0 || (geometry >> 16) == 0 || ((geometry >> 8) & 0xFF) is 0 or > 16 || (geometry & 0xFF) == 0 || !uniqueId) return false;
        return ComputeVhdChecksum(footer, 64) == ReadUInt32BigEndian(footer, 64);
    }

    private static bool TryValidateVhdDynamicHeader(ReadOnlySpan<byte> header, long fileLength, uint diskType, ulong currentSize)
    {
        if (header.Length != 1024 || !header.Slice(0, 8).SequenceEqual("cxsparse"u8) ||
            ReadUInt64(header, 8, littleEndian: false) != ulong.MaxValue || ReadUInt32BigEndian(header, 24) != 0x00010000 ||
            ComputeVhdChecksum(header, 36) != ReadUInt32BigEndian(header, 36)) return false;
        ulong tableOffset = ReadUInt64(header, 16, littleEndian: false);
        uint entries = ReadUInt32BigEndian(header, 28);
        uint blockSize = ReadUInt32BigEndian(header, 32);
        ulong tableLength = ((ulong)entries * 4 + 511) & ~511UL;
        ulong requiredEntries = blockSize == 0 ? ulong.MaxValue :
            currentSize / blockSize + (currentSize % blockSize == 0 ? 0UL : 1UL);
        if (entries == 0 || blockSize < 512 * 1024 || (blockSize & (blockSize - 1)) != 0 ||
            requiredEntries > entries ||
            tableOffset < 1536 || (tableOffset & 511) != 0 || tableOffset > (ulong)fileLength || tableLength > (ulong)fileLength - tableOffset) return false;
        if (diskType == 4)
        {
            bool parentId = false;
            for (int index = 40; index < 56; index++) parentId |= header[index] != 0;
            if (!parentId) return false;
        }
        return true;
    }

    private static uint ComputeVhdChecksum(ReadOnlySpan<byte> data, int checksumOffset)
    {
        uint sum = 0;
        for (int index = 0; index < data.Length; index++)
            if (index < checksumOffset || index >= checksumOffset + 4) sum += data[index];
        return ~sum;
    }

    private static bool TryValidateParquetMetadata(ReadOnlySpan<byte> metadata)
    {
        int cursor = 0;
        short previousField = 0;
        var fields = new System.Collections.Generic.HashSet<short>();
        bool version = false, schema = false, rows = false, rowGroups = false;
        while (cursor < metadata.Length)
        {
            byte header = metadata[cursor++];
            if (header == 0) break;
            int type = header & 0x0F;
            int delta = header >> 4;
            int decodedField = delta == 0 ? ReadCompactFieldId(metadata, ref cursor) : previousField + delta;
            if (decodedField is <= 0 or > short.MaxValue) return false;
            short field = (short)decodedField;
            if (!fields.Add(field)) return false;
            previousField = field;
            if (field == 1) { if (type != 5 || !SkipCompactValue(metadata, ref cursor, type, 0)) return false; version = true; }
            else if (field == 2) { if (type != 9 || !SkipCompactList(metadata, ref cursor, requireNonEmpty: true, 0)) return false; schema = true; }
            else if (field == 3) { if (type != 6 || !SkipCompactValue(metadata, ref cursor, type, 0)) return false; rows = true; }
            else if (field == 4) { if (type != 9 || !SkipCompactList(metadata, ref cursor, requireNonEmpty: false, 0)) return false; rowGroups = true; }
            else if (!SkipCompactValue(metadata, ref cursor, type, 0)) return false;
        }
        return cursor == metadata.Length && version && schema && rows && rowGroups;
    }

    private static short ReadCompactFieldId(ReadOnlySpan<byte> src, ref int cursor)
    {
        return TryReadCompactVarint(src, ref cursor, out ulong value) && value <= ushort.MaxValue
            ? (short)((long)(value >> 1) ^ -(long)(value & 1)) : (short)-1;
    }

    private static bool SkipCompactList(ReadOnlySpan<byte> src, ref int cursor, bool requireNonEmpty, int depth)
    {
        if (cursor >= src.Length || depth > 8) return false;
        byte header = src[cursor++];
        int count = header >> 4;
        int elementType = header & 0x0F;
        if (count == 15)
        {
            if (!TryReadCompactVarint(src, ref cursor, out ulong longCount) || longCount > int.MaxValue) return false;
            count = (int)longCount;
        }
        if (requireNonEmpty && count == 0) return false;
        if (count > src.Length - cursor) return false;
        if (elementType is 1 or 2)
        {
            for (int i = 0; i < count; i++)
                if (src[cursor++] is not (1 or 2)) return false;
            return true;
        }
        for (int i = 0; i < count; i++) if (!SkipCompactValue(src, ref cursor, elementType, depth + 1)) return false;
        return true;
    }

    private static bool SkipCompactValue(ReadOnlySpan<byte> src, ref int cursor, int type, int depth)
    {
        if (depth > 8) return false;
        if (type is 1 or 2) return true;
        if (type is 3) return cursor++ < src.Length;
        if (type is 4 or 5 or 6) return TryReadCompactVarint(src, ref cursor, out _);
        if (type == 7) { if (cursor + 8 > src.Length) return false; cursor += 8; return true; }
        if (type == 8) { if (!TryReadCompactVarint(src, ref cursor, out ulong length) || length > (ulong)(src.Length - cursor)) return false; cursor += (int)length; return true; }
        if (type == 9) return SkipCompactList(src, ref cursor, false, depth + 1);
        if (type == 12)
        {
            short previous = 0;
            var fields = new System.Collections.Generic.HashSet<short>();
            while (cursor < src.Length)
            {
                byte header = src[cursor++];
                if (header == 0) return true;
                int delta = header >> 4;
                int decodedField = delta == 0 ? ReadCompactFieldId(src, ref cursor) : previous + delta;
                if (decodedField is <= 0 or > short.MaxValue) return false;
                short field = (short)decodedField;
                if (!fields.Add(field) || !SkipCompactValue(src, ref cursor, header & 0x0F, depth + 1)) return false;
                previous = field;
            }
        }
        return false;
    }

    private static bool TryReadCompactVarint(ReadOnlySpan<byte> src, ref int cursor, out ulong value)
    {
        value = 0;
        for (int shift = 0; shift < 64 && cursor < src.Length; shift += 7)
        {
            byte current = src[cursor++];
            value |= (ulong)(current & 0x7F) << shift;
            if ((current & 0x80) == 0) return true;
        }
        return false;
    }

    private static bool TryValidateArrowFooter(ReadOnlySpan<byte> footer)
    {
        if (footer.Length < 16) return false;
        uint root = ReadUInt32LittleEndian(footer, 0);
        if (root > int.MaxValue || root + 8 > footer.Length) return false;
        int table = (int)root;
        if (!TryGetArrowVtable(footer, table, 8, out int vtable, out ushort objectLength)) return false;
        ushort versionOffset = ReadUInt16LittleEndian(footer, vtable + 4);
        ushort schemaOffset = ReadUInt16LittleEndian(footer, vtable + 6);
        if (objectLength < 8 || versionOffset == 0 || schemaOffset == 0 ||
            versionOffset + 2 > objectLength || schemaOffset + 4 > objectLength) return false;
        ushort version = ReadUInt16LittleEndian(footer, table + versionOffset);
        if (version > 4) return false;
        uint schemaRelative = ReadUInt32LittleEndian(footer, table + schemaOffset);
        ulong schemaTableValue = (ulong)table + schemaOffset + schemaRelative;
        if (schemaRelative < 4 || schemaTableValue + 4 > (ulong)footer.Length) return false;
        int schemaTable = (int)schemaTableValue;
        return TryGetArrowVtable(footer, schemaTable, 4, out _, out _);
    }

    private static bool TryGetArrowVtable(ReadOnlySpan<byte> footer, int table, int minimumVtableLength,
        out int vtable, out ushort objectLength)
    {
        vtable = 0;
        objectLength = 0;
        if (table < 0 || table + 4 > footer.Length) return false;
        int displacement = unchecked((int)ReadUInt32LittleEndian(footer, table));
        if (displacement == 0) return false;
        long vtableLocation = (long)table - displacement;
        if (vtableLocation < 0 || vtableLocation > int.MaxValue || vtableLocation + 4 > footer.Length) return false;
        vtable = (int)vtableLocation;
        ushort vtableLength = ReadUInt16LittleEndian(footer, vtable);
        objectLength = ReadUInt16LittleEndian(footer, vtable + 2);
        return vtableLength >= minimumVtableLength && vtable + vtableLength <= footer.Length &&
               objectLength >= 4 && table + objectLength <= footer.Length;
    }

    private static bool TryValidateVhdxHeader(ReadOnlySpan<byte> header)
    {
        if (header.Length != 4096 || !header.Slice(0, 4).SequenceEqual("head"u8) ||
            ReadUInt16LittleEndian(header, 64) != 0 || ReadUInt16LittleEndian(header, 66) != 1 ||
            ReadUInt64(header, 8, true) == 0) return false;
        uint stored = ReadUInt32LittleEndian(header, 4);
        return stored != 0 && ComputeCrc32C(header, 4, 4) == stored;
    }

    private static bool TryValidateVhdxRegionTable(ReadOnlySpan<byte> table, long fileLength)
    {
        if (table.Length != 64 * 1024 || !table.Slice(0, 4).SequenceEqual("regi"u8)) return false;
        uint entries = ReadUInt32LittleEndian(table, 8);
        if (entries is < 1 or > 2047 || ReadUInt32LittleEndian(table, 12) != 0 ||
            ComputeCrc32C(table, 4, 4) != ReadUInt32LittleEndian(table, 4)) return false;
        bool bat = false;
        bool metadata = false;
        ulong batOffset = 0, batEnd = 0, metadataOffset = 0, metadataEnd = 0;
        var batGuid = new byte[] { 0x66, 0x77, 0xC2, 0x2D, 0x23, 0xF6, 0x00, 0x42, 0x9D, 0x64, 0x11, 0x5E, 0x9B, 0xFD, 0x4A, 0x08 };
        var metadataGuid = new byte[] { 0x06, 0xA2, 0x7C, 0x8B, 0x90, 0x47, 0x9A, 0x4B, 0xB8, 0xFE, 0x57, 0x5F, 0x05, 0x0F, 0x88, 0x6E };
        for (uint i = 0; i < entries; i++)
        {
            int offset = checked(16 + (int)i * 32);
            var guid = table.Slice(offset, 16);
            ulong fileOffset = ReadUInt64(table, offset + 16, true);
            uint length = ReadUInt32LittleEndian(table, offset + 24);
            uint flags = ReadUInt32LittleEndian(table, offset + 28);
            if (length == 0 || (length & 0xFFFFF) != 0 || fileOffset < 0x100000 || (fileOffset & 0xFFFFF) != 0 ||
                fileOffset > (ulong)fileLength || length > (ulong)fileLength - fileOffset || flags > 1) return false;
            ulong end = fileOffset + length;
            if (guid.SequenceEqual(batGuid))
            {
                if (bat || flags != 1) return false;
                bat = true;
                batOffset = fileOffset;
                batEnd = end;
            }
            else if (guid.SequenceEqual(metadataGuid))
            {
                if (metadata || flags != 1) return false;
                metadata = true;
                metadataOffset = fileOffset;
                metadataEnd = end;
            }
            else if (flags == 1) return false;
        }
        return bat && metadata && (batEnd <= metadataOffset || metadataEnd <= batOffset);
    }

    private static uint ComputeCrc32C(ReadOnlySpan<byte> data, int zeroOffset, int zeroLength)
    {
        uint crc = uint.MaxValue;
        for (int i = 0; i < data.Length; i++)
        {
            byte value = i >= zeroOffset && i < zeroOffset + zeroLength ? (byte)0 : data[i];
            crc ^= value;
            for (int bit = 0; bit < 8; bit++) crc = (crc & 1) != 0 ? (crc >> 1) ^ 0x82F63B78u : crc >> 1;
        }
        return ~crc;
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
