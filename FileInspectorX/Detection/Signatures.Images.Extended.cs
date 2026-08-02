namespace FileInspectorX;

/// <summary>
/// Structured image formats not covered by the core signature table.
/// </summary>
internal static partial class Signatures {
    internal static bool TryMatchOpenExr(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
        => TryMatchOpenExr(src, src.Length, out result);

    internal static bool TryMatchOpenExr(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result) {
        result = null;
        if (completeLength < 0 || src.Length < 8 || src[0] != 0x76 || src[1] != 0x2F || src[2] != 0x31 || src[3] != 0x01)
            return false;

        uint versionField = ReadUInt32(src, 4, littleEndian: true);
        const uint AllowedFlags = 0x00001E00;
        if ((versionField & 0xFF) != 2 || (versionField & ~(AllowedFlags | 0xFFu)) != 0) return false;
        bool tiled = (versionField & 0x00000200) != 0;
        bool multipart = (versionField & 0x00001000) != 0;
        bool deep = (versionField & 0x00000800) != 0;
        if (tiled && multipart) return false;

        int cursor = 8;
        bool sawAnyPart = false;
        ulong totalChunkCount = 0;
        var partLayouts = new System.Collections.Generic.List<OpenExrPartLayout>();
        var multipartPartNames = new System.Collections.Generic.HashSet<string>();
        while (true)
        {
            bool channels = false;
            bool compression = false;
            bool dataWindow = false;
            bool displayWindow = false;
            bool lineOrder = false;
            bool pixelAspectRatio = false;
            bool screenWindowCenter = false;
            bool screenWindowWidth = false;
            bool tiles = !tiled && !multipart;
            bool nameAttribute = false;
            bool typeAttribute = false;
            bool chunkCount = false;
            bool partRequiresTiles = tiled;
            bool partIsDeep = deep;
            bool sawAttribute = false;
            byte compressionValue = 0;
            int dataMinX = 0, dataMinY = 0, dataMaxX = -1, dataMaxY = -1;
            uint tileWidth = 0, tileHeight = 0;
            byte tileMode = 0;
            uint declaredChunkCount = 0;
            var attributeNames = new System.Collections.Generic.HashSet<string>();

            while (true)
            {
                if (cursor >= src.Length)
                    return TryReturnSampledOpenExr(completeLength, src.Length, sawAttribute || sawAnyPart, out result);
                if (src[cursor] == 0)
                {
                    cursor++;
                    if (!HasMandatoryOpenExrAttributes(channels, compression, dataWindow, displayWindow, lineOrder,
                            pixelAspectRatio, screenWindowCenter, screenWindowWidth,
                            tiles || (multipart && !partRequiresTiles)) ||
                        (multipart && (!nameAttribute || !typeAttribute || !chunkCount || (partRequiresTiles && !tiles))))
                        return false;
                    sawAnyPart = true;
                    break;
                }

                if (!TryReadOpenExrString(src, ref cursor, out string name) ||
                    !TryReadOpenExrString(src, ref cursor, out string type) || cursor + 4 > src.Length)
                    return TryReturnSampledOpenExr(completeLength, src.Length, sawAttribute || sawAnyPart, out result);
                if (!attributeNames.Add(name)) return false;
                uint valueLength = ReadUInt32(src, cursor, littleEndian: true);
                cursor += 4;
                if (valueLength == 0 || valueLength > int.MaxValue) return false;
                sawAttribute = true;

                if (completeLength.HasValue && (ulong)cursor + valueLength > (ulong)completeLength.Value) return false;
                if ((ulong)cursor + valueLength > (ulong)src.Length)
                    return TryReturnSampledOpenExr(completeLength, src.Length, true, out result);
                var value = src.Slice(cursor, (int)valueLength);
                if (!TryValidateOpenExrAttribute(name, type, value, out bool mandatory)) return false;
                channels |= mandatory && name == "channels";
                compression |= mandatory && name == "compression";
                dataWindow |= mandatory && name == "dataWindow";
                displayWindow |= mandatory && name == "displayWindow";
                lineOrder |= mandatory && name == "lineOrder";
                pixelAspectRatio |= mandatory && name == "pixelAspectRatio";
                screenWindowCenter |= mandatory && name == "screenWindowCenter";
                screenWindowWidth |= mandatory && name == "screenWindowWidth";
                tiles |= mandatory && name == "tiles";
                if (mandatory && name == "compression") compressionValue = value[0];
                if (mandatory && name == "dataWindow")
                {
                    dataMinX = (int)ReadUInt32(value, 0, true);
                    dataMinY = (int)ReadUInt32(value, 4, true);
                    dataMaxX = (int)ReadUInt32(value, 8, true);
                    dataMaxY = (int)ReadUInt32(value, 12, true);
                }
                if (mandatory && name == "tiles")
                {
                    tileWidth = ReadUInt32(value, 0, true);
                    tileHeight = ReadUInt32(value, 4, true);
                    tileMode = (byte)(value[8] & 3);
                }
                if (multipart && name == "name")
                {
                    nameAttribute = TryValidateOpenExrTextAttribute(type, value);
                    if (nameAttribute && !multipartPartNames.Add(System.Text.Encoding.ASCII.GetString(value.ToArray()))) return false;
                }
                if (multipart && name == "type")
                {
                    typeAttribute = TryValidateOpenExrTextAttribute(type, value);
                    if (typeAttribute)
                    {
                        string partType = System.Text.Encoding.ASCII.GetString(value.ToArray());
                        if (partType is not ("scanlineimage" or "tiledimage" or "deepscanline" or "deeptile")) return false;
                        partRequiresTiles = partType is "tiledimage" or "deeptile";
                        partIsDeep = partType is "deepscanline" or "deeptile";
                    }
                }
                if (multipart && name == "chunkCount")
                {
                    declaredChunkCount = type == "int" && value.Length == 4 ? ReadUInt32(value, 0, true) : 0;
                    chunkCount = declaredChunkCount > 0;
                }
                cursor += (int)valueLength;
            }

            ulong partChunks;
            if (multipart)
            {
                partChunks = declaredChunkCount;
            }
            else if (partRequiresTiles)
            {
                if (tileMode != 0) return TryReturnUnsupportedOpenExrLevelLayout(out result);
                ulong width = (ulong)((long)dataMaxX - dataMinX + 1);
                ulong height = (ulong)((long)dataMaxY - dataMinY + 1);
                ulong horizontalChunks = DivideRoundUp(width, tileWidth);
                ulong verticalChunks = DivideRoundUp(height, tileHeight);
                if (horizontalChunks == 0 || verticalChunks == 0 || horizontalChunks > ulong.MaxValue / verticalChunks) return false;
                partChunks = horizontalChunks * verticalChunks;
            }
            else
            {
                ulong height = (ulong)((long)dataMaxY - dataMinY + 1);
                partChunks = DivideRoundUp(height, GetOpenExrScanLinesPerChunk(compressionValue));
            }
            if (partChunks == 0 || totalChunkCount > ulong.MaxValue - partChunks) return false;
            partLayouts.Add(new OpenExrPartLayout(partRequiresTiles, partIsDeep, partChunks,
                dataMinX, dataMinY, dataMaxX, dataMaxY, tileWidth, tileHeight, tileMode,
                GetOpenExrScanLinesPerChunk(compressionValue)));
            totalChunkCount += partChunks;

            if (!multipart) break;
            if (cursor >= src.Length) return TryReturnSampledOpenExr(completeLength, src.Length, true, out result);
            if (src[cursor] == 0)
            {
                cursor++;
                break;
            }
        }

        if (!TryValidateOpenExrChunkFraming(src, cursor, completeLength, totalChunkCount,
                multipart, partLayouts, out bool chunkFramingValidated))
            return false;

        result = new ContentTypeDetectionResult {
            Extension = "exr",
            MimeType = "image/x-exr",
            Confidence = "Medium",
            Reason = "openexr:v2" + (chunkFramingValidated
                ? ";chunk-framing;chunk-payloads-not-validated"
                : ";sampled-chunk-framing")
        };
        return true;
    }

    private static ulong DivideRoundUp(ulong value, ulong divisor)
        => divisor == 0 || value > ulong.MaxValue - (divisor - 1) ? 0 : (value + divisor - 1) / divisor;

    private static uint GetOpenExrScanLinesPerChunk(byte compression)
        => compression switch { 3 or 5 => 16, 4 or 6 or 7 or 8 or 11 => 32, 9 or 10 => 256, _ => 1 };

    private readonly struct OpenExrPartLayout
    {
        internal OpenExrPartLayout(bool tiled, bool deep, ulong chunkCount, int minX, int minY, int maxX, int maxY,
            uint tileWidth, uint tileHeight, byte tileMode, uint scanLinesPerChunk)
        {
            Tiled = tiled; Deep = deep; ChunkCount = chunkCount; MinX = minX; MinY = minY; MaxX = maxX; MaxY = maxY;
            TileWidth = tileWidth; TileHeight = tileHeight; TileMode = tileMode; ScanLinesPerChunk = scanLinesPerChunk;
        }
        internal bool Tiled { get; }
        internal bool Deep { get; }
        internal ulong ChunkCount { get; }
        internal int MinX { get; }
        internal int MinY { get; }
        internal int MaxX { get; }
        internal int MaxY { get; }
        internal uint TileWidth { get; }
        internal uint TileHeight { get; }
        internal byte TileMode { get; }
        internal uint ScanLinesPerChunk { get; }
    }

    private static bool TryValidateOpenExrChunkFraming(ReadOnlySpan<byte> src, int tableOffset, long? completeLength,
        ulong chunkCount, bool multipart, System.Collections.Generic.List<OpenExrPartLayout> partLayouts,
        out bool fullyValidated)
    {
        fullyValidated = false;
        if (chunkCount == 0 || chunkCount > (ulong)int.MaxValue / 8 || partLayouts.Count == 0 ||
            (!multipart && partLayouts.Count != 1)) return false;
        ulong tableEnd = (ulong)tableOffset + chunkCount * 8;
        if (completeLength.HasValue && tableEnd > (ulong)completeLength.Value) return false;
        if (tableEnd > (ulong)src.Length)
            return !completeLength.HasValue || completeLength.Value > src.Length;

        ulong offsetBudget = (ulong)Math.Max(1, Settings.DetectionReadBudgetBytes / 8);
        ulong inspectedOffsetCount = Math.Min(chunkCount, offsetBudget);
        var offsets = new System.Collections.Generic.HashSet<ulong>();
        for (ulong index = 0; index < inspectedOffsetCount; index++) {
            ulong offset = ReadUInt64(src, tableOffset + checked((int)(index * 8)), true);
            if (!offsets.Add(offset) || offset < tableEnd ||
                completeLength.HasValue && (offset > (ulong)completeLength.Value ||
                    (ulong)(multipart ? 4 : 8) > (ulong)completeLength.Value - offset)) return false;
        }
        if (inspectedOffsetCount != chunkCount) return true;
        ulong chunkBudget = (ulong)Math.Max(1, Settings.DetectionReadBudgetBytes / 8);
        if (chunkCount > chunkBudget) return true;
        var ranges = new System.Collections.Generic.List<(ulong Start, ulong End)>((int)chunkCount);
        var partChunkCounts = new ulong[partLayouts.Count];
        var partCoordinates = new System.Collections.Generic.HashSet<string>[partLayouts.Count];
        for (int part = 0; part < partCoordinates.Length; part++) partCoordinates[part] = new System.Collections.Generic.HashSet<string>();
        foreach (ulong offset in offsets) {
            if (offset > int.MaxValue || offset + (ulong)(multipart ? 4 : 8) > (ulong)src.Length)
                return !completeLength.HasValue || completeLength.Value > src.Length;
            int chunk = (int)offset;
            int partNumber = multipart ? unchecked((int)ReadUInt32(src, chunk, true)) : 0;
            if (partNumber < 0 || partNumber >= partLayouts.Count) return false;
            partChunkCounts[partNumber]++;
            OpenExrPartLayout layout = partLayouts[partNumber];
            int partPrefix = multipart ? 4 : 0;
            int sizeOffset = partPrefix + (layout.Tiled ? 16 : 4);
            int chunkHeaderLength = partPrefix + (layout.Tiled ? (layout.Deep ? 40 : 20) : (layout.Deep ? 28 : 8));
            if (completeLength.HasValue && (ulong)chunkHeaderLength > (ulong)completeLength.Value - offset) return false;
            if (offset + (ulong)chunkHeaderLength > (ulong)src.Length)
                return !completeLength.HasValue || completeLength.Value > src.Length;
            if (layout.Tiled)
            {
                int tileX = unchecked((int)ReadUInt32(src, chunk + partPrefix, true));
                int tileY = unchecked((int)ReadUInt32(src, chunk + partPrefix + 4, true));
                int levelX = unchecked((int)ReadUInt32(src, chunk + partPrefix + 8, true));
                int levelY = unchecked((int)ReadUInt32(src, chunk + partPrefix + 12, true));
                if (tileX < 0 || tileY < 0 || levelX < 0 || levelY < 0) return false;
                if (layout.TileMode == 0)
                {
                    ulong tilesX = DivideRoundUp((ulong)((long)layout.MaxX - layout.MinX + 1), layout.TileWidth);
                    ulong tilesY = DivideRoundUp((ulong)((long)layout.MaxY - layout.MinY + 1), layout.TileHeight);
                    if (levelX != 0 || levelY != 0 || (ulong)tileX >= tilesX || (ulong)tileY >= tilesY) return false;
                }
                if (!partCoordinates[partNumber].Add(tileX + ":" + tileY + ":" + levelX + ":" + levelY)) return false;
            }
            else
            {
                int scanLine = unchecked((int)ReadUInt32(src, chunk + partPrefix, true));
                long relative = (long)scanLine - layout.MinY;
                if (scanLine < layout.MinY || scanLine > layout.MaxY || relative % layout.ScanLinesPerChunk != 0 ||
                    !partCoordinates[partNumber].Add(scanLine.ToString(System.Globalization.CultureInfo.InvariantCulture))) return false;
            }
            ulong payloadLength;
            if (layout.Deep) {
                ulong offsetTableLength = ReadUInt64(src, chunk + sizeOffset, true);
                ulong sampleDataLength = ReadUInt64(src, chunk + sizeOffset + 8, true);
                if (offsetTableLength > ulong.MaxValue - sampleDataLength) return false;
                payloadLength = offsetTableLength + sampleDataLength;
            } else payloadLength = ReadUInt32(src, chunk + sizeOffset, true);
            if (payloadLength == 0 || offset > ulong.MaxValue - (ulong)chunkHeaderLength - payloadLength) return false;
            ulong payloadEnd = offset + (ulong)chunkHeaderLength + payloadLength;
            if (completeLength.HasValue && payloadEnd > (ulong)completeLength.Value) return false;
            if (payloadEnd > (ulong)src.Length) return !completeLength.HasValue || completeLength.Value > src.Length;
            ranges.Add((offset, payloadEnd));
        }
        for (int part = 0; part < partLayouts.Count; part++)
            if (partChunkCounts[part] != partLayouts[part].ChunkCount) return false;
        ranges.Sort((left, right) => left.Start.CompareTo(right.Start));
        for (int index = 1; index < ranges.Count; index++)
            if (ranges[index].Start < ranges[index - 1].End) return false;
        fullyValidated = true;
        return true;
    }

    private static bool TryReturnUnsupportedOpenExrLevelLayout(out ContentTypeDetectionResult? result)
    {
        result = new ContentTypeDetectionResult {
            Extension = "exr",
            MimeType = "image/x-exr",
            Confidence = "Medium",
            Reason = "openexr:v2;unsupported-level-layout"
        };
        return true;
    }

    private static bool TryValidateOpenExrAttribute(string name, string type, ReadOnlySpan<byte> value, out bool mandatory)
    {
        mandatory = true;
        switch (name)
        {
            case "channels": return type == "chlist" && TryValidateOpenExrChannelList(value);
            case "compression": return type == "compression" && value.Length == 1 && value[0] <= 11;
            case "dataWindow":
            case "displayWindow":
                return type == "box2i" && value.Length == 16 &&
                       (int)ReadUInt32(value, 0, true) <= (int)ReadUInt32(value, 8, true) &&
                       (int)ReadUInt32(value, 4, true) <= (int)ReadUInt32(value, 12, true);
            case "lineOrder": return type == "lineOrder" && value.Length == 1 && value[0] <= 2;
            case "pixelAspectRatio":
            case "screenWindowWidth":
                return type == "float" && value.Length == 4 && IsPositiveFiniteOpenExrFloat(value);
            case "screenWindowCenter":
                return type == "v2f" && value.Length == 8 && IsFiniteOpenExrFloat(value.Slice(0, 4)) && IsFiniteOpenExrFloat(value.Slice(4, 4));
            case "tiles":
                return type == "tiledesc" && value.Length == 9 && ReadUInt32(value, 0, true) > 0 &&
                       ReadUInt32(value, 4, true) > 0 && (value[8] & ~0x13) == 0 && (value[8] & 3) <= 2;
            default:
                mandatory = false;
                return true;
        }
    }

    private static bool TryValidateOpenExrChannelList(ReadOnlySpan<byte> value)
    {
        int cursor = 0;
        int channels = 0;
        var channelNames = new System.Collections.Generic.HashSet<string>();
        while (cursor < value.Length && value[cursor] != 0)
        {
            int nameStart = cursor;
            while (cursor < value.Length && value[cursor] != 0 && cursor - nameStart < 255) cursor++;
            if (cursor >= value.Length || cursor == nameStart || cursor + 17 > value.Length) return false;
            string channelName = System.Text.Encoding.ASCII.GetString(value.Slice(nameStart, cursor - nameStart).ToArray());
            if (!channelNames.Add(channelName)) return false;
            cursor++;
            uint pixelType = ReadUInt32(value, cursor, true);
            if (pixelType > 2 || value[cursor + 4] > 1 || value[cursor + 5] != 0 || value[cursor + 6] != 0 || value[cursor + 7] != 0 ||
                ReadUInt32(value, cursor + 8, true) == 0 || ReadUInt32(value, cursor + 12, true) == 0) return false;
            cursor += 16;
            channels++;
        }
        return channels > 0 && cursor == value.Length - 1 && value[cursor] == 0;
    }

    private static bool TryValidateOpenExrTextAttribute(string type, ReadOnlySpan<byte> value)
    {
        if (type != "string" || value.Length == 0) return false;
        for (int i = 0; i < value.Length; i++)
            if (value[i] < 0x20 || value[i] > 0x7E) return false;
        return true;
    }

    private static bool IsPositiveFiniteOpenExrFloat(ReadOnlySpan<byte> value)
    {
        uint bits = ReadUInt32(value, 0, true);
        return (bits & 0x80000000u) == 0 && (bits & 0x7FFFFFFFu) != 0 && (bits & 0x7F800000u) != 0x7F800000u;
    }

    private static bool IsFiniteOpenExrFloat(ReadOnlySpan<byte> value)
    {
        uint bits = ReadUInt32(value, 0, true);
        return (bits & 0x7F800000u) != 0x7F800000u;
    }

    private static bool TryReadOpenExrString(ReadOnlySpan<byte> src, ref int cursor, out string value)
    {
        value = string.Empty;
        int start = cursor;
        while (cursor < src.Length && src[cursor] != 0)
        {
            if (src[cursor] < 0x20 || src[cursor] > 0x7E || cursor - start >= 255) return false;
            cursor++;
        }
        if (cursor >= src.Length || cursor == start) return false;
        value = System.Text.Encoding.ASCII.GetString(src.Slice(start, cursor - start).ToArray());
        cursor++;
        return true;
    }

    private static bool HasMandatoryOpenExrAttributes(bool channels, bool compression, bool dataWindow,
        bool displayWindow, bool lineOrder, bool pixelAspectRatio, bool screenWindowCenter,
        bool screenWindowWidth, bool tiles)
        => channels && compression && dataWindow && displayWindow && lineOrder && pixelAspectRatio &&
           screenWindowCenter && screenWindowWidth && tiles;

    private static bool TryReturnSampledOpenExr(long? completeLength, int sampledLength, bool sawAttribute,
        out ContentTypeDetectionResult? result)
    {
        result = null;
        if (!sawAttribute || completeLength.HasValue && completeLength.Value <= sampledLength) return false;
        result = new ContentTypeDetectionResult {
            Extension = "exr",
            MimeType = "image/x-exr",
            Confidence = "Medium",
            Reason = "openexr:v2;sampled-attribute-header"
        };
        return true;
    }

    internal static bool TryMatchPhotoshop(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
        => TryMatchPhotoshop(src, src.Length, out result);

    internal static bool TryMatchPhotoshop(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result) {
        result = null;
        if (src.Length < 26 || src[0] != (byte)'8' || src[1] != (byte)'B' || src[2] != (byte)'P' || src[3] != (byte)'S')
            return false;

        ushort version = ReadUInt16BigEndian(src, 4);
        if (version != 1 && version != 2) return false;
        for (int i = 6; i < 12; i++)
            if (src[i] != 0) return false;

        ushort channels = ReadUInt16BigEndian(src, 12);
        uint height = ReadUInt32BigEndian(src, 14);
        uint width = ReadUInt32BigEndian(src, 18);
        ushort depth = ReadUInt16BigEndian(src, 22);
        ushort colorMode = ReadUInt16BigEndian(src, 24);
        ulong? colorModeDataLength = src.Length >= 30 ? ReadUInt32BigEndian(src, 26) : null;
        uint maximumDimension = version == 1 ? 30000u : 300000u;
        if (channels < 1 || channels > 56 || height < 1 || height > maximumDimension ||
            width < 1 || width > maximumDimension ||
            (depth != 1 && depth != 8 && depth != 16 && depth != 32) ||
            (colorMode != 0 && colorMode != 1 && colorMode != 2 && colorMode != 3 && colorMode != 4 &&
             colorMode != 7 && colorMode != 8 && colorMode != 9) ||
            !IsValidPhotoshopColorMode(channels, depth, colorMode, colorModeDataLength))
            return false;

        int cursor = 26;
        if (!TrySkipPhotoshopSection(src, ref cursor, completeLength, 4) ||
            !TrySkipPhotoshopSection(src, ref cursor, completeLength, 4) ||
            !TrySkipPhotoshopSection(src, ref cursor, completeLength, version == 1 ? 4 : 8)) return false;
        bool imageDataValidated = false;
        if (cursor + 2 > src.Length)
        {
            if (completeLength.HasValue) return false;
        }
        else
        {
            ushort compression = ReadUInt16BigEndian(src, cursor);
            if (compression > 3 || !TryValidatePhotoshopImageData(src, cursor + 2, completeLength,
                    version, channels, height, width, depth, compression, out imageDataValidated)) return false;
        }

        string extension = version == 1 ? "psd" : "psb";
        result = new ContentTypeDetectionResult {
            Extension = extension,
            MimeType = "image/vnd.adobe.photoshop",
            Confidence = imageDataValidated ? "High" : "Medium",
            Reason = "photoshop:" + extension + (imageDataValidated ? string.Empty : ";sampled-image-data")
        };
        return true;
    }

    private static bool TryValidatePhotoshopImageData(ReadOnlySpan<byte> src, int dataOffset, long? completeLength,
        ushort version, ushort channels, uint height, uint width, ushort depth, ushort compression,
        out bool fullyValidated)
    {
        fullyValidated = false;
        ulong rowBytes = ((ulong)width * depth + 7) / 8;
        if (compression == 0)
        {
            ulong requiredLength = (ulong)dataOffset + rowBytes * height * channels;
            if (completeLength.HasValue && requiredLength != (ulong)completeLength.Value) return false;
            fullyValidated = completeLength.HasValue;
            return true;
        }

        if (compression is 2 or 3)
        {
            if (completeLength.HasValue && (ulong)dataOffset + 2 > (ulong)completeLength.Value) return false;
            if (dataOffset + 2 > src.Length) return true;
            if (!IsPhotoshopZlibHeader(src.Slice(dataOffset, 2))) return false;
            // A valid zlib header establishes the compression kind, but it does not prove
            // that the deflate stream is complete or expands to the declared image shape.
            // Keep this structurally plausible identity at reduced confidence.
            return true;
        }

        ulong rowCount = (ulong)channels * height;
        int rowLengthSize = version == 1 ? 2 : 4;
        ulong tableLength = rowCount * (uint)rowLengthSize;
        ulong tableEnd = (ulong)dataOffset + tableLength;
        if (completeLength.HasValue && tableEnd > (ulong)completeLength.Value) return false;
        if (tableEnd > (ulong)src.Length) return true;

        ulong compressedLength = 0;
        for (ulong row = 0; row < rowCount; row++)
        {
            int offset = dataOffset + checked((int)(row * (uint)rowLengthSize));
            uint rowLength = rowLengthSize == 2 ? ReadUInt16BigEndian(src, offset) : ReadUInt32BigEndian(src, offset);
            if (rowLength == 0 || compressedLength > ulong.MaxValue - rowLength) return false;
            compressedLength += rowLength;
        }
        ulong requiredEnd = tableEnd + compressedLength;
        if (requiredEnd < tableEnd || completeLength.HasValue && requiredEnd != (ulong)completeLength.Value) return false;
        if (requiredEnd <= (ulong)src.Length)
        {
            int compressedOffset = checked((int)tableEnd);
            for (ulong row = 0; row < rowCount; row++)
            {
                int lengthOffset = dataOffset + checked((int)(row * (uint)rowLengthSize));
                uint rowLength = rowLengthSize == 2 ? ReadUInt16BigEndian(src, lengthOffset) : ReadUInt32BigEndian(src, lengthOffset);
                if (!TryValidatePhotoshopRleRow(src.Slice(compressedOffset, checked((int)rowLength)), rowBytes)) return false;
                compressedOffset += checked((int)rowLength);
            }
            fullyValidated = completeLength.HasValue;
        }
        return true;
    }

    private static bool TrySkipPhotoshopSection(ReadOnlySpan<byte> src, ref int cursor, long? completeLength, int lengthSize)
    {
        if (cursor + lengthSize > src.Length) return !completeLength.HasValue;
        ulong length = lengthSize == 4 ? ReadUInt32BigEndian(src, cursor) : ReadUInt64(src, cursor, false);
        cursor += lengthSize;
        if (length > int.MaxValue || (completeLength.HasValue && (ulong)cursor + length > (ulong)completeLength.Value)) return false;
        if ((ulong)cursor + length > (ulong)src.Length) return !completeLength.HasValue;
        cursor += (int)length;
        return true;
    }

    internal static bool TryMatchPhotoshop(Stream stream, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (!stream.CanRead || !stream.CanSeek) return false;
        long originalPosition = stream.Position;
        try
        {
            if (!TryReadAt(stream, 0, 26, out var header) ||
                !TryMatchPhotoshop(new ReadOnlySpan<byte>(header), completeLength: null, out var sampled)) return false;
            ushort version = ReadUInt16BigEndian(new ReadOnlySpan<byte>(header), 4);
            var headerSpan = new ReadOnlySpan<byte>(header);
            long cursor = 26;
            if (!TryReadAt(stream, cursor, 4, out var colorModeLengthBytes)) return false;
            ulong colorModeLength = ReadUInt32BigEndian(new ReadOnlySpan<byte>(colorModeLengthBytes), 0);
            if (!IsValidPhotoshopColorMode(ReadUInt16BigEndian(headerSpan, 12), ReadUInt16BigEndian(headerSpan, 22),
                    ReadUInt16BigEndian(headerSpan, 24), colorModeLength)) return false;
            if (!TrySkipPhotoshopSection(stream, ref cursor, 4) ||
                !TrySkipPhotoshopSection(stream, ref cursor, 4) ||
                !TrySkipPhotoshopSection(stream, ref cursor, version == 1 ? 4 : 8) ||
                cursor > stream.Length - 2 || !TryReadAt(stream, cursor, 2, out var compression)) return false;
            ushort compressionValue = ReadUInt16BigEndian(new ReadOnlySpan<byte>(compression), 0);
            if (compressionValue > 3 || !TryValidatePhotoshopImageData(stream, cursor + 2, version,
                    ReadUInt16BigEndian(headerSpan, 12), ReadUInt32BigEndian(headerSpan, 14),
                    ReadUInt32BigEndian(headerSpan, 18), ReadUInt16BigEndian(headerSpan, 22),
                    compressionValue, out bool imageDataValidated)) return false;
            sampled!.Confidence = imageDataValidated ? "High" : "Medium";
            sampled.Reason = "photoshop:" + (version == 1 ? "psd" : "psb") +
                             (imageDataValidated ? string.Empty : ";image-data-budget");
            result = sampled;
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

    private static bool IsValidPhotoshopColorMode(ushort channels, ushort depth, ushort colorMode, ulong? dataLength)
    {
        bool lengthIs(ulong expected) => !dataLength.HasValue || dataLength.Value == expected;
        return colorMode switch
        {
            0 => channels == 1 && depth == 1 && lengthIs(0),
            1 => channels is 1 or 2 && depth is 8 or 16 or 32 && lengthIs(0),
            2 => channels == 1 && depth == 8 && lengthIs(768),
            3 => channels >= 3 && depth is 8 or 16 or 32 && lengthIs(0),
            4 => channels >= 4 && depth is 8 or 16 or 32 && lengthIs(0),
            7 => depth is 8 or 16 or 32 && lengthIs(0),
            8 => channels is 1 or 2 && depth == 8 && (!dataLength.HasValue || dataLength.Value > 0),
            9 => channels >= 3 && depth is 8 or 16 or 32 && lengthIs(0),
            _ => false
        };
    }

    private static bool TrySkipPhotoshopSection(Stream stream, ref long cursor, int lengthSize)
    {
        if (cursor < 0 || cursor > stream.Length - lengthSize ||
            !TryReadAt(stream, cursor, lengthSize, out var encodedLength)) return false;
        var span = new ReadOnlySpan<byte>(encodedLength);
        ulong length = lengthSize == 4 ? ReadUInt32BigEndian(span, 0) : ReadUInt64(span, 0, false);
        cursor += lengthSize;
        if (length > (ulong)(stream.Length - cursor)) return false;
        cursor += (long)length;
        return true;
    }

    private static bool TryValidatePhotoshopImageData(Stream stream, long dataOffset, ushort version,
        ushort channels, uint height, uint width, ushort depth, ushort compression, out bool fullyValidated)
    {
        fullyValidated = false;
        ulong rowBytes = ((ulong)width * depth + 7) / 8;
        if (compression == 0)
        {
            ulong requiredLength = (ulong)dataOffset + rowBytes * height * channels;
            fullyValidated = requiredLength == (ulong)stream.Length;
            return fullyValidated;
        }
        if (compression is 2 or 3)
        {
            if (dataOffset > stream.Length - 2 || !TryReadAt(stream, dataOffset, 2, out var zlibHeader) ||
                !IsPhotoshopZlibHeader(new ReadOnlySpan<byte>(zlibHeader))) return false;
            return true;
        }

        ulong rowCount = (ulong)channels * height;
        int rowLengthSize = version == 1 ? 2 : 4;
        ulong tableLength = rowCount * (uint)rowLengthSize;
        ulong tableEnd = (ulong)dataOffset + tableLength;
        if (tableEnd >= (ulong)stream.Length) return false;
        if (tableLength > (ulong)Math.Max(256, Settings.DetectionReadBudgetBytes)) return true;
        if (!TryReadAt(stream, dataOffset, checked((int)tableLength), out var table)) return false;

        ulong compressedLength = 0;
        var tableSpan = new ReadOnlySpan<byte>(table);
        var rowLengths = new uint[(int)rowCount];
        for (int row = 0; row < (int)rowCount; row++)
        {
            int offset = row * rowLengthSize;
            uint rowLength = rowLengthSize == 2 ? ReadUInt16BigEndian(tableSpan, offset) : ReadUInt32BigEndian(tableSpan, offset);
            if (rowLength == 0 || compressedLength > ulong.MaxValue - rowLength) return false;
            rowLengths[row] = rowLength;
            compressedLength += rowLength;
        }
        ulong requiredEnd = tableEnd + compressedLength;
        if (requiredEnd < tableEnd || requiredEnd != (ulong)stream.Length) return false;
        int budget = Math.Max(256, Settings.DetectionReadBudgetBytes);
        if (compressedLength > (ulong)budget) return true;
        if (!TryReadAt(stream, (long)tableEnd, checked((int)compressedLength), out var compressedRows)) return false;
        int compressedOffset = 0;
        var compressedSpan = new ReadOnlySpan<byte>(compressedRows);
        for (int row = 0; row < rowLengths.Length; row++)
        {
            int rowLength = checked((int)rowLengths[row]);
            if (!TryValidatePhotoshopRleRow(compressedSpan.Slice(compressedOffset, rowLength), rowBytes)) return false;
            compressedOffset += rowLength;
        }
        fullyValidated = true;
        return true;
    }

    private static bool TryValidatePhotoshopRleRow(ReadOnlySpan<byte> compressed, ulong expectedLength)
    {
        int cursor = 0;
        ulong decodedLength = 0;
        while (cursor < compressed.Length)
        {
            byte control = compressed[cursor++];
            if (control <= 127)
            {
                int literalLength = control + 1;
                if (literalLength > compressed.Length - cursor || decodedLength > ulong.MaxValue - (uint)literalLength) return false;
                decodedLength += (uint)literalLength;
                cursor += literalLength;
            }
            else if (control >= 129)
            {
                int repeatedLength = 257 - control;
                if (cursor >= compressed.Length || decodedLength > ulong.MaxValue - (uint)repeatedLength) return false;
                decodedLength += (uint)repeatedLength;
                cursor++;
            }
            if (decodedLength > expectedLength) return false;
        }
        return decodedLength == expectedLength;
    }

    private static bool IsPhotoshopZlibHeader(ReadOnlySpan<byte> header)
    {
        if (header.Length < 2) return false;
        int value = header[0] << 8 | header[1];
        return (header[0] & 0x0F) == 8 && (header[0] >> 4) <= 7 && (header[1] & 0x20) == 0 && value % 31 == 0;
    }

    internal static bool TryMatchJpeg2000(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
        => TryMatchJpeg2000(src, src.Length, out result);

    internal static bool TryMatchJpeg2000(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result) {
        result = null;
        if (src.Length < 32 ||
            ReadUInt32BigEndian(src, 0) != 12 ||
            src[4] != (byte)'j' || src[5] != (byte)'P' || src[6] != (byte)' ' || src[7] != (byte)' ' ||
            src[8] != 0x0D || src[9] != 0x0A || src[10] != 0x87 || src[11] != 0x0A ||
            src[16] != (byte)'f' || src[17] != (byte)'t' || src[18] != (byte)'y' || src[19] != (byte)'p')
            return false;

        uint fileTypeLength = ReadUInt32BigEndian(src, 12);
        if (fileTypeLength < 20 || (fileTypeLength & 3) != 0) return false;
        long boxEnd = 12L + fileTypeLength;
        if (completeLength < 0 || (completeLength.HasValue && boxEnd > completeLength.Value)) return false;

        uint brand = ReadUInt32BigEndian(src, 20);
        string extension = string.Empty;
        string mime = string.Empty;
        if (brand == 0x6A703220) { extension = "jp2"; mime = "image/jp2"; }
        else if (brand == 0x6A707820) { extension = "jpx"; mime = "image/jpx"; }
        else if (brand == 0x6A706D20) { extension = "jpm"; mime = "image/jpm"; }
        else if (brand == 0x6D6A7032) { extension = "mj2"; mime = "video/mj2"; }
        if (extension.Length == 0) return false;

        int availableEnd = (int)Math.Min(boxEnd, src.Length);
        bool completeBox = boxEnd <= src.Length;
        bool compatible = false;
        for (int offset = 28; offset + 4 <= availableEnd; offset += 4) {
            if (ReadUInt32BigEndian(src, offset) == brand) {
                compatible = true;
                break;
            }
        }
        if (completeBox && !compatible) return false;

        bool requiredBoxes = false;
        if (completeLength.HasValue)
        {
            if (completeLength.Value > src.Length) return false;
            requiredBoxes = TryValidateJpeg2000TopLevelBoxes(src, (int)boxEnd, brand);
            if (!requiredBoxes) return false;
        }

        result = new ContentTypeDetectionResult {
            Extension = extension,
            MimeType = mime,
            Confidence = completeBox && requiredBoxes && brand != 0x6D6A7032 ? "High" : "Medium",
            Reason = "jpeg2000:" + extension + (completeBox && requiredBoxes ?
                brand == 0x6D6A7032 ? ";sample-table-not-validated" : string.Empty : ";sampled-file-type-box")
        };
        return true;
    }

    private static bool TryValidateJpeg2000TopLevelBoxes(ReadOnlySpan<byte> src, int cursor, uint brand)
    {
        bool header = false;
        bool sawHeaderBox = false;
        bool data = false;
        while (cursor < src.Length)
        {
            if (cursor + 8 > src.Length) return false;
            uint length32 = ReadUInt32BigEndian(src, cursor);
            uint type = ReadUInt32BigEndian(src, cursor + 4);
            long boxLength = length32;
            int headerLength = 8;
            if (length32 == 1)
            {
                if (cursor + 16 > src.Length) return false;
                ulong large = ReadUInt64(src, cursor + 8, false);
                if (large > long.MaxValue) return false;
                boxLength = (long)large;
                headerLength = 16;
            }
            else if (length32 == 0) boxLength = src.Length - cursor;
            if (boxLength < headerLength || boxLength > src.Length - cursor) return false;
            if (brand == 0x6D6A7032)
            {
                if (type == 0x6D6F6F76)
                {
                    if (sawHeaderBox) return false;
                    sawHeaderBox = true;
                    header = TryValidateMj2MovieBox(src.Slice(cursor + headerLength, (int)boxLength - headerLength));
                    if (!header) return false;
                }
                if (type == 0x6D646174) data |= boxLength > headerLength;
            }
            else
            {
                if (type == GetJpeg2000HeaderBoxType(brand))
                {
                    if (sawHeaderBox) return false;
                    sawHeaderBox = true;
                    header = TryValidateJpeg2000HeaderPayload(src.Slice(cursor + headerLength, (int)boxLength - headerLength), brand);
                    if (!header) return false;
                }
                if (header && type == 0x6A703263)
                    data |= TryValidateJpeg2000Codestream(src.Slice(cursor + headerLength, (int)boxLength - headerLength));
            }
            cursor += (int)boxLength;
        }
        return cursor == src.Length && header && data;
    }

    private static bool TryValidateMj2MovieBox(ReadOnlySpan<byte> payload)
    {
        bool movieHeader = false, mediaTrack = false;
        int cursor = 0;
        while (cursor < payload.Length)
        {
            if (!TryReadIsoBox(payload, ref cursor, out uint type, out ReadOnlySpan<byte> child)) return false;
            if (type == 0x6D766864) movieHeader |= child.Length > 0;
            else if (type == 0x7472616B) mediaTrack |= TryFindMj2MediaBox(child);
        }
        return cursor == payload.Length && movieHeader && mediaTrack;
    }

    private static bool TryFindMj2MediaBox(ReadOnlySpan<byte> track)
    {
        int cursor = 0;
        while (cursor < track.Length)
        {
            if (!TryReadIsoBox(track, ref cursor, out uint type, out ReadOnlySpan<byte> child)) return false;
            if (type == 0x6D646961 && child.Length > 0) return true;
        }
        return false;
    }

    private static bool TryReadIsoBox(ReadOnlySpan<byte> src, ref int cursor, out uint type, out ReadOnlySpan<byte> payload)
    {
        type = 0;
        payload = default;
        if (src.Length - cursor < 8) return false;
        uint length32 = ReadUInt32BigEndian(src, cursor);
        type = ReadUInt32BigEndian(src, cursor + 4);
        int headerLength = 8;
        ulong length = length32;
        if (length32 == 1)
        {
            if (src.Length - cursor < 16) return false;
            length = ReadUInt64(src, cursor + 8, false);
            headerLength = 16;
        }
        else if (length32 == 0) length = (ulong)(src.Length - cursor);
        if (length < (ulong)headerLength || length > (ulong)(src.Length - cursor) || length > int.MaxValue) return false;
        payload = src.Slice(cursor + headerLength, (int)length - headerLength);
        cursor += (int)length;
        return true;
    }

    internal static bool TryMatchJpeg2000(Stream stream, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (!stream.CanRead || !stream.CanSeek) return false;
        long originalPosition = stream.Position;
        try
        {
            if (!TryReadAt(stream, 0, 28, out var prefix)) return false;
            var span = new ReadOnlySpan<byte>(prefix);
            if (ReadUInt32BigEndian(span, 0) != 12 ||
                !span.Slice(4, 4).SequenceEqual("jP  "u8) ||
                span[8] != 0x0D || span[9] != 0x0A || span[10] != 0x87 || span[11] != 0x0A ||
                !span.Slice(16, 4).SequenceEqual("ftyp"u8)) return false;
            uint fileTypeLength = ReadUInt32BigEndian(span, 12);
            if (fileTypeLength < 20 || (fileTypeLength & 3) != 0 || fileTypeLength > stream.Length - 12) return false;
            uint brand = ReadUInt32BigEndian(span, 20);
            if (!TryGetJpeg2000Brand(brand, out string extension, out string mime)) return false;
            bool compatible = false;
            for (long offset = 28; offset < 12L + fileTypeLength; offset += 4)
            {
                if (!TryReadAt(stream, offset, 4, out var compatibleBrand)) return false;
                if (ReadUInt32BigEndian(new ReadOnlySpan<byte>(compatibleBrand), 0) == brand) compatible = true;
            }
            if (!compatible) return false;

            bool header = false;
            bool data = false;
            bool sampledMj2 = false;
            bool sampledCodestream = false;
            bool sawHeaderBox = false;
            long cursor = 12L + fileTypeLength;
            int remainingBoxHeaders = Math.Max(1, Settings.DetectionReadBudgetBytes / 8);
            while (cursor < stream.Length)
            {
                if (remainingBoxHeaders-- == 0)
                {
                    result = new ContentTypeDetectionResult {
                        Extension = extension,
                        MimeType = mime,
                        Confidence = "Medium",
                        Reason = "jpeg2000:" + extension + ";box-budget"
                    };
                    return true;
                }
                if (cursor > stream.Length - 8 || !TryReadAt(stream, cursor, 8, out var boxHeader)) return false;
                var box = new ReadOnlySpan<byte>(boxHeader);
                uint length32 = ReadUInt32BigEndian(box, 0);
                uint type = ReadUInt32BigEndian(box, 4);
                long boxLength;
                int headerLength = 8;
                if (length32 == 1)
                {
                    if (cursor > stream.Length - 16 || !TryReadAt(stream, cursor + 8, 8, out var extended)) return false;
                    ulong large = ReadUInt64(new ReadOnlySpan<byte>(extended), 0, false);
                    if (large > long.MaxValue) return false;
                    boxLength = (long)large;
                    headerLength = 16;
                }
                else boxLength = length32 == 0 ? stream.Length - cursor : length32;
                if (boxLength < headerLength || boxLength > stream.Length - cursor) return false;
                if (brand == 0x6D6A7032)
                {
                    if (type == 0x6D6F6F76)
                    {
                        if (sawHeaderBox) return false;
                        sawHeaderBox = true;
                        long payloadLength = boxLength - headerLength;
                        if (payloadLength > Settings.DetectionReadBudgetBytes) sampledMj2 = true;
                        else if (!TryReadAt(stream, cursor + headerLength, (int)payloadLength, out var movieBytes) ||
                                 !TryValidateMj2MovieBox(new ReadOnlySpan<byte>(movieBytes))) return false;
                        else header = true;
                    }
                    if (type == 0x6D646174) data |= boxLength > headerLength;
                }
                else
                {
                    if (type == GetJpeg2000HeaderBoxType(brand))
                    {
                        if (sawHeaderBox) return false;
                        sawHeaderBox = true;
                        header = TryValidateJpeg2000HeaderPayload(stream, cursor + headerLength, boxLength - headerLength, brand);
                        if (!header) return false;
                    }
                    if (header && type == 0x6A703263)
                        data |= TryValidateJpeg2000Codestream(stream, cursor + headerLength, boxLength - headerLength, out sampledCodestream);
                }
                cursor += boxLength;
            }
            if (cursor != stream.Length || (!header && !sampledMj2) || !data) return false;
            result = new ContentTypeDetectionResult {
                Extension = extension,
                MimeType = mime,
                Confidence = brand == 0x6D6A7032 || sampledMj2 || sampledCodestream ? "Medium" : "High",
                Reason = "jpeg2000:" + extension + (sampledMj2 ? ";movie-box-budget" : string.Empty) +
                         (sampledCodestream ? ";codestream-budget" : string.Empty) +
                         (brand == 0x6D6A7032 && !sampledMj2 ? ";sample-table-not-validated" : string.Empty)
            };
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

    private static bool TryGetJpeg2000Brand(uint brand, out string extension, out string mime)
    {
        extension = string.Empty;
        mime = string.Empty;
        if (brand == 0x6A703220) { extension = "jp2"; mime = "image/jp2"; }
        else if (brand == 0x6A707820) { extension = "jpx"; mime = "image/jpx"; }
        else if (brand == 0x6A706D20) { extension = "jpm"; mime = "image/jpm"; }
        else if (brand == 0x6D6A7032) { extension = "mj2"; mime = "video/mj2"; }
        return extension.Length != 0;
    }

    private static uint GetJpeg2000HeaderBoxType(uint brand)
        => brand == 0x6A707820 ? 0x6A707868u : brand == 0x6A706D20 ? 0x6A706D68u : 0x6A703268u;

    private static bool TryValidateJpeg2000HeaderPayload(ReadOnlySpan<byte> payload, uint brand)
    {
        if (brand == 0x6A706D20) return payload.Length >= 8 && ReadUInt32BigEndian(payload, 0) >= 8 && ReadUInt32BigEndian(payload, 0) <= payload.Length;
        if (!TryValidateJpeg2000ImageHeader(payload, out ushort components, out byte bits)) return false;
        bool sawBitsPerComponent = false;
        bool sawColourSpecification = false;
        int cursor = 22;
        while (cursor < payload.Length)
        {
            if (cursor + 8 > payload.Length) return false;
            uint length32 = ReadUInt32BigEndian(payload, cursor);
            uint type = ReadUInt32BigEndian(payload, cursor + 4);
            long boxLength = length32;
            int headerLength = 8;
            if (length32 == 1)
            {
                if (cursor + 16 > payload.Length) return false;
                ulong large = ReadUInt64(payload, cursor + 8, false);
                if (large > long.MaxValue) return false;
                boxLength = (long)large;
                headerLength = 16;
            }
            else if (length32 == 0) boxLength = payload.Length - cursor;
            if (boxLength < headerLength || boxLength > payload.Length - cursor) return false;
            if (type == 0x62706363)
            {
                if (sawBitsPerComponent || boxLength != headerLength + components) return false;
                var componentDepths = payload.Slice(cursor + headerLength, components);
                for (int component = 0; component < componentDepths.Length; component++)
                    if ((componentDepths[component] & 0x7F) > 37) return false;
                sawBitsPerComponent = true;
            }
            else if (type == 0x636F6C72)
            {
                if (!TryValidateJpeg2000ColourSpecification(payload.Slice(cursor + headerLength, (int)boxLength - headerLength))) return false;
                sawColourSpecification = true;
            }
            cursor += (int)boxLength;
        }
        return (bits == 0xFF) == sawBitsPerComponent && (brand != 0x6A703220 || sawColourSpecification);
    }

    private static bool TryValidateJpeg2000HeaderPayload(Stream stream, long offset, long length, uint brand)
    {
        int required = brand == 0x6A706D20 ? 8 : 22;
        if (length < required || !TryReadAt(stream, offset, required, out var bytes)) return false;
        if (brand == 0x6A706D20) return TryValidateJpeg2000HeaderPayload(new ReadOnlySpan<byte>(bytes), brand);
        if (!TryValidateJpeg2000ImageHeader(new ReadOnlySpan<byte>(bytes), out ushort components, out byte bits)) return false;
        bool sawBitsPerComponent = false;
        bool sawColourSpecification = false;
        long cursor = 22;
        int remainingHeaders = Math.Max(1, Settings.DetectionReadBudgetBytes / 8);
        while (cursor < length)
        {
            if (remainingHeaders-- == 0 || cursor > length - 8 || !TryReadAt(stream, offset + cursor, 8, out var childHeader)) return false;
            var child = new ReadOnlySpan<byte>(childHeader);
            uint length32 = ReadUInt32BigEndian(child, 0);
            uint type = ReadUInt32BigEndian(child, 4);
            long boxLength = length32;
            int headerLength = 8;
            if (length32 == 1)
            {
                if (cursor > length - 16 || !TryReadAt(stream, offset + cursor + 8, 8, out var extended)) return false;
                ulong large = ReadUInt64(new ReadOnlySpan<byte>(extended), 0, false);
                if (large > long.MaxValue) return false;
                boxLength = (long)large;
                headerLength = 16;
            }
            else if (length32 == 0) boxLength = length - cursor;
            if (boxLength < headerLength || boxLength > length - cursor) return false;
            if (type == 0x62706363)
            {
                if (sawBitsPerComponent || boxLength != headerLength + components ||
                    !TryReadAt(stream, offset + cursor + headerLength, components, out var depths)) return false;
                for (int component = 0; component < depths.Length; component++)
                    if ((depths[component] & 0x7F) > 37) return false;
                sawBitsPerComponent = true;
            }
            else if (type == 0x636F6C72)
            {
                long colourLength = boxLength - headerLength;
                int prefixLength = (int)Math.Min(7, colourLength);
                if (prefixLength < 3 || !TryReadAt(stream, offset + cursor + headerLength, prefixLength, out var colour) ||
                    !TryValidateJpeg2000ColourSpecification(new ReadOnlySpan<byte>(colour), colourLength)) return false;
                sawColourSpecification = true;
            }
            cursor += boxLength;
        }
        return (bits == 0xFF) == sawBitsPerComponent && (brand != 0x6A703220 || sawColourSpecification);
    }

    private static bool TryValidateJpeg2000ColourSpecification(ReadOnlySpan<byte> payload, long? declaredLength = null)
    {
        long length = declaredLength ?? payload.Length;
        if (length < 3 || payload.Length < Math.Min(3, length)) return false;
        byte method = payload[0];
        if (method == 1)
            return length == 7 && payload.Length >= 7 && ReadUInt32BigEndian(payload, 3) is 16 or 17 or 18;
        return method is 2 or 3 && length > 3;
    }

    private static bool TryValidateJpeg2000ImageHeader(ReadOnlySpan<byte> payload, out ushort components, out byte bits)
    {
        components = 0;
        bits = 0;
        if (payload.Length < 22 || ReadUInt32BigEndian(payload, 0) != 22 || ReadUInt32BigEndian(payload, 4) != 0x69686472) return false;
        uint height = ReadUInt32BigEndian(payload, 8);
        uint width = ReadUInt32BigEndian(payload, 12);
        components = ReadUInt16BigEndian(payload, 16);
        bits = payload[18];
        return height != 0 && width != 0 && components != 0 && (bits == 0xFF || (bits & 0x7F) <= 37) &&
               payload[19] == 7 && payload[20] <= 1 && payload[21] <= 1;
    }

    private static bool TryValidateJpeg2000Codestream(ReadOnlySpan<byte> payload)
        => TryValidateJpeg2000CodestreamFraming(payload, payload.Length, requireEnd: true);

    private static bool TryValidateJpeg2000Codestream(Stream stream, long offset, long length, out bool sampled)
    {
        sampled = false;
        if (length < 61 || !TryReadAt(stream, offset + length - 2, 2, out var end) || end[0] != 0xFF || end[1] != 0xD9) return false;
        int budget = Math.Max(256, Settings.DetectionReadBudgetBytes);
        int readLength = (int)Math.Min(length, budget);
        if (!TryReadAt(stream, offset, readLength, out var bytes)) return false;
        sampled = readLength < length;
        return TryValidateJpeg2000CodestreamFraming(new ReadOnlySpan<byte>(bytes), length, requireEnd: !sampled);
    }

    private static bool TryValidateJpeg2000CodestreamFraming(ReadOnlySpan<byte> payload, long declaredLength, bool requireEnd)
    {
        if (payload.Length < 47 || payload[0] != 0xFF || payload[1] != 0x4F ||
            payload[2] != 0xFF || payload[3] != 0x51) return false;
        ushort sizLength = ReadUInt16BigEndian(payload, 4);
        if (sizLength < 41 || 2L + sizLength > payload.Length) return false;
        uint xSize = ReadUInt32BigEndian(payload, 8), ySize = ReadUInt32BigEndian(payload, 12);
        uint xOrigin = ReadUInt32BigEndian(payload, 16), yOrigin = ReadUInt32BigEndian(payload, 20);
        uint tileWidth = ReadUInt32BigEndian(payload, 24), tileHeight = ReadUInt32BigEndian(payload, 28);
        uint tileXOrigin = ReadUInt32BigEndian(payload, 32), tileYOrigin = ReadUInt32BigEndian(payload, 36);
        ushort components = ReadUInt16BigEndian(payload, 40);
        if (components == 0 || sizLength != 38 + components * 3 || xSize <= xOrigin || ySize <= yOrigin ||
            tileWidth == 0 || tileHeight == 0 || tileXOrigin > xOrigin || tileYOrigin > yOrigin) return false;
        for (int component = 0; component < components; component++)
        {
            int descriptor = 42 + component * 3;
            if ((payload[descriptor] & 0x7F) > 37 || payload[descriptor + 1] == 0 || payload[descriptor + 2] == 0) return false;
        }
        ulong tilesAcross = ((ulong)xSize - tileXOrigin + tileWidth - 1) / tileWidth;
        ulong tilesDown = ((ulong)ySize - tileYOrigin + tileHeight - 1) / tileHeight;
        ulong tileCountValue = tilesAcross * tilesDown;
        if (tileCountValue == 0 || tileCountValue > ushort.MaxValue) return false;
        int tileCount = (int)tileCountValue;
        var nextTileParts = new int[tileCount];
        var declaredTileParts = new int[tileCount];
        var seenTiles = new bool[tileCount];
        int cursor = 4 + sizLength;
        bool sawTile = false;
        while (cursor + 2 <= payload.Length)
        {
            if (payload[cursor] != 0xFF) return false;
            byte marker = payload[cursor + 1];
            if (marker == 0xD9)
            {
                if (!requireEnd || !sawTile || cursor + 2 != payload.Length || declaredLength != payload.Length)
                    return false;
                for (int tile = 0; tile < tileCount; tile++)
                    if (!seenTiles[tile] || declaredTileParts[tile] != 0 && nextTileParts[tile] != declaredTileParts[tile])
                        return false;
                return true;
            }
            if (marker != 0x90)
            {
                if (cursor + 4 > payload.Length) return false;
                ushort segmentLength = ReadUInt16BigEndian(payload, cursor + 2);
                if (segmentLength < 2 || cursor + 2 + segmentLength > payload.Length) return false;
                cursor += 2 + segmentLength;
                continue;
            }
            if (cursor + 12 > payload.Length || ReadUInt16BigEndian(payload, cursor + 2) != 10) return false;
            ushort tileIndex = ReadUInt16BigEndian(payload, cursor + 4);
            uint tilePartLength = ReadUInt32BigEndian(payload, cursor + 6);
            byte tilePartIndex = payload[cursor + 10];
            byte tilePartCount = payload[cursor + 11];
            if (tileIndex >= tileCount || tilePartIndex != nextTileParts[tileIndex] ||
                tilePartCount != 0 && tilePartIndex >= tilePartCount ||
                declaredTileParts[tileIndex] != 0 && tilePartCount != declaredTileParts[tileIndex]) return false;
            if (tilePartCount != 0) declaredTileParts[tileIndex] = tilePartCount;
            seenTiles[tileIndex] = true;
            nextTileParts[tileIndex]++;
            if (tilePartLength != 0 && (tilePartLength < 15 || cursor + (long)tilePartLength > declaredLength - 2)) return false;
            int tileStart = cursor;
            cursor += 12;
            while (cursor + 2 <= payload.Length && !(payload[cursor] == 0xFF && payload[cursor + 1] == 0x93))
            {
                if (payload[cursor] != 0xFF || cursor + 4 > payload.Length) return false;
                ushort segmentLength = ReadUInt16BigEndian(payload, cursor + 2);
                if (segmentLength < 2 || cursor + 2 + segmentLength > payload.Length) return false;
                cursor += 2 + segmentLength;
            }
            if (cursor + 3 > payload.Length) return false;
            cursor += 2;
            sawTile = true;
            if (tilePartLength == 0) return !requireEnd;
            long tileEnd = tileStart + (long)tilePartLength;
            if (tileEnd <= cursor) return false;
            if (tileEnd > payload.Length) return !requireEnd;
            cursor = (int)tileEnd;
        }
        return !requireEnd && sawTile;
    }
}
