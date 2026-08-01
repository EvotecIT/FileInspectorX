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
        if (tiled && multipart) return false;

        int cursor = 8;
        bool sawAnyPart = false;
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
            bool sawAttribute = false;

            while (true)
            {
                if (cursor >= src.Length)
                    return TryReturnSampledOpenExr(completeLength, sawAttribute || sawAnyPart, out result);
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
                    return TryReturnSampledOpenExr(completeLength, sawAttribute || sawAnyPart, out result);
                uint valueLength = ReadUInt32(src, cursor, littleEndian: true);
                cursor += 4;
                if (valueLength == 0 || valueLength > int.MaxValue) return false;
                sawAttribute = true;

                if ((ulong)cursor + valueLength > (ulong)src.Length)
                    return TryReturnSampledOpenExr(completeLength, true, out result);
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
                if (multipart && name == "name") nameAttribute = TryValidateOpenExrTextAttribute(type, value);
                if (multipart && name == "type")
                {
                    typeAttribute = TryValidateOpenExrTextAttribute(type, value);
                    if (typeAttribute)
                    {
                        string partType = System.Text.Encoding.ASCII.GetString(value.ToArray());
                        if (partType is not ("scanlineimage" or "tiledimage" or "deepscanline" or "deeptile")) return false;
                        partRequiresTiles = partType is "tiledimage" or "deeptile";
                    }
                }
                if (multipart && name == "chunkCount")
                    chunkCount = type == "int" && value.Length == 4 && ReadUInt32(value, 0, true) > 0;
                cursor += (int)valueLength;
            }

            if (!multipart) break;
            if (cursor >= src.Length) return TryReturnSampledOpenExr(completeLength, true, out result);
            if (src[cursor] == 0)
            {
                cursor++;
                break;
            }
        }

        result = new ContentTypeDetectionResult {
            Extension = "exr",
            MimeType = "image/x-exr",
            Confidence = "High",
            Reason = "openexr:v2"
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
        while (cursor < value.Length && value[cursor] != 0)
        {
            int nameStart = cursor;
            while (cursor < value.Length && value[cursor] != 0 && cursor - nameStart < 255) cursor++;
            if (cursor >= value.Length || cursor == nameStart || cursor + 17 > value.Length) return false;
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

    private static bool TryReturnSampledOpenExr(long? completeLength, bool sawAttribute,
        out ContentTypeDetectionResult? result)
    {
        result = null;
        if (completeLength.HasValue || !sawAttribute) return false;
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
        uint maximumDimension = version == 1 ? 30000u : 300000u;
        if (channels < 1 || channels > 56 || height < 1 || height > maximumDimension ||
            width < 1 || width > maximumDimension ||
            (depth != 1 && depth != 8 && depth != 16 && depth != 32) ||
            (colorMode != 0 && colorMode != 1 && colorMode != 2 && colorMode != 3 && colorMode != 4 &&
             colorMode != 7 && colorMode != 8 && colorMode != 9))
            return false;

        int cursor = 26;
        if (!TrySkipPhotoshopSection(src, ref cursor, completeLength, 4) ||
            !TrySkipPhotoshopSection(src, ref cursor, completeLength, 4) ||
            !TrySkipPhotoshopSection(src, ref cursor, completeLength, version == 1 ? 4 : 8)) return false;
        if (cursor + 2 > src.Length)
        {
            if (completeLength.HasValue) return false;
        }
        else if (ReadUInt16BigEndian(src, cursor) > 3) return false;

        string extension = version == 1 ? "psd" : "psb";
        result = new ContentTypeDetectionResult {
            Extension = extension,
            MimeType = "image/vnd.adobe.photoshop",
            Confidence = cursor + 2 <= src.Length ? "High" : "Medium",
            Reason = "photoshop:" + extension + (cursor + 2 <= src.Length ? string.Empty : ";sampled-sections")
        };
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
            long cursor = 26;
            if (!TrySkipPhotoshopSection(stream, ref cursor, 4) ||
                !TrySkipPhotoshopSection(stream, ref cursor, 4) ||
                !TrySkipPhotoshopSection(stream, ref cursor, version == 1 ? 4 : 8) ||
                cursor > stream.Length - 2 || !TryReadAt(stream, cursor, 2, out var compression) ||
                ReadUInt16BigEndian(new ReadOnlySpan<byte>(compression), 0) > 3) return false;
            sampled!.Confidence = "High";
            sampled.Reason = "photoshop:" + (version == 1 ? "psd" : "psb");
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
            Confidence = completeBox && requiredBoxes ? "High" : "Medium",
            Reason = "jpeg2000:" + extension + (completeBox && requiredBoxes ? string.Empty : ";sampled-file-type-box")
        };
        return true;
    }

    private static bool TryValidateJpeg2000TopLevelBoxes(ReadOnlySpan<byte> src, int cursor, uint brand)
    {
        bool header = false;
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
            if (brand == 0x6D6A7032) { header |= type == 0x6D6F6F76; data |= type == 0x6D646174; }
            else
            {
                header |= type == (brand == 0x6A707820 ? 0x6A707868u : 0x6A703268u);
                data |= header && type == 0x6A703263;
            }
            cursor += (int)boxLength;
        }
        return cursor == src.Length && header && data;
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
            long cursor = 12L + fileTypeLength;
            while (cursor < stream.Length)
            {
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
                if (brand == 0x6D6A7032) { header |= type == 0x6D6F6F76; data |= type == 0x6D646174; }
                else
                {
                    header |= type == (brand == 0x6A707820 ? 0x6A707868u : 0x6A703268u);
                    data |= header && type == 0x6A703263;
                }
                cursor += boxLength;
            }
            if (cursor != stream.Length || !header || !data) return false;
            result = new ContentTypeDetectionResult {
                Extension = extension,
                MimeType = mime,
                Confidence = "High",
                Reason = "jpeg2000:" + extension
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
}
