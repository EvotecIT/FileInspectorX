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
        bool channels = false;
        bool compression = false;
        bool dataWindow = false;
        bool displayWindow = false;
        bool lineOrder = false;
        bool pixelAspectRatio = false;
        bool screenWindowCenter = false;
        bool screenWindowWidth = false;
        bool tiles = !tiled;
        bool sawAttribute = false;
        while (true)
        {
            if (cursor >= src.Length)
                return TryReturnSampledOpenExr(completeLength, sawAttribute, channels, compression, dataWindow, displayWindow,
                    lineOrder, pixelAspectRatio, screenWindowCenter, screenWindowWidth, tiles, out result);
            if (src[cursor] == 0)
            {
                cursor++;
                if (!HasMandatoryOpenExrAttributes(channels, compression, dataWindow, displayWindow, lineOrder,
                        pixelAspectRatio, screenWindowCenter, screenWindowWidth, tiles)) return false;
                break;
            }

            if (!TryReadOpenExrString(src, ref cursor, out string name) ||
                !TryReadOpenExrString(src, ref cursor, out _) || cursor + 4 > src.Length)
                return TryReturnSampledOpenExr(completeLength, sawAttribute, channels, compression, dataWindow, displayWindow,
                    lineOrder, pixelAspectRatio, screenWindowCenter, screenWindowWidth, tiles, out result);
            uint valueLength = ReadUInt32(src, cursor, littleEndian: true);
            cursor += 4;
            if (valueLength == 0 || valueLength > int.MaxValue) return false;
            sawAttribute = true;

            channels |= name == "channels";
            compression |= name == "compression";
            dataWindow |= name == "dataWindow";
            displayWindow |= name == "displayWindow";
            lineOrder |= name == "lineOrder";
            pixelAspectRatio |= name == "pixelAspectRatio";
            screenWindowCenter |= name == "screenWindowCenter";
            screenWindowWidth |= name == "screenWindowWidth";
            tiles |= name == "tiles";
            if ((ulong)cursor + valueLength > (ulong)src.Length)
                return TryReturnSampledOpenExr(completeLength, sawAttribute, channels, compression, dataWindow, displayWindow,
                    lineOrder, pixelAspectRatio, screenWindowCenter, screenWindowWidth, tiles, out result);
            cursor += (int)valueLength;
        }

        result = new ContentTypeDetectionResult {
            Extension = "exr",
            MimeType = "image/x-exr",
            Confidence = "High",
            Reason = "openexr:v2"
        };
        return true;
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

    private static bool TryReturnSampledOpenExr(long? completeLength, bool sawAttribute, bool channels, bool compression,
        bool dataWindow, bool displayWindow, bool lineOrder, bool pixelAspectRatio, bool screenWindowCenter,
        bool screenWindowWidth, bool tiles, out ContentTypeDetectionResult? result)
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

    internal static bool TryMatchPhotoshop(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result) {
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

        string extension = version == 1 ? "psd" : "psb";
        result = new ContentTypeDetectionResult {
            Extension = extension,
            MimeType = "image/vnd.adobe.photoshop",
            Confidence = "High",
            Reason = "photoshop:" + extension
        };
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

        result = new ContentTypeDetectionResult {
            Extension = extension,
            MimeType = mime,
            Confidence = completeBox ? "High" : "Medium",
            Reason = "jpeg2000:" + extension + (completeBox ? string.Empty : ";sampled-file-type-box")
        };
        return true;
    }
}
