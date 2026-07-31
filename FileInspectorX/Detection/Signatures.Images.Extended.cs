namespace FileInspectorX;

/// <summary>
/// Structured image formats not covered by the core signature table.
/// </summary>
internal static partial class Signatures {
    internal static bool TryMatchOpenExr(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result) {
        result = null;
        if (src.Length < 8 || src[0] != 0x76 || src[1] != 0x2F || src[2] != 0x31 || src[3] != 0x01)
            return false;

        uint versionField = ReadUInt32(src, 4, littleEndian: true);
        const uint AllowedFlags = 0x00001E00;
        if ((versionField & 0xFF) != 2 || (versionField & ~(AllowedFlags | 0xFFu)) != 0) return false;
        bool tiled = (versionField & 0x00000200) != 0;
        bool multipart = (versionField & 0x00001000) != 0;
        if (tiled && multipart) return false;

        result = new ContentTypeDetectionResult {
            Extension = "exr",
            MimeType = "image/x-exr",
            Confidence = "High",
            Reason = "openexr:v2"
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

    internal static bool TryMatchJpeg2000(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result) {
        result = null;
        if (src.Length < 32 ||
            ReadUInt32BigEndian(src, 0) != 12 ||
            src[4] != (byte)'j' || src[5] != (byte)'P' || src[6] != (byte)' ' || src[7] != (byte)' ' ||
            src[8] != 0x0D || src[9] != 0x0A || src[10] != 0x87 || src[11] != 0x0A ||
            src[16] != (byte)'f' || src[17] != (byte)'t' || src[18] != (byte)'y' || src[19] != (byte)'p')
            return false;

        uint fileTypeLength = ReadUInt32BigEndian(src, 12);
        if (fileTypeLength < 20 || (fileTypeLength & 3) != 0) return false;

        uint brand = ReadUInt32BigEndian(src, 20);
        string extension = string.Empty;
        string mime = string.Empty;
        if (brand == 0x6A703220) { extension = "jp2"; mime = "image/jp2"; }
        else if (brand == 0x6A707820) { extension = "jpx"; mime = "image/jpx"; }
        else if (brand == 0x6A706D20) { extension = "jpm"; mime = "image/jpm"; }
        else if (brand == 0x6D6A7032) { extension = "mj2"; mime = "video/mj2"; }
        if (extension.Length == 0) return false;

        long boxEnd = 12L + fileTypeLength;
        int availableEnd = (int)Math.Min(boxEnd, src.Length);
        bool compatible = false;
        for (int offset = 28; offset + 4 <= availableEnd; offset += 4) {
            if (ReadUInt32BigEndian(src, offset) == brand) {
                compatible = true;
                break;
            }
        }
        if (!compatible) return false;

        result = new ContentTypeDetectionResult {
            Extension = extension,
            MimeType = mime,
            Confidence = "High",
            Reason = "jpeg2000:" + extension
        };
        return true;
    }
}
