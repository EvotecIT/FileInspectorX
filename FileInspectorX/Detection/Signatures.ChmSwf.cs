namespace FileInspectorX;

/// <summary>Structural validation for compiled HTML Help and Shockwave Flash headers.</summary>
internal static partial class Signatures
{
    internal static bool TryMatchChm(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 16 || !src.Slice(0, 4).SequenceEqual("ITSF"u8)) return false;
        uint version = ReadUInt32LittleEndian(src, 4);
        uint headerLength = ReadUInt32LittleEndian(src, 8);
        if (version is not (2u or 3u) || headerLength < 0x60 || headerLength > int.MaxValue) return false;
        if (completeLength.HasValue && headerLength > completeLength.Value) return false;
        if (src.Length < Math.Min((int)headerLength, 0x60)) return false;

        result = new ContentTypeDetectionResult
        {
            Extension = "chm",
            MimeType = "application/vnd.ms-htmlhelp",
            Confidence = "High",
            Reason = "magic:chm-structured"
        };
        return true;
    }

    internal static bool TryMatchSwf(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result)
    {
        result = null;
        if (src.Length < 8) return false;
        bool compressed = src[0] == (byte)'C';
        if ((!compressed && src[0] != (byte)'F') || src[1] != (byte)'W' || src[2] != (byte)'S') return false;
        byte version = src[3];
        uint declaredLength = ReadUInt32LittleEndian(src, 4);
        if (version is 0 or > 50 || declaredLength < 14 || declaredLength > int.MaxValue) return false;
        if (compressed)
        {
            if (src.Length < 10) return false;
            int zlibHeader = (src[8] << 8) | src[9];
            if ((src[8] & 0x0F) != 8 || (src[8] >> 4) > 7 || zlibHeader % 31 != 0) return false;
        }
        else
        {
            if (completeLength.HasValue && declaredLength != completeLength.Value) return false;
            int coordinateBits = src[8] >> 3;
            if (coordinateBits == 0) return false;
            int rectangleBytes = (5 + coordinateBits * 4 + 7) / 8;
            if (src.Length < 8 + rectangleBytes + 4) return false;
        }

        result = new ContentTypeDetectionResult
        {
            Extension = "swf",
            MimeType = "application/x-shockwave-flash",
            Confidence = "High",
            Reason = "magic:swf-structured"
        };
        return true;
    }
}
