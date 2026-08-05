namespace FileInspectorX;

/// <summary>Structural validation for Windows Registry export text headers.</summary>
internal static partial class Signatures
{
    internal static bool TryMatchRegistryExport(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        bool versionFour = HasEncodedHeaderLine(src, "REGEDIT4"u8);
        bool versionFive = HasEncodedHeaderLine(src, "Windows Registry Editor Version 5.00"u8);
        if (!versionFour && !versionFive) return false;

        result = new ContentTypeDetectionResult
        {
            Extension = "reg",
            MimeType = "text/plain",
            Confidence = versionFive ? "High" : "Medium",
            Reason = "magic:reg-structured"
        };
        return true;
    }

    private static bool HasEncodedHeaderLine(ReadOnlySpan<byte> src, ReadOnlySpan<byte> header)
    {
        if (HasSingleByteHeaderLine(src, header)) return true;
        if (src.StartsWith(new byte[] { 0xEF, 0xBB, 0xBF }))
            return HasSingleByteHeaderLine(src.Slice(3), header);
        if (src.StartsWith(new byte[] { 0xFF, 0xFE }))
            return HasUtf16HeaderLine(src.Slice(2), header, littleEndian: true);
        if (src.StartsWith(new byte[] { 0xFE, 0xFF }))
            return HasUtf16HeaderLine(src.Slice(2), header, littleEndian: false);
        return false;
    }

    private static bool HasSingleByteHeaderLine(ReadOnlySpan<byte> src, ReadOnlySpan<byte> header)
        => src.Length > header.Length &&
           src.Slice(0, header.Length).SequenceEqual(header) &&
           src[header.Length] is (byte)'\r' or (byte)'\n';

    private static bool HasUtf16HeaderLine(
        ReadOnlySpan<byte> src,
        ReadOnlySpan<byte> header,
        bool littleEndian)
    {
        int headerBytes = checked(header.Length * 2);
        if (src.Length < headerBytes + 2) return false;

        for (int index = 0; index < header.Length; index++)
        {
            int offset = index * 2;
            byte value = littleEndian ? src[offset] : src[offset + 1];
            byte padding = littleEndian ? src[offset + 1] : src[offset];
            if (value != header[index] || padding != 0) return false;
        }

        byte lineBreak = littleEndian ? src[headerBytes] : src[headerBytes + 1];
        byte lineBreakPadding = littleEndian ? src[headerBytes + 1] : src[headerBytes];
        return lineBreakPadding == 0 && lineBreak is (byte)'\r' or (byte)'\n';
    }
}
