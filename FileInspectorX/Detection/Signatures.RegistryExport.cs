namespace FileInspectorX;

/// <summary>Structural validation for Windows Registry export text headers.</summary>
internal static partial class Signatures
{
    internal static bool TryMatchRegistryExport(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
    {
        result = null;
        bool versionFour = HasHeaderLine(src, "REGEDIT4"u8);
        bool versionFive = HasHeaderLine(src, "Windows Registry Editor Version 5.00"u8);
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

    private static bool HasHeaderLine(ReadOnlySpan<byte> src, ReadOnlySpan<byte> header)
    {
        if (src.Length <= header.Length || !src.Slice(0, header.Length).SequenceEqual(header)) return false;
        return src[header.Length] is (byte)'\r' or (byte)'\n';
    }
}
