namespace FileInspectorX;

/// <summary>
/// Windows-specific binary format detection.
/// </summary>
internal static partial class Signatures {
    private static readonly byte[] ShellLinkClassId = {
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
    };

    internal static bool TryMatchShellLink(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result) {
        result = null;
        if (src.Length < 76 || src[0] != 0x4C || src[1] != 0 || src[2] != 0 || src[3] != 0)
            return false;

        for (int i = 0; i < ShellLinkClassId.Length; i++)
            if (src[4 + i] != ShellLinkClassId[i]) return false;

        result = new ContentTypeDetectionResult {
            Extension = "lnk",
            MimeType = "application/x-ms-shortcut",
            Confidence = "High",
            Reason = "shell-link:header-clsid"
        };
        return true;
    }
}
