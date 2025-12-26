namespace FileInspectorX;

/// <summary>
/// Text and markup format detection (JSON, XML/HTML, YAML, EML, CSV/TSV/INI/LOG) and Outlook MSG hints.
/// </summary>
internal static partial class Signatures {
    private const int BINARY_SCAN_LIMIT = 2048; // 2 KB: doubled from 1024 to reduce UTF-16 false negatives
    private const int HEADER_BYTES_FALLBACK = 4096; // align with default Settings.HeaderReadBytes for deeper text heuristics
    private const double UTF_NUL_RATIO_MIN = 0.2;
    private const double UTF32_NUL_RATIO_MIN = 0.6;
    private const double UTF32_NONNULL_POS_DOMINANCE = 0.7;
    private const int UTF16_NUL_DOMINANCE_FACTOR = 4;
    private const int JSON_DETECTION_SCAN_LIMIT = 2048;
    // see FileInspectorX.Settings for configurable thresholds

    internal static bool TryMatchMsg(string path, out ContentTypeDetectionResult? result) {
        result = null;
        try {
            using var fs = File.OpenRead(path);
            var header = new byte[8];
            if (fs.Read(header, 0, 8) != 8) return false;
            byte[] ole = new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };
            for (int i = 0; i < 8; i++) if (header[i] != ole[i]) return false;
            var buf = new byte[64 * 1024];
            fs.Seek(0, SeekOrigin.Begin);
            int read = fs.Read(buf, 0, buf.Length);
            var span = new ReadOnlySpan<byte>(buf, 0, read);
            if (span.IndexOf("__substg1.0_"u8) >= 0 || span.IndexOf("__properties_version1.0"u8) >= 0) {
                result = new ContentTypeDetectionResult { Extension = "msg", MimeType = "application/vnd.ms-outlook", Confidence = "Medium", Reason = "msg:ole" };
                return true;
            }
        } catch { }
        return false;
    }
}
