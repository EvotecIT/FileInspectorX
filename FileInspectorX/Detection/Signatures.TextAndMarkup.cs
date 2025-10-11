namespace FileInspectorX;

/// <summary>
/// Text and markup format detection (JSON, XML/HTML, YAML, EML, CSV/TSV/INI/LOG) and Outlook MSG hints.
/// </summary>
internal static partial class Signatures {
    internal static bool TryMatchText(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result) {
        result = null;
        if (src.Length == 0) return false;

        // BOMs
        if (src.Length >= 3 && src[0] == 0xEF && src[1] == 0xBB && src[2] == 0xBF) { result = new ContentTypeDetectionResult { Extension = "txt", MimeType = "text/plain; charset=utf-8", Confidence = "Medium", Reason = "bom:utf8" }; return true; }
        if (src.Length >= 2 && src[0] == 0xFF && src[1] == 0xFE) { result = new ContentTypeDetectionResult { Extension = "txt", MimeType = "text/plain; charset=utf-16le", Confidence = "Medium", Reason = "bom:utf16le" }; return true; }
        if (src.Length >= 2 && src[0] == 0xFE && src[1] == 0xFF) { result = new ContentTypeDetectionResult { Extension = "txt", MimeType = "text/plain; charset=utf-16be", Confidence = "Medium", Reason = "bom:utf16be" }; return true; }

        // Binary heuristic: NUL in head implies not text
        for (int i = 0; i < src.Length && i < 1024; i++) if (src[i] == 0x00) return false;

        // Trim leading whitespace for structure checks
        int start = 0; while (start < src.Length && char.IsWhiteSpace((char)src[start])) start++;
        var head = src.Slice(start, Math.Min(2048, src.Length - start));

        // RTF
        if (src.Length >= 5 && src[0] == '{' && src[1] == '\\' && src[2] == 'r' && src[3] == 't' && src[4] == 'f') { result = new ContentTypeDetectionResult { Extension = "rtf", MimeType = "application/rtf", Confidence = "Medium", Reason = "text:rtf" }; return true; }

        // JSON
        if (head.Length > 0 && (head[0] == (byte)'{' || head[0] == (byte)'[')) {
            if (head.IndexOf((byte)':') >= 0) { result = new ContentTypeDetectionResult { Extension = "json", MimeType = "application/json", Confidence = "Medium", Reason = "text:json" }; return true; }
        }
        // XML / HTML
        if (head.Length >= 5 && head[0] == (byte)'<') {
            if (head.Length >= 5 && head.Slice(0, 5).SequenceEqual("<?xml"u8)) { result = new ContentTypeDetectionResult { Extension = "xml", MimeType = "application/xml", Confidence = "Medium", Reason = "text:xml" }; return true; }
            if (head.IndexOf("<!DOCTYPE html"u8) >= 0 || head.IndexOf("<html"u8) >= 0) { result = new ContentTypeDetectionResult { Extension = "html", MimeType = "text/html", Confidence = "Medium", Reason = "text:html" }; return true; }
        }

        // YAML (starts with '---' typical)
        if (head.Length >= 3 && head[0] == (byte)'-' && head[1] == (byte)'-' && head[2] == (byte)'-') { result = new ContentTypeDetectionResult { Extension = "yml", MimeType = "application/x-yaml", Confidence = "Low", Reason = "text:yaml" }; return true; }

        // EML basics (check first two lines for typical headers)
        {
            int n1 = head.IndexOf((byte)'\n'); if (n1 < 0) n1 = head.Length;
            var l1 = head.Slice(0, n1);
            var rem = head.Slice(Math.Min(n1 + 1, head.Length));
            int n2 = rem.IndexOf((byte)'\n'); if (n2 < 0) n2 = rem.Length;
            var l2 = rem.Slice(0, n2);
            bool hasFrom = l1.StartsWith("From:"u8) || l2.StartsWith("From:"u8);
            bool hasSubj = l1.StartsWith("Subject:"u8) || l2.StartsWith("Subject:"u8);
            bool hasMimeVer = head.IndexOf("MIME-Version:"u8) >= 0;
            bool hasContentType = head.IndexOf("Content-Type:"u8) >= 0;
            if ((hasFrom && hasSubj) || (hasMimeVer && hasContentType)) { result = new ContentTypeDetectionResult { Extension = "eml", MimeType = "message/rfc822", Confidence = "Low", Reason = "text:eml" }; return true; }
        }

        // MSG basics (very weak text fallback)
        if (head.IndexOf("__substg1.0_"u8) >= 0) { result = new ContentTypeDetectionResult { Extension = "msg", MimeType = "application/vnd.ms-outlook", Confidence = "Low", Reason = "msg:marker" }; return true; }

        // CSV/TSV heuristics (look at first two lines)
        var span = head;
        int nl = head.IndexOf((byte)'\n'); if (nl < 0) nl = head.Length;
        var line1 = span.Slice(0, nl);
        var rest = span.Slice(Math.Min(nl + 1, span.Length));
        int nl2 = rest.IndexOf((byte)'\n'); if (nl2 < 0) nl2 = rest.Length;
        var line2 = rest.Slice(0, nl2);

        int commas1 = Count(line1, (byte)','); int commas2 = Count(line2, (byte)',');
        int tabs1 = Count(line1, (byte)'\t'); int tabs2 = Count(line2, (byte)'\t');
        if (commas1 >= 1 && commas2 >= 1 && Math.Abs(commas1 - commas2) <= 2) { result = new ContentTypeDetectionResult { Extension = "csv", MimeType = "text/csv", Confidence = "Low", Reason = "text:csv" }; return true; }
        if (tabs1 >= 1 && tabs2 >= 1 && Math.Abs(tabs1 - tabs2) <= 2) { result = new ContentTypeDetectionResult { Extension = "tsv", MimeType = "text/tab-separated-values", Confidence = "Low", Reason = "text:tsv" }; return true; }

        // INI heuristic
        if (line1.IndexOf((byte)'=') > 0 || line2.IndexOf((byte)'=') > 0) {
            if (head.IndexOf((byte)'[') >= 0 && head.IndexOf((byte)']') > head.IndexOf((byte)'[')) { result = new ContentTypeDetectionResult { Extension = "ini", MimeType = "text/plain", Confidence = "Low", Reason = "text:ini" }; return true; }
        }

        // LOG heuristic (timestamps at start of two lines)
        static bool LooksLikeTimestamp(ReadOnlySpan<byte> l) {
            if (l.Length < 10) return false;
            bool y = IsDigit(l[0]) && IsDigit(l[1]) && IsDigit(l[2]) && IsDigit(l[3]);
            bool sep1 = l[4] == (byte)'-' || l[4] == (byte)'/';
            bool m = IsDigit(l[5]) && IsDigit(l[6]);
            bool sep2 = l[7] == (byte)'-' || l[7] == (byte)'/';
            bool d = IsDigit(l[8]) && IsDigit(l[9]);
            return y && sep1 && m && sep2 && d;
        }
        if (LooksLikeTimestamp(line1) && LooksLikeTimestamp(line2)) { result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = "Low", Reason = "text:log" }; return true; }

        // Fallback: treat as plain text if mostly printable
        int printable = 0; int sample = Math.Min(1024, src.Length);
        for (int i = 0; i < sample; i++) { byte b = src[i]; if (b == 9 || b == 10 || b == 13 || (b >= 32 && b < 127)) printable++; }
        if ((double)printable / sample > 0.95) { result = new ContentTypeDetectionResult { Extension = "txt", MimeType = "text/plain", Confidence = "Low", Reason = "text:plain" }; return true; }
        return false;

        static int Count(ReadOnlySpan<byte> l, byte ch) { int c = 0; for (int i = 0; i < l.Length; i++) if (l[i] == ch) c++; return c; }
        static bool IsDigit(byte b) => b >= (byte)'0' && b <= (byte)'9';
    }

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

