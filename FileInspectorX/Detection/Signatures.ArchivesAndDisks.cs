namespace FileInspectorX;

/// <summary>
/// Archive and disk image signatures (CAB/TAR/ISO/UDF).
/// </summary>
internal static partial class Signatures {
    internal static bool TryMatch7z(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result) {
        result = null;
        // 7z signature: 37 7A BC AF 27 1C
        if (src.Length >= 6 && src[0] == 0x37 && src[1] == 0x7A && src[2] == 0xBC && src[3] == 0xAF && src[4] == 0x27 && src[5] == 0x1C) {
            result = new ContentTypeDetectionResult { Extension = "7z", MimeType = "application/x-7z-compressed", Confidence = "High", Reason = "7z" };
            return true;
        }
        return false;
    }

    internal static bool TryMatchRar(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result) {
        result = null;
        // RAR 4.x: 52 61 72 21 1A 07 00
        if (src.Length >= 7 && src[0] == 0x52 && src[1] == 0x61 && src[2] == 0x72 && src[3] == 0x21 && src[4] == 0x1A && src[5] == 0x07 && src[6] == 0x00) {
            result = new ContentTypeDetectionResult { Extension = "rar", MimeType = "application/vnd.rar", Confidence = "High", Reason = "rar4" };
            return true;
        }
        // RAR 5.x: 52 61 72 21 1A 07 01 00
        if (src.Length >= 8 && src[0] == 0x52 && src[1] == 0x61 && src[2] == 0x72 && src[3] == 0x21 && src[4] == 0x1A && src[5] == 0x07 && src[6] == 0x01 && src[7] == 0x00) {
            result = new ContentTypeDetectionResult { Extension = "rar", MimeType = "application/vnd.rar", Confidence = "High", Reason = "rar5" };
            return true;
        }
        return false;
    }
    internal static bool TryMatchCab(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result) {
        result = null;
        if (src.Length < 4) return false;
        if (src[0] == (byte)'M' && src[1] == (byte)'S' && src[2] == (byte)'C' && src[3] == (byte)'F') {
            result = new ContentTypeDetectionResult { Extension = "cab", MimeType = "application/vnd.ms-cab-compressed", Confidence = "High", Reason = "cab" };
            return true;
        }
        return false;
    }

    internal static bool TryMatchTar(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result) {
        result = null;
        if (src.Length < 265) return false;
        if (src.Slice(257, 5).SequenceEqual("ustar"u8)) { result = new ContentTypeDetectionResult { Extension = "tar", MimeType = "application/x-tar", Confidence = "High", Reason = "ustar" }; return true; }
        return false;
    }

    internal static bool TryMatchIso(string path, out ContentTypeDetectionResult? result) {
        result = null;
        try {
            using var fs = File.OpenRead(path);
            static bool checkAt(Stream s, long offset) {
                if (s.Length < offset + 5) return false;
                var arr = new byte[5];
                s.Seek(offset, SeekOrigin.Begin);
                var r = s.Read(arr, 0, arr.Length);
                return r == 5 && new ReadOnlySpan<byte>(arr).SequenceEqual("CD001"u8);
            }
            if (checkAt(fs, 0x8001) || checkAt(fs, 0x8801) || checkAt(fs, 0x9001) || ScanAnywhere(fs)) {
                result = new ContentTypeDetectionResult { Extension = "iso", MimeType = "application/x-iso9660-image", Confidence = "High", Reason = "iso:cd001" };
                return true;
            }
            static bool ScanAnywhere(Stream s) {
                try {
                    if (s.CanSeek) s.Seek(0, SeekOrigin.Begin);
                    ReadOnlySpan<byte> pat = "CD001"u8;
                    var buf = new byte[8192];
                    int read; long total = 0;
                    int cap = FileInspectorX.Settings.DetectionReadBudgetBytes;
                    while ((read = s.Read(buf, 0, buf.Length)) > 0 && total < cap) {
                        var span = new ReadOnlySpan<byte>(buf, 0, read);
                        for (int i = 0; i + pat.Length <= span.Length; i++) if (span.Slice(i, pat.Length).SequenceEqual(pat)) return true;
                        total += read;
                    }
                } catch { }
                return false;
            }
        } catch { }
        return false;
    }

    internal static bool TryMatchUdf(string path, out ContentTypeDetectionResult? result) {
        result = null;
        try {
            using var fs = File.OpenRead(path);
            const int sector = 2048;
            long start = 16L * sector + 1; // byte index for 5-char id
            var ids = new[] {
                System.Text.Encoding.ASCII.GetBytes("NSR02"),
                System.Text.Encoding.ASCII.GetBytes("NSR03"),
                System.Text.Encoding.ASCII.GetBytes("BEA01"),
                System.Text.Encoding.ASCII.GetBytes("TEA01")
            };
            var buf = new byte[5];
            int bea = -1; int nsr = -1; string nsrVer = ""; int tea = -1;
            for (int i = 0; i < 32; i++) {
                long off = start + i * sector;
                if (fs.Length < off + 5) break;
                fs.Seek(off, SeekOrigin.Begin);
                if (fs.Read(buf, 0, 5) != 5) break;
                var span = new ReadOnlySpan<byte>(buf);
                if (span.SequenceEqual(ids[2])) bea = i; // BEA01
                else if (span.SequenceEqual(ids[0]) || span.SequenceEqual(ids[1])) { nsr = i; nsrVer = span.SequenceEqual(ids[0]) ? "nsr02" : "nsr03"; }
                else if (span.SequenceEqual(ids[3])) tea = i; // TEA01
            }
            if (nsr >= 0) {
                var confidence = (bea >= 0 && bea < nsr && tea > nsr) ? "High" : "Medium";
                result = new ContentTypeDetectionResult { Extension = "udf", MimeType = "application/udf", Confidence = confidence, Reason = $"udf:{nsrVer}{(confidence == "High" ? ":bea+tea" : "")}" };
                return true;
            }
        } catch { }
        return false;
    }

    internal static bool TryMatchDmg(string path, out ContentTypeDetectionResult? result) {
        // Apple UDIF (DMG) has 512-byte trailer at EOF starting with 'koly'
        result = null;
        try {
            using var fs = File.OpenRead(path);
            if (fs.Length < 512) return false;
            fs.Seek(-512, SeekOrigin.End);
            var buf = new byte[4];
            int n = fs.Read(buf, 0, 4);
            if (n == 4 && buf[0] == (byte)'k' && buf[1] == (byte)'o' && buf[2] == (byte)'l' && buf[3] == (byte)'y') {
                result = new ContentTypeDetectionResult { Extension = "dmg", MimeType = "application/x-apple-diskimage", Confidence = "Medium", Reason = "udif:koly" };
                return true;
            }
        } catch { }
        return false;
    }
}
