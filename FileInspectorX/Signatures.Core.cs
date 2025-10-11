// (deliberately no extra using requirements; compatible with net472 via System.Memory)

namespace FileInspectorX;

internal static partial class Signatures {
    internal sealed class Signature {
        public readonly string Extension;
        public readonly string MimeType;
        public readonly byte[] Prefix;
        public readonly int Offset;
        public Signature(string extension, string mimeType, byte[] prefix, int offset = 0) {
            Extension = extension; MimeType = mimeType; Prefix = prefix; Offset = offset;
        }
    }

    // Common magic signatures (subset; easy to expand)
    internal static readonly Signature[] Core = new[] {
        new Signature("png",  "image/png",            new byte[]{0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A}),
        new Signature("jpg",  "image/jpeg",           new byte[]{0xFF,0xD8,0xFF}),
        new Signature("gif",  "image/gif",            System.Text.Encoding.ASCII.GetBytes("GIF87a")),
        new Signature("gif",  "image/gif",            System.Text.Encoding.ASCII.GetBytes("GIF89a")),
        new Signature("pdf",  "application/pdf",      System.Text.Encoding.ASCII.GetBytes("%PDF-")),
        new Signature("zip",  "application/zip",      new byte[]{0x50,0x4B,0x03,0x04}),
        new Signature("zip",  "application/zip",      new byte[]{0x50,0x4B,0x05,0x06}),
        new Signature("zip",  "application/zip",      new byte[]{0x50,0x4B,0x07,0x08}),
        new Signature("7z",   "application/x-7z-compressed", new byte[]{0x37,0x7A,0xBC,0xAF,0x27,0x1C}),
        new Signature("rar",  "application/vnd.rar",  System.Text.Encoding.ASCII.GetBytes("Rar!\x1A\x07")),
        new Signature("gz",   "application/gzip",     new byte[]{0x1F,0x8B}),
        new Signature("bmp",  "image/bmp",            new byte[]{0x42,0x4D}),
        new Signature("ogg",  "application/ogg",      System.Text.Encoding.ASCII.GetBytes("OggS")),
        new Signature("mp3",  "audio/mpeg",          System.Text.Encoding.ASCII.GetBytes("ID3")),
        new Signature("exe",  "application/x-msdownload", new byte[]{0x4D,0x5A}), // MZ
        new Signature("ole2", "application/vnd.ms-office", new byte[]{0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1}),
    };

    internal static IEnumerable<Signature> All() {
        // Merge core list with consolidated imported signatures
        Signature[] standard;
        try { standard = Standard; } catch { standard = Array.Empty<Signature>(); }
        return Core.Concat(standard);
    }

    internal static bool Match(ReadOnlySpan<byte> src, Signature sig) {
        var off = sig.Offset;
        if (off < 0 || off + sig.Prefix.Length > src.Length) return false;
        return src.Slice(off, sig.Prefix.Length).SequenceEqual(sig.Prefix);
    }

    internal static bool TryMatchRiff(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result) {
        result = null;
        if (src.Length < 12) return false;
        if (!src.Slice(0, 4).SequenceEqual("RIFF"u8)) return false;
        var fcc = src.Slice(8, 4);
        if (fcc.SequenceEqual("WAVE"u8)) {
            result = new ContentTypeDetectionResult { Extension = "wav", MimeType = "audio/wav", Confidence = "High", Reason = "riff:wav" };
            return true;
        }
        if (fcc.SequenceEqual("AVI "u8)) {
            result = new ContentTypeDetectionResult { Extension = "avi", MimeType = "video/x-msvideo", Confidence = "High", Reason = "riff:avi" };
            return true;
        }
        if (fcc.SequenceEqual("WEBP"u8)) {
            result = new ContentTypeDetectionResult { Extension = "webp", MimeType = "image/webp", Confidence = "High", Reason = "riff:webp" };
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

    internal static bool TryMatchGlb(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result) {
        result = null;
        if (src.Length < 4) return false;
        if (src.Slice(0, 4).SequenceEqual("glTF"u8)) {
            result = new ContentTypeDetectionResult { Extension = "glb", MimeType = "model/gltf-binary", Confidence = "High", Reason = "glb" };
            return true;
        }
        return false;
    }

    internal static bool TryMatchTiff(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result) {
        result = null;
        if (src.Length < 4) return false;
        // Little-endian TIFF: II 2A 00
        if (src[0] == 0x49 && src[1] == 0x49 && src[2] == 0x2A && src[3] == 0x00) {
            result = new ContentTypeDetectionResult { Extension = "tif", MimeType = "image/tiff", Confidence = "High", Reason = "tiff:le" };
            return true;
        }
        // Big-endian TIFF: MM 00 2A ; BigTIFF: MM 00 2B
        if (src[0] == 0x4D && src[1] == 0x4D && src[2] == 0x00 && (src[3] == 0x2A || src[3] == 0x2B)) {
            result = new ContentTypeDetectionResult { Extension = "tif", MimeType = "image/tiff", Confidence = "High", Reason = src[3] == 0x2B ? "tiff:be64" : "tiff:be" };
            return true;
        }
        return false;
    }

    internal static bool TryMatchElf(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result) {
        // 0x7F,'E','L','F' at offset 0; refine class/endian for reason
        result = null;
        if (src.Length < 6) return false;
        if (!(src[0] == 0x7F && src[1] == (byte)'E' && src[2] == (byte)'L' && src[3] == (byte)'F')) return false;
        var clazz = src[4]; // 1=32, 2=64
        var endian = src[5]; // 1=little, 2=big
        string c = clazz == 2 ? "64" : clazz == 1 ? "32" : "?";
        string e = endian == 2 ? "be" : endian == 1 ? "le" : "?";
        string et = "";
        string mach = "";
        if (src.Length >= 18) {
            int eTypeOff = 16;
            ushort etype;
            if (endian == 2 && eTypeOff + 1 < src.Length) // big-endian
                etype = (ushort)((src[eTypeOff] << 8) | src[eTypeOff + 1]);
            else if (eTypeOff + 1 < src.Length)
                etype = (ushort)(src[eTypeOff] | (src[eTypeOff + 1] << 8));
            else etype = 0;
            // 1=REL,2=EXEC,3=DYN,4=CORE
            et = etype == 1 ? "rel" : etype == 2 ? "exec" : etype == 3 ? "dyn" : etype == 4 ? "core" : "?";
        }
        if (src.Length >= 20) {
            int eMachOff = 18;
            ushort emach;
            if (endian == 2 && eMachOff + 1 < src.Length)
                emach = (ushort)((src[eMachOff] << 8) | src[eMachOff + 1]);
            else if (eMachOff + 1 < src.Length)
                emach = (ushort)(src[eMachOff] | (src[eMachOff + 1] << 8));
            else emach = 0;
            mach = emach switch {
                3 => "x86",
                62 => "x86_64",
                40 => "arm",
                183 => "aarch64",
                8 => "mips",
                50 => "ia64",
                243 => "riscv",
                _ => "?"
            };
        }
        var r = $"elf:{c}-{e}" + (et == "" ? "" : $":{et}") + (mach == "" ? "" : $":{mach}");
        result = new ContentTypeDetectionResult { Extension = "elf", MimeType = "application/x-elf", Confidence = "High", Reason = r };
        return true;
    }

    internal static bool TryMatchIso(string path, out ContentTypeDetectionResult? result) {
        // ISO9660 primary/supplementary volume descriptor contains 'CD001' at offset
        // 0x8001 (sector 16 + 1), sometimes also at 0x8801 / 0x9001 for other descriptors
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
                    int read;
                    long total = 0;
                    // simple KMP-less scan; good enough for small files
                    while ((read = s.Read(buf, 0, buf.Length)) > 0 && total < 1_000_000) {
                        var span = new ReadOnlySpan<byte>(buf, 0, read);
                        for (int i = 0; i + pat.Length <= span.Length; i++) {
                            if (span.Slice(i, pat.Length).SequenceEqual(pat)) return true;
                        }
                        total += read;
                    }
                } catch { }
                return false;
            }
        } catch { /* ignore IO */ }
        return false;
    }

    internal static bool TryMatchUdf(string path, out ContentTypeDetectionResult? result) {
        // UDF VRS area near sector 16 has BEA01 / NSR02 / NSR03 / TEA01 markers at byte 1..5
        result = null;
        try {
            using var fs = File.OpenRead(path);
            // scan a handful of 2KB sectors starting at sector 16
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
                else if (span.SequenceEqual(ids[0]) || span.SequenceEqual(ids[1])) { nsr = i; nsrVer = span.SequenceEqual(ids[0]) ? "nsr02" : "nsr03"; } else if (span.SequenceEqual(ids[3])) tea = i; // TEA01
            }
            if (nsr >= 0) {
                // High only if BEA appears before NSR and TEA after NSR
                var confidence = (bea >= 0 && bea < nsr && tea > nsr) ? "High" : "Medium";
                result = new ContentTypeDetectionResult { Extension = "udf", MimeType = "application/udf", Confidence = confidence, Reason = $"udf:{nsrVer}{(confidence == "High" ? ":bea+tea" : "")}" };
                return true;
            }
        } catch { }
        return false;
    }

    internal static bool TryMatchTar(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result) {
        // USTAR signature at offset 257
        result = null;
        if (src.Length < 265) return false;
        if (src.Slice(257, 5).SequenceEqual("ustar"u8)) {
            result = new ContentTypeDetectionResult { Extension = "tar", MimeType = "application/x-tar", Confidence = "High", Reason = "ustar" };
            return true;
        }
        return false;
    }

    internal static bool TryMatchSqlite(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result) {
        result = null;
        var sig = System.Text.Encoding.ASCII.GetBytes("SQLite format 3\x00");
        if (src.Length >= sig.Length && src.Slice(0, sig.Length).SequenceEqual(sig)) {
            result = new ContentTypeDetectionResult { Extension = "sqlite", MimeType = "application/vnd.sqlite3", Confidence = "High", Reason = "sqlite" };
            return true;
        }
        return false;
    }

    internal static bool TryMatchFtyp(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result) {
        // MP4/QuickTime/HEIF family: 'ftyp' at offset 4 (big-endian box size at 0..3)
        result = null;
        if (src.Length < 12) return false;
        if (!src.Slice(4, 4).SequenceEqual("ftyp"u8)) return false;
        var brand = src.Slice(8, 4);
        // Collect major + a couple compatible brands if present, to better classify (m4a/3gp, etc.)
        ReadOnlySpan<byte> comp = src.Length >= 20 ? src.Slice(16, Math.Min(8, src.Length - 16)) : ReadOnlySpan<byte>.Empty; // up to two brands

        static bool HasBrand(ReadOnlySpan<byte> major, ReadOnlySpan<byte> compat, ReadOnlySpan<byte> sought) {
            if (major.SequenceEqual(sought)) return true;
            for (int i = 0; i + 4 <= compat.Length; i += 4)
                if (compat.Slice(i, 4).SequenceEqual(sought)) return true;
            return false;
        }

        // HEIF brands
        if (brand.SequenceEqual("heic"u8) || brand.SequenceEqual("heif"u8) || HasBrand(brand, comp, "mif1"u8) || brand.SequenceEqual("hevc"u8)) {
            result = new ContentTypeDetectionResult { Extension = "heic", MimeType = "image/heic", Confidence = "High", Reason = "ftyp:heif" };
            return true;
        }
        // Audio MP4 (M4A)
        if (HasBrand(brand, comp, "M4A "u8) || HasBrand(brand, comp, "M4B "u8)) {
            result = new ContentTypeDetectionResult { Extension = "m4a", MimeType = "audio/mp4", Confidence = "High", Reason = "ftyp:m4a" };
            return true;
        }
        // 3GP/3G2
        if (HasBrand(brand, comp, "3gp4"u8) || HasBrand(brand, comp, "3g2a"u8)) {
            result = new ContentTypeDetectionResult { Extension = "3gp", MimeType = "video/3gpp", Confidence = "High", Reason = "ftyp:3gp" };
            return true;
        }
        // QuickTime/MP4 common brands (isom, mp41, mp42, MSNV, etc.)
        result = new ContentTypeDetectionResult { Extension = "mp4", MimeType = "video/mp4", Confidence = "High", Reason = "ftyp:mp4" };
        return true;
    }

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

        // EML basics
        // Check first two lines for typical headers
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

        // MSG basics (very weak text fallback): Outlook .msg are OLE; however some dumped text may contain markers
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
            // e.g., 2025-10-10 or 2025/10/10
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
        int printable = 0;
        int sample = Math.Min(1024, src.Length);
        for (int i = 0; i < sample; i++) {
            byte b = src[i];
            if (b == 9 || b == 10 || b == 13 || (b >= 32 && b < 127)) printable++;
        }
        if ((double)printable / sample > 0.95) { result = new ContentTypeDetectionResult { Extension = "txt", MimeType = "text/plain", Confidence = "Low", Reason = "text:plain" }; return true; }
        return false;

        static int Count(ReadOnlySpan<byte> l, byte ch) { int c = 0; for (int i = 0; i < l.Length; i++) if (l[i] == ch) c++; return c; }
        static bool IsDigit(byte b) => b >= (byte)'0' && b <= (byte)'9';
    }
    internal static bool TryMatchMachO(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result) {
        result = null;
        if (src.Length < 4) return false;
        uint m = (uint)(src[0] << 24 | src[1] << 16 | src[2] << 8 | src[3]);
        // 0xFEEDFACE BE (32), 0xCEFAEDFE LE (32), 0xFEEDFACF BE (64), 0xCFEAEDFE LE (64)
        // Fat: 0xCAFEBABE (BE), 0xBEBAFECA (LE)
        switch (m) {
            case 0xFEEDFACE: result = new ContentTypeDetectionResult { Extension = "macho", MimeType = "application/x-mach-binary", Confidence = "High", Reason = "macho:be32" }; return true;
            case 0xCEFAEDFE: result = new ContentTypeDetectionResult { Extension = "macho", MimeType = "application/x-mach-binary", Confidence = "High", Reason = "macho:le32" }; return true;
            case 0xFEEDFACF: result = new ContentTypeDetectionResult { Extension = "macho", MimeType = "application/x-mach-binary", Confidence = "High", Reason = "macho:be64" }; return true;
            case 0xCFFAEDFE: result = new ContentTypeDetectionResult { Extension = "macho", MimeType = "application/x-mach-binary", Confidence = "High", Reason = "macho:le64" }; return true;
            case 0xCAFEBABE: result = new ContentTypeDetectionResult { Extension = "macho", MimeType = "application/x-mach-binary", Confidence = "High", Reason = "macho:fat" }; return true;
            case 0xBEBAFECA: result = new ContentTypeDetectionResult { Extension = "macho", MimeType = "application/x-mach-binary", Confidence = "High", Reason = "macho:fat-le" }; return true;
        }
        return false;
    }

    internal static bool TryMatchMsg(string path, out ContentTypeDetectionResult? result) {
        // Outlook .msg are OLE CF files (D0 CF 11 E0 A1 B1 1A E1) containing __substg1.0_* streams.
        result = null;
        try {
            using var fs = File.OpenRead(path);
            var header = new byte[8];
            if (fs.Read(header, 0, 8) != 8) return false;
            byte[] ole = new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };
            for (int i = 0; i < 8; i++) if (header[i] != ole[i]) return false;
            // scan first 64KB for marker
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