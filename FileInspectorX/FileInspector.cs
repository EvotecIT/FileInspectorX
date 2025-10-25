using System.IO.Compression;
using System.Text;

namespace FileInspectorX;

/// <summary>
/// Minimal, dependency-free file inspector based on magic bytes and lightweight heuristics.
/// Provides fast content type detection and optional analysis helpers across .NET 8, .NET Framework 4.7.2 and .NET Standard 2.0.
/// </summary>
public static partial class FileInspector {
    /// <summary>
    /// Options controlling enrichment of detection output (hashes, magic header capture).
    /// </summary>
    public sealed class DetectionOptions {
        /// <summary>When true, computes a SHA-256 hash of the full stream/file and exposes it on <see cref="ContentTypeDetectionResult.Sha256Hex"/>.</summary>
        public bool ComputeSha256 { get; set; } = false;
        /// <summary>When &gt; 0, captures the first N bytes of the header as uppercase hex into <see cref="ContentTypeDetectionResult.MagicHeaderHex"/>.</summary>
        public int MagicHeaderBytes { get; set; } = 0; // 0 = skip
        /// <summary>
        /// When true, indicates callers intend a detection-only pass. Helper APIs may honor this by running
        /// only detection and returning a minimal <see cref="FileInspectorX.FileAnalysis"/> (when used with
        /// <see cref="FileInspectorX.FileInspector.Inspect(string, FileInspectorX.FileInspector.DetectionOptions?)"/>).
        /// This does not affect <see cref="FileInspectorX.FileInspector.Detect(string)"/> which is always detection-only.
        /// </summary>
        public bool DetectOnly { get; set; } = false;

        /// <summary>Include container analysis (ZIP/TAR summaries, inner-archive hints). Default true.</summary>
        public bool IncludeContainer { get; set; } = true;
        /// <summary>Include permissions/ownership snapshot. Default true.</summary>
        public bool IncludePermissions { get; set; } = true;
        /// <summary>Include Authenticode/package signature analysis where applicable. Default true.</summary>
        public bool IncludeAuthenticode { get; set; } = true;
        /// <summary>Include references extraction from config files (Task XML, scripts.ini/xml). Default true.</summary>
        public bool IncludeReferences { get; set; } = true;
        /// <summary>Include installer/package metadata (MSIX/APPX/VSIX/MSI). Default true.</summary>
        public bool IncludeInstaller { get; set; } = true;
        /// <summary>Compute Assessment (score/decision) and attach to the result. Default true.</summary>
        public bool IncludeAssessment { get; set; } = true;
    }

    /// <summary>
    /// Compares a declared/expected file extension with the detected extension.
    /// </summary>
    /// <param name="declaredExtension">The file extension provided by the caller or file name (with or without dot).</param>
    /// <param name="detected">The detection result produced by <see cref="Detect(string)"/> or contained in <see cref="FileAnalysis.Detection"/>.</param>
    /// <returns>
    /// A tuple where <c>Mismatch</c> indicates whether the extensions differ and <c>Reason</c>
    /// describes the comparison (e.g., "match" or "decl:txt vs det:pdf").
    /// </returns>
    public static (bool Mismatch, string Reason) CompareDeclared(string? declaredExtension, ContentTypeDetectionResult? detected) {
        var decl = (declaredExtension ?? string.Empty).Trim().TrimStart('.');
        if (detected is null || string.IsNullOrEmpty(decl)) return (false, "no-detection-or-declared");
        var det = (detected.Extension ?? string.Empty).Trim();

        // Treat common synonyms as equivalent (avoid false mismatches)
        static bool Equivalent(string a, string b) {
            if (string.Equals(a, b, StringComparison.OrdinalIgnoreCase)) return true;
            // .cer <-> .crt
            if ((a.Equals("cer", StringComparison.OrdinalIgnoreCase) && b.Equals("crt", StringComparison.OrdinalIgnoreCase)) ||
                (a.Equals("crt", StringComparison.OrdinalIgnoreCase) && b.Equals("cer", StringComparison.OrdinalIgnoreCase))) return true;
            // .yml <-> .yaml
            if ((a.Equals("yml", StringComparison.OrdinalIgnoreCase) && b.Equals("yaml", StringComparison.OrdinalIgnoreCase)) ||
                (a.Equals("yaml", StringComparison.OrdinalIgnoreCase) && b.Equals("yml", StringComparison.OrdinalIgnoreCase))) return true;
            // .jpg <-> .jpeg
            if ((a.Equals("jpg", StringComparison.OrdinalIgnoreCase) && b.Equals("jpeg", StringComparison.OrdinalIgnoreCase)) ||
                (a.Equals("jpeg", StringComparison.OrdinalIgnoreCase) && b.Equals("jpg", StringComparison.OrdinalIgnoreCase))) return true;
            // .htm <-> .html
            if ((a.Equals("htm", StringComparison.OrdinalIgnoreCase) && b.Equals("html", StringComparison.OrdinalIgnoreCase)) ||
                (a.Equals("html", StringComparison.OrdinalIgnoreCase) && b.Equals("htm", StringComparison.OrdinalIgnoreCase))) return true;
            // Plain‑text family: treat generic text and log/config notes as equivalent
            if (InPlainTextFamily(a) && InPlainTextFamily(b)) return true;
            return false;
        }

        static bool InPlainTextFamily(string ext)
        {
            // Conservative set: generic text and common note/config/log formats; excludes csv/tsv/scripts
            switch ((ext ?? string.Empty).ToLowerInvariant())
            {
                case "txt":
                case "text":
                case "log":
                case "cfg":
                case "conf":
                case "ini":
                case "md":
                case "markdown":
                case "properties":
                case "prop":
                    return true;
                default:
                    return false;
            }
        }

        var mismatch = !Equivalent(decl, det);
        var reason = mismatch ? $"decl:{decl} vs det:{detected.Extension}" : "match";
        return (mismatch, reason);
    }

    /// <summary>
    /// Converts up to <paramref name="bytes"/> from <paramref name="data"/> into an uppercase hex string (no separators).
    /// </summary>
    public static string MagicHeaderHex(ReadOnlySpan<byte> data, int bytes) {
        var n = Math.Min(bytes, data.Length);
        if (n <= 0) return string.Empty;
        var chars = new char[n * 2];
        for (int i = 0; i < n; i++) {
            var b = data[i];
            chars[i * 2] = GetHexNibble(b >> 4);
            chars[i * 2 + 1] = GetHexNibble(b & 0xF);
        }
        return new string(chars);

        static char GetHexNibble(int v) => (char)(v < 10 ? ('0' + v) : ('A' + (v - 10)));
    }

    /// <summary>
    /// Reads the first <paramref name="bytes"/> from the file at <paramref name="path"/> and returns them as uppercase hex.
    /// </summary>
    public static string MagicHeaderHex(string path, int bytes) {
        try {
            using var fs = File.OpenRead(path);
            var buf = new byte[Math.Min(bytes, 1 << 20)]; // cap at 1MB for safety
            var read = fs.Read(buf, 0, buf.Length);
            return MagicHeaderHex(new ReadOnlySpan<byte>(buf, 0, read), bytes);
        } catch { return string.Empty; }
    }
    /// <summary>
    /// Detects content type from a file path using magic bytes and heuristics. Returns null when unknown.
    /// Fast and minimal: does not perform container/PDF/PE/permission analysis.
    /// </summary>
    public static ContentTypeDetectionResult? Detect(string path) {
        try {
            if (Signatures.TryMatchUdf(path, out var udf)) return udf;
            if (Signatures.TryMatchIso(path, out var iso)) return iso;
            if (Signatures.TryMatchDmg(path, out var dmg)) return dmg;
            using var fs = File.OpenRead(path);
            // Try MSG (.msg) path-based detection (OLE with msg markers)
            if (Signatures.TryMatchMsg(path, out var msg)) return msg;
            return Detect(fs, null);
        } catch { return null; }
    }

    /// <summary>
    /// Detects content type from a file path and enriches the result using <paramref name="options"/>.
    /// </summary>
    public static ContentTypeDetectionResult? Detect(string path, DetectionOptions? options) {
        try {
            if (Signatures.TryMatchUdf(path, out var udf)) return udf;
            if (Signatures.TryMatchIso(path, out var iso)) return iso;
            if (Signatures.TryMatchDmg(path, out var dmg)) return dmg;
            using var fs = File.OpenRead(path);
            if (Signatures.TryMatchMsg(path, out var msg)) return msg;
            return Detect(fs, options);
        } catch { return null; }
    }

    /// <summary>
    /// Detects content type from a readable stream; the stream is rewound where possible.
    /// Fast and minimal: does not perform container/PDF/PE/permission analysis.
    /// </summary>
    public static ContentTypeDetectionResult? Detect(Stream stream, DetectionOptions? options = null) {
        options ??= new DetectionOptions();
        var headLen = Math.Max(256, Math.Min(Settings.HeaderReadBytes, 1 << 20));
        var header = new byte[headLen];
        if (stream.CanSeek) stream.Seek(0, SeekOrigin.Begin);
        var read = stream.Read(header, 0, header.Length);
        var src = new ReadOnlySpan<byte>(header, 0, read);

        // TAR, RIFF, EVTX, ESE/Registry, SQLite quick checks first
        if (Signatures.TryMatchTar(src, out var tar)) return Enrich(tar, src, stream, options);
        if (Signatures.TryMatchRiff(src, out var riff)) return Enrich(riff, src, stream, options);
        if (Signatures.TryMatchEvtx(src, out var evtx)) return Enrich(evtx, src, stream, options);
        if (Signatures.TryMatchEse(src, out var ese)) return Enrich(ese, src, stream, options);
        if (Signatures.TryMatchRegistryHive(src, out var hive)) return Enrich(hive, src, stream, options);
        if (Signatures.TryMatchFtyp(src, out var ftyp)) return Enrich(ftyp, src, stream, options);
        if (Signatures.TryMatchSqlite(src, out var sqlite)) return Enrich(sqlite, src, stream, options);
        if (Signatures.TryMatchPkcs12(src, out var p12)) return Enrich(p12, src, stream, options);
        if (Signatures.TryMatchDerCertificate(src, out var der)) return Enrich(der, src, stream, options);
        if (Signatures.TryMatchOpenPgpBinary(src, out var pgpbin)) return Enrich(pgpbin, src, stream, options);
        if (Signatures.TryMatchKeePassKdbx(src, out var kdbx)) return Enrich(kdbx, src, stream, options);
        if (Signatures.TryMatch7z(src, out var _7z)) return Enrich(_7z, src, stream, options);
        if (Signatures.TryMatchRar(src, out var rar)) return Enrich(rar, src, stream, options);
        if (Signatures.TryMatchElf(src, out var elf)) return Enrich(elf, src, stream, options);
        if (Signatures.TryMatchMachO(src, out var macho)) return Enrich(macho, src, stream, options);
        if (Signatures.TryMatchCab(src, out var cab)) return Enrich(cab, src, stream, options);
        if (Signatures.TryMatchGlb(src, out var glb)) return Enrich(glb, src, stream, options);
        if (Signatures.TryMatchTiff(src, out var tiff)) return Enrich(tiff, src, stream, options);
        // ISO requires file path offsets; skip here

        foreach (var sig in Signatures.All()) {
            if (Signatures.Match(src, sig)) {
                if (sig.Extension == "zip") {
                    var refined = TryRefineZipOOxml(stream);
                    if (refined != null) return Enrich(refined, src, stream, options);
                    var confZip = sig.Prefix != null && sig.Prefix.Length >= 4 ? "High" : (sig.Prefix != null && sig.Prefix.Length == 3 ? "Medium" : "Low");
                    var guess = TryGuessZipSubtype(stream, out var guessMime);
                    var basicZip = new ContentTypeDetectionResult {
                        Extension = sig.Extension,
                        MimeType = NormalizeMime(sig.Extension, sig.MimeType),
                        Confidence = confZip,
                        Reason = $"magic:{sig.Extension}",
                        GuessedExtension = guess
                    };
                    return Enrich(basicZip, src, stream, options);
                }
                if (sig.Extension == "ole2" && stream is not null) {
                    var refinedOle = TryRefineOle2Subtype(stream);
                    if (refinedOle != null) return Enrich(refinedOle, src, stream, options);
                }
                var conf = sig.Prefix != null && sig.Prefix.Length >= 4 ? "High" : (sig.Prefix != null && sig.Prefix.Length == 3 ? "Medium" : "Low");
                var basic = new ContentTypeDetectionResult {
                    Extension = sig.Extension,
                    MimeType = NormalizeMime(sig.Extension, sig.MimeType),
                    Confidence = conf,
                    Reason = $"magic:{sig.Extension}"
                };
                return Enrich(basic, src, stream, options);
            }
        }

        if (Signatures.TryMatchText(src, out var text)) {
            if (text is not null && text.Extension == "json") {
                var refined = TryRefineGltfJson(stream);
                if (refined != null) return Enrich(refined, src, stream, options);
            }
            return Enrich(text, src, stream, options);
        }
        return Enrich(null, src, stream, options);
    }

    private static ContentTypeDetectionResult? TryRefineGltfJson(Stream stream) {
        try {
            long pos = stream.CanSeek ? stream.Position : 0;
            if (stream.CanSeek) stream.Seek(0, SeekOrigin.Begin);
            using var reader = new StreamReader(stream, System.Text.Encoding.UTF8, true, 8192, leaveOpen: true);
            char[] buf = new char[8192];
            int n = reader.Read(buf, 0, buf.Length);
            var s = new string(buf, 0, n);
            if ((s.IndexOf("\"asset\"", StringComparison.OrdinalIgnoreCase) >= 0 && s.IndexOf("\"version\"", StringComparison.OrdinalIgnoreCase) >= 0) &&
                (s.IndexOf("\"scenes\"", StringComparison.OrdinalIgnoreCase) >= 0 || s.IndexOf("\"nodes\"", StringComparison.OrdinalIgnoreCase) >= 0)) {
                if (stream.CanSeek) stream.Seek(pos, SeekOrigin.Begin);
                return new ContentTypeDetectionResult { Extension = "gltf", MimeType = "model/gltf+json", Confidence = "Medium", Reason = "gltf:json" };
            }
            if (stream.CanSeek) stream.Seek(pos, SeekOrigin.Begin);
        } catch { }
        return null;
    }

    private static void TryParseP7b(string path, FileAnalysis res)
    {
        try
        {
            var raw = File.ReadAllBytes(path);
            var cms = new System.Security.Cryptography.Pkcs.SignedCms();
            cms.Decode(raw);
            var certs = cms.Certificates;
            if (certs != null && certs.Count > 0)
            {
                var subs = new List<string>(certs.Count);
                foreach (var c in certs)
                {
                    try { if (!string.IsNullOrWhiteSpace(c.Subject)) subs.Add(c.Subject); } catch { }
                }
                res.CertificateBundleCount = certs.Count;
                res.CertificateBundleSubjects = subs;
            }
        } catch { }
    }

    /// <summary>
    /// Unified entry point for consumers who want a single method.
    /// When <paramref name="options"/> has <c>DetectOnly</c> true, returns a minimal <see cref="FileInspectorX.FileAnalysis"/>
    /// wrapping detection (equivalent to calling <see cref="FileInspectorX.FileInspector.Detect(string, FileInspectorX.FileInspector.DetectionOptions?)"/>).
    /// Otherwise performs full analysis (equivalent to <see cref="FileInspectorX.FileInspector.Analyze(string, FileInspectorX.FileInspector.DetectionOptions?)"/>).
    /// <example>
    /// var detOnly = FileInspector.Inspect(path, new FileInspector.DetectionOptions { DetectOnly = true });
    /// var full    = FileInspector.Inspect(path, new FileInspector.DetectionOptions { ComputeSha256 = true });
    /// </example>
    /// </summary>
    public static FileAnalysis Inspect(string path, DetectionOptions? options = null)
    {
        options ??= new DetectionOptions();
        if (options.DetectOnly)
        {
            var det = Detect(path, options);
            return new FileAnalysis { Detection = det, Kind = KindClassifier.Classify(det), Flags = ContentFlags.None };
        }
        return Analyze(path, options);
    }

    private static ContentTypeDetectionResult? TryRefineOle2Subtype(Stream stream) {
        try {
            long pos = stream.CanSeek ? stream.Position : 0;
            if (stream.CanSeek) stream.Seek(0, SeekOrigin.Begin);
            int cap = Math.Max(8 * 1024, Math.Min(Settings.DetectionReadBudgetBytes, 512 * 1024));
            var buf = new byte[cap];
            int n = stream.Read(buf, 0, buf.Length);
            if (stream.CanSeek) stream.Seek(pos, SeekOrigin.Begin);
            var ascii = System.Text.Encoding.ASCII.GetString(buf, 0, n);
            if (ascii.IndexOf("WordDocument", StringComparison.OrdinalIgnoreCase) >= 0)
                return new ContentTypeDetectionResult { Extension = "doc", MimeType = "application/msword", Confidence = "Medium", Reason = "ole2:word" };
            if (ascii.IndexOf("Workbook", StringComparison.OrdinalIgnoreCase) >= 0)
                return new ContentTypeDetectionResult { Extension = "xls", MimeType = "application/vnd.ms-excel", Confidence = "Medium", Reason = "ole2:xls" };
            if (ascii.IndexOf("PowerPoint Document", StringComparison.OrdinalIgnoreCase) >= 0)
                return new ContentTypeDetectionResult { Extension = "ppt", MimeType = "application/vnd.ms-powerpoint", Confidence = "Medium", Reason = "ole2:ppt" };
            // MSI hint: raise confidence to High when multiple typical MSI table names occur alongside SummaryInformation
            bool hasSum = ascii.IndexOf("SummaryInformation", StringComparison.OrdinalIgnoreCase) >= 0;
            int cnt = 0;
            if (ascii.IndexOf("Property", StringComparison.OrdinalIgnoreCase) >= 0) cnt++;
            if (ascii.IndexOf("Directory", StringComparison.OrdinalIgnoreCase) >= 0) cnt++;
            if (ascii.IndexOf("Media", StringComparison.OrdinalIgnoreCase) >= 0) cnt++;
            if (ascii.IndexOf("Component", StringComparison.OrdinalIgnoreCase) >= 0) cnt++;
            if (hasSum && cnt >= 2)
                return new ContentTypeDetectionResult { Extension = "msi", MimeType = "application/x-msi", Confidence = cnt >= 3 ? "High" : "Medium", Reason = cnt >= 3 ? "ole2:msi-dir-high" : "ole2:msi-hint" };

            // Try mini CFBF directory parse for higher confidence
            if (TryGetOleDirectoryNames(stream, out var names))
            {
                bool hasSummary = names.Any(nm => nm.IndexOf("SummaryInformation", StringComparison.OrdinalIgnoreCase) >= 0 || (nm.Length > 0 && nm[0] == '\u0005' && nm.IndexOf("SummaryInformation", StringComparison.OrdinalIgnoreCase) >= 1));
                int hits = 0;
                string[] msiNames = new [] { "Property", "Directory", "Feature", "Media", "Component", "File", "InstallExecuteSequence" };
                foreach (var nm in names) foreach (var t in msiNames) { if (nm.Equals(t, StringComparison.OrdinalIgnoreCase)) { hits++; break; } }
                if (hasSummary && hits >= 2)
                    return new ContentTypeDetectionResult { Extension = "msi", MimeType = "application/x-msi", Confidence = hits >= 3 ? "High" : "Medium", Reason = hits >= 3 ? "ole2:msi-cfbf-high" : "ole2:msi-cfbf" };
            }
        } catch { }
        return null;
    }

    private static bool TryGetOleDirectoryNames(Stream stream, out List<string> names)
    {
        names = new List<string>();
        long save = stream.CanSeek ? stream.Position : 0;
        try {
            if (!stream.CanSeek) return false;
            stream.Seek(0, SeekOrigin.Begin);
            var hdr = new byte[512];
            if (stream.Read(hdr, 0, hdr.Length) != hdr.Length) return false;
            // Signature
            byte[] sig = new byte[] { 0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1 };
            for (int i = 0; i < 8; i++) if (hdr[i] != sig[i]) return false;
            int secShift = hdr[0x1E] | (hdr[0x1F] << 8); // typically 9 => 512 bytes
            int sectorSize = 1 << secShift;
            int dirStartSid = BitConverter.ToInt32(hdr, 0x30);
            int fatCount = BitConverter.ToInt32(hdr, 0x2C);
            if (dirStartSid < 0 || sectorSize < 512 || sectorSize > (1<<20)) return false;
            // Read FAT sector SIDs from DIFAT in header (109 entries)
            var fatSids = new List<int>();
            for (int i = 0; i < 109; i++)
            {
                int sid = BitConverter.ToInt32(hdr, 0x4C + i*4);
                if (sid >= 0) fatSids.Add(sid);
            }
            if (fatSids.Count == 0 || fatCount == 0) return false;
            // Build FAT table
            var fat = new List<int>();
            foreach (var sid in fatSids)
            {
                long off = 512L + ((long)sid + 1) * sectorSize;
                if (off < 0 || off + sectorSize > stream.Length) continue;
                stream.Seek(off, SeekOrigin.Begin);
                var sec = new byte[sectorSize];
                int rn = stream.Read(sec, 0, sec.Length);
                if (rn != sec.Length) break;
                // Each FAT sector contains 32-bit entries
                for (int p = 0; p + 4 <= sec.Length; p += 4)
                    fat.Add(BitConverter.ToInt32(sec, p));
            }
            // Walk directory stream through FAT (limit a few sectors)
            const int ENDOFCHAIN = unchecked((int)0xFFFFFFFE);
            int cur = dirStartSid; int maxSectors = 8; int sectors = 0;
            while (cur >= 0 && cur < fat.Count && sectors < maxSectors)
            {
                long off = 512L + ((long)cur + 1) * sectorSize;
                if (off < 0 || off + sectorSize > stream.Length) break;
                stream.Seek(off, SeekOrigin.Begin);
                var dirSec = new byte[sectorSize];
                if (stream.Read(dirSec, 0, dirSec.Length) != dirSec.Length) break;
                // Parse 128-byte directory entries
                for (int p = 0; p + 128 <= dirSec.Length; p += 128)
                {
                    int nameLen = dirSec[p + 0x40] | (dirSec[p + 0x41] << 8); // bytes
                    if (nameLen >= 2 && nameLen <= 128)
                    {
                        int bytes = nameLen - 2; // exclude terminating null
                        if (bytes > 0 && bytes <= 128)
                        {
                            try {
                                string nm = Encoding.Unicode.GetString(dirSec, p, bytes);
                                if (!string.IsNullOrWhiteSpace(nm)) names.Add(nm);
                            } catch { }
                        }
                    }
                }
                int next = fat[cur];
                if (next == ENDOFCHAIN) break;
                cur = next; sectors++;
            }
            return names.Count > 0;
        } catch { return false; }
        finally { if (stream.CanSeek) stream.Seek(save, SeekOrigin.Begin); }
    }

    /// <summary>
    /// Detects content type from an in-memory span of bytes.
    /// </summary>
    public static ContentTypeDetectionResult? Detect(ReadOnlySpan<byte> data, DetectionOptions? options = null) {
        options ??= new DetectionOptions();
        if (Signatures.TryMatchRiff(data, out var riff)) return Enrich(riff, data, null, options);
        if (Signatures.TryMatchEvtx(data, out var evtx2)) return Enrich(evtx2, data, null, options);
        if (Signatures.TryMatchEse(data, out var ese2)) return Enrich(ese2, data, null, options);
        if (Signatures.TryMatchRegistryHive(data, out var hive2)) return Enrich(hive2, data, null, options);
        if (Signatures.TryMatchFtyp(data, out var ftyp)) return Enrich(ftyp, data, null, options);
        if (Signatures.TryMatchSqlite(data, out var sqlite)) return Enrich(sqlite, data, null, options);
        if (Signatures.TryMatchElf(data, out var elf)) return Enrich(elf, data, null, options);
        foreach (var sig in Signatures.All()) if (Signatures.Match(data, sig)) {
                var conf = sig.Prefix != null && sig.Prefix.Length >= 4 ? "High" : (sig.Prefix != null && sig.Prefix.Length == 3 ? "Medium" : "Low");
                var basic = new ContentTypeDetectionResult {
                    Extension = sig.Extension,
                    MimeType = NormalizeMime(sig.Extension, sig.MimeType),
                    Confidence = conf,
                    Reason = $"magic:{sig.Extension}"
                };
                return Enrich(basic, data, null, options);
            }
        if (Signatures.TryMatchText(data, out var text)) return Enrich(text, data, null, options);
        return Enrich(null, data, null, options);
    }

    private static ContentTypeDetectionResult? TryRefineZipOOxml(string path) {
        try {
            using var fs = File.OpenRead(path);
            using var za = new ZipArchive(fs, ZipArchiveMode.Read, leaveOpen: true);
            // OOXML key parts
            bool hasContentTypes = za.GetEntry("[Content_Types].xml") != null;
            if (!hasContentTypes) return null;
            bool isDocx = za.GetEntry("word/document.xml") != null;
            if (isDocx) return new ContentTypeDetectionResult { Extension = "docx", MimeType = "application/vnd.openxmlformats-officedocument.wordprocessingml.document", Confidence = "High", Reason = "ooxml:docx" };
            bool isXlsx = za.GetEntry("xl/workbook.xml") != null;
            if (isXlsx) return new ContentTypeDetectionResult { Extension = "xlsx", MimeType = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", Confidence = "High", Reason = "ooxml:xlsx" };
            bool isPptx = za.GetEntry("ppt/presentation.xml") != null;
            if (isPptx) return new ContentTypeDetectionResult { Extension = "pptx", MimeType = "application/vnd.openxmlformats-officedocument.presentationml.presentation", Confidence = "High", Reason = "ooxml:pptx" };
            return null;
        } catch { return null; }
    }

    private static ContentTypeDetectionResult? TryRefineZipOOxml(Stream stream) {
        try {
            long pos = stream.CanSeek ? stream.Position : 0;
            if (stream.CanSeek) stream.Seek(0, SeekOrigin.Begin);
            using var za = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
            bool hasContentTypes = za.GetEntry("[Content_Types].xml") != null;
            if (!hasContentTypes) { if (stream.CanSeek) stream.Seek(pos, SeekOrigin.Begin); return null; }
            bool isDocx = za.GetEntry("word/document.xml") != null;
            if (isDocx) { if (stream.CanSeek) stream.Seek(pos, SeekOrigin.Begin); return new ContentTypeDetectionResult { Extension = "docx", MimeType = "application/vnd.openxmlformats-officedocument.wordprocessingml.document", Confidence = "High", Reason = "ooxml:docx" }; }
            bool isXlsx = za.GetEntry("xl/workbook.xml") != null;
            if (isXlsx) { if (stream.CanSeek) stream.Seek(pos, SeekOrigin.Begin); return new ContentTypeDetectionResult { Extension = "xlsx", MimeType = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", Confidence = "High", Reason = "ooxml:xlsx" }; }
            bool isPptx = za.GetEntry("ppt/presentation.xml") != null;
            if (isPptx) { if (stream.CanSeek) stream.Seek(pos, SeekOrigin.Begin); return new ContentTypeDetectionResult { Extension = "pptx", MimeType = "application/vnd.openxmlformats-officedocument.presentationml.presentation", Confidence = "High", Reason = "ooxml:pptx" }; }
            if (stream.CanSeek) stream.Seek(pos, SeekOrigin.Begin);
            return null;
        } catch { return null; }
    }

    private static string? TryGuessZipSubtype(Stream stream, out string? mime) {
        mime = null;
        try {
            long pos = stream.CanSeek ? stream.Position : 0;
            if (stream.CanSeek) stream.Seek(0, SeekOrigin.Begin);
            using var za = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
            bool hasManifest = za.GetEntry("META-INF/MANIFEST.MF") != null;
            bool hasDex = za.GetEntry("classes.dex") != null;
            bool hasAndroidMan = za.GetEntry("AndroidManifest.xml") != null;
            bool hasPayload = za.Entries.Any(e => e.FullName.StartsWith("Payload/", StringComparison.Ordinal));
            bool hasInfoPlist = za.Entries.Any(e => (e.FullName.IndexOf(".app/Info.plist", System.StringComparison.Ordinal) >= 0));
            bool hasAppxManifest = za.GetEntry("AppxManifest.xml") != null;
            bool hasAppxSignature = za.GetEntry("AppxSignature.p7x") != null;

            if (hasAndroidMan || hasDex) { mime = "application/vnd.android.package-archive"; if (stream.CanSeek) stream.Seek(pos, SeekOrigin.Begin); return "apk"; }
            if (hasManifest) { mime = "application/java-archive"; if (stream.CanSeek) stream.Seek(pos, SeekOrigin.Begin); return "jar"; }
            if (hasPayload && hasInfoPlist) { mime = null; if (stream.CanSeek) stream.Seek(pos, SeekOrigin.Begin); return "ipa"; }
            if (hasAppxManifest) { mime = "application/zip"; if (stream.CanSeek) stream.Seek(pos, SeekOrigin.Begin); return hasAppxSignature ? "msix" : "appx"; }

            var mimetypeEntry = za.GetEntry("mimetype");
            if (mimetypeEntry != null) {
                using var s = mimetypeEntry.Open();
                using var sr = new StreamReader(s);
                var mt = sr.ReadToEnd().Trim();
                switch (mt) {
                    case "application/epub+zip": mime = mt; if (stream.CanSeek) stream.Seek(pos, SeekOrigin.Begin); return "epub";
                    case "application/vnd.oasis.opendocument.text": mime = mt; if (stream.CanSeek) stream.Seek(pos, SeekOrigin.Begin); return "odt";
                    case "application/vnd.oasis.opendocument.spreadsheet": mime = mt; if (stream.CanSeek) stream.Seek(pos, SeekOrigin.Begin); return "ods";
                    case "application/vnd.oasis.opendocument.presentation": mime = mt; if (stream.CanSeek) stream.Seek(pos, SeekOrigin.Begin); return "odp";
                    case "application/vnd.oasis.opendocument.graphics": mime = mt; if (stream.CanSeek) stream.Seek(pos, SeekOrigin.Begin); return "odg";
                }
            }

            if (za.GetEntry("doc.kml") != null) { mime = "application/vnd.google-earth.kmz"; if (stream.CanSeek) stream.Seek(pos, SeekOrigin.Begin); return "kmz"; }

            if (za.GetEntry("extension.vsixmanifest") != null) { mime = "application/zip"; if (stream.CanSeek) stream.Seek(pos, SeekOrigin.Begin); return "vsix"; }

            if (za.GetEntry("AppManifest.xaml") != null) { mime = "application/x-silverlight-app"; if (stream.CanSeek) stream.Seek(pos, SeekOrigin.Begin); return "xap"; }

            // NuGet package (nupkg): presence of a .nuspec file
            if (za.Entries.Any(e => e.FullName.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase))) { mime = "application/zip"; if (stream.CanSeek) stream.Seek(pos, SeekOrigin.Begin); return "nupkg"; }

            if (stream.CanSeek) stream.Seek(pos, SeekOrigin.Begin);
        } catch { }
        return null;
    }

    private static ContentTypeDetectionResult? Enrich(ContentTypeDetectionResult? result, ReadOnlySpan<byte> header, Stream? stream, DetectionOptions options) {
        int inspected = header.Length;
        if (options.MagicHeaderBytes > 0) {
            var mh = MagicHeaderHex(header, Math.Min(options.MagicHeaderBytes, header.Length));
            if (result is null) {
                result = new ContentTypeDetectionResult { Extension = string.Empty, MimeType = string.Empty, Confidence = "Low", Reason = "unknown", MagicHeaderHex = mh };
            } else {
                result = new ContentTypeDetectionResult { Extension = result.Extension, MimeType = result.MimeType, Confidence = result.Confidence, Reason = result.Reason, ReasonDetails = result.ReasonDetails, Sha256Hex = result.Sha256Hex, MagicHeaderHex = mh, GuessedExtension = result.GuessedExtension };
            }
        }
        if (options.ComputeSha256 && stream != null) {
            try {
                if (stream.CanSeek) stream.Seek(0, SeekOrigin.Begin);
                using var sha = System.Security.Cryptography.SHA256.Create();
                var hash = sha.ComputeHash(stream);
                var hex = ToLowerHex(hash);
                if (result is null) {
                    result = new ContentTypeDetectionResult { Extension = string.Empty, MimeType = string.Empty, Confidence = "Low", Reason = "unknown", Sha256Hex = hex };
                } else {
                    result = new ContentTypeDetectionResult { Extension = result.Extension, MimeType = result.MimeType, Confidence = result.Confidence, Reason = result.Reason, ReasonDetails = result.ReasonDetails, Sha256Hex = hex, MagicHeaderHex = result.MagicHeaderHex, GuessedExtension = result.GuessedExtension };
                }
            } catch { /* ignore */ } finally { if (stream.CanSeek) stream.Seek(0, SeekOrigin.Begin); }
        }
        if (result != null) result.BytesInspected = inspected;
        return result;
    }

    private static string NormalizeMime(string ext, string mime) {
        if (string.Equals(mime, "application/octet-stream", StringComparison.OrdinalIgnoreCase)) {
            if (MimeMaps.Default.TryGetValue(ext, out var better)) return better;
        }
        return mime;
    }

    private static string ToLowerHex(byte[] data) {
        if (data == null || data.Length == 0) return string.Empty;
        var c = new char[data.Length * 2];
        int p = 0;
        for (int i = 0; i < data.Length; i++) {
            byte b = data[i];
            c[p++] = NibbleToHexLower(b >> 4);
            c[p++] = NibbleToHexLower(b & 0xF);
        }
        return new string(c);
    }

    private static char NibbleToHexLower(int v) => (char)(v < 10 ? ('0' + v) : ('a' + (v - 10)));
}
