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
        var decl = NormalizeExtension(declaredExtension) ?? string.Empty;
        if (detected is null || string.IsNullOrEmpty(decl)) return (false, "no-detection-or-declared");
        var detRaw = NormalizeExtension(detected.Extension);
        var detGuess = NormalizeExtension(detected.GuessedExtension);
        if (string.IsNullOrEmpty(detRaw) && string.IsNullOrEmpty(detGuess)) return (false, "no-detection-or-declared");
        string det;
        string detLabel;
        if (!string.IsNullOrEmpty(detRaw))
        {
            det = detRaw!;
            detLabel = detRaw!;
        }
        else if (!string.IsNullOrEmpty(detGuess))
        {
            det = detGuess!;
            detLabel = detGuess! + "(guess)";
        }
        else
        {
            return (false, "no-detection-or-declared");
        }

        // Treat common synonyms as equivalent (avoid false mismatches)
        static bool Equivalent(string a, string b) {
            if (string.Equals(a, b, StringComparison.OrdinalIgnoreCase)) return true;
            // .cer <-> .crt
            if ((a.Equals("cer", StringComparison.OrdinalIgnoreCase) && b.Equals("crt", StringComparison.OrdinalIgnoreCase)) ||
                (a.Equals("crt", StringComparison.OrdinalIgnoreCase) && b.Equals("cer", StringComparison.OrdinalIgnoreCase))) return true;
            // .yml <-> .yaml
            if ((a.Equals("yml", StringComparison.OrdinalIgnoreCase) && b.Equals("yaml", StringComparison.OrdinalIgnoreCase)) ||
                (a.Equals("yaml", StringComparison.OrdinalIgnoreCase) && b.Equals("yml", StringComparison.OrdinalIgnoreCase))) return true;
            // .jsonl <-> .ndjson
            if ((a.Equals("jsonl", StringComparison.OrdinalIgnoreCase) && b.Equals("ndjson", StringComparison.OrdinalIgnoreCase)) ||
                (a.Equals("ndjson", StringComparison.OrdinalIgnoreCase) && b.Equals("jsonl", StringComparison.OrdinalIgnoreCase))) return true;
            // .jpg <-> .jpeg
            if ((a.Equals("jpg", StringComparison.OrdinalIgnoreCase) && b.Equals("jpeg", StringComparison.OrdinalIgnoreCase)) ||
                (a.Equals("jpeg", StringComparison.OrdinalIgnoreCase) && b.Equals("jpg", StringComparison.OrdinalIgnoreCase))) return true;
            // .htm <-> .html
            if ((a.Equals("htm", StringComparison.OrdinalIgnoreCase) && b.Equals("html", StringComparison.OrdinalIgnoreCase)) ||
                (a.Equals("html", StringComparison.OrdinalIgnoreCase) && b.Equals("htm", StringComparison.OrdinalIgnoreCase))) return true;
            // Group Policy templates: .admx/.adml are XML-based
            if ((a.Equals("admx", StringComparison.OrdinalIgnoreCase) || a.Equals("adml", StringComparison.OrdinalIgnoreCase)) && b.Equals("xml", StringComparison.OrdinalIgnoreCase)) return true;
            if ((b.Equals("admx", StringComparison.OrdinalIgnoreCase) || b.Equals("adml", StringComparison.OrdinalIgnoreCase)) && a.Equals("xml", StringComparison.OrdinalIgnoreCase)) return true;
            // INI/TOML are both key/value config formats; treat as equivalent to reduce false mismatches
            if ((a.Equals("ini", StringComparison.OrdinalIgnoreCase) && b.Equals("toml", StringComparison.OrdinalIgnoreCase)) ||
                (a.Equals("toml", StringComparison.OrdinalIgnoreCase) && b.Equals("ini", StringComparison.OrdinalIgnoreCase))) return true;
            // INF is INI-like; accept ini/toml detection
            if ((a.Equals("inf", StringComparison.OrdinalIgnoreCase) && (b.Equals("ini", StringComparison.OrdinalIgnoreCase) || b.Equals("toml", StringComparison.OrdinalIgnoreCase))) ||
                (b.Equals("inf", StringComparison.OrdinalIgnoreCase) && (a.Equals("ini", StringComparison.OrdinalIgnoreCase) || a.Equals("toml", StringComparison.OrdinalIgnoreCase)))) return true;
            // Ambiguous config family: treat .config/.conf/.cfg as matching common text-based config formats (xml/json/yaml/ini/etc.)
            if (a.Equals("config", StringComparison.OrdinalIgnoreCase) || a.Equals("conf", StringComparison.OrdinalIgnoreCase) || a.Equals("cfg", StringComparison.OrdinalIgnoreCase))
                return InConfigFamily(b);
            if (b.Equals("config", StringComparison.OrdinalIgnoreCase) || b.Equals("conf", StringComparison.OrdinalIgnoreCase) || b.Equals("cfg", StringComparison.OrdinalIgnoreCase))
                return InConfigFamily(a);
            // PowerShell family: .ps1 <-> .psm1 <-> .psd1
            if ((a.Equals("ps1", StringComparison.OrdinalIgnoreCase) || a.Equals("psm1", StringComparison.OrdinalIgnoreCase) || a.Equals("psd1", StringComparison.OrdinalIgnoreCase)) &&
                (b.Equals("ps1", StringComparison.OrdinalIgnoreCase) || b.Equals("psm1", StringComparison.OrdinalIgnoreCase) || b.Equals("psd1", StringComparison.OrdinalIgnoreCase))) return true;
            // Windows scripts: .bat <-> .cmd
            if ((a.Equals("bat", StringComparison.OrdinalIgnoreCase) && b.Equals("cmd", StringComparison.OrdinalIgnoreCase)) ||
                (a.Equals("cmd", StringComparison.OrdinalIgnoreCase) && b.Equals("bat", StringComparison.OrdinalIgnoreCase))) return true;
            // Batch scripts are plain text. If the file is declared as .bat/.cmd but detected as generic text, treat as match.
            // (Do NOT treat the reverse as match: a .txt detected as .bat/.cmd is a potentially dangerous rename.)
            if ((a.Equals("bat", StringComparison.OrdinalIgnoreCase) || a.Equals("cmd", StringComparison.OrdinalIgnoreCase)) &&
                (b.Equals("txt", StringComparison.OrdinalIgnoreCase) || b.Equals("text", StringComparison.OrdinalIgnoreCase) || b.Equals("log", StringComparison.OrdinalIgnoreCase))) return true;
            // MSI promoted from generic OLE2
            if ((a.Equals("msi", StringComparison.OrdinalIgnoreCase) && b.Equals("ole2", StringComparison.OrdinalIgnoreCase)) ||
                (a.Equals("ole2", StringComparison.OrdinalIgnoreCase) && b.Equals("msi", StringComparison.OrdinalIgnoreCase))) return true;
            // Plain‑text family: treat generic text and note/config/log formats as equivalent
            if (InPlainTextFamily(a) && InPlainTextFamily(b)) return true;
            // Heuristic: PowerShell vs .txt — avoid noisy mismatches for short scripts/changelogs
            if ((a.Equals("txt", StringComparison.OrdinalIgnoreCase) && (b.Equals("ps1", StringComparison.OrdinalIgnoreCase) || b.Equals("psm1", StringComparison.OrdinalIgnoreCase) || b.Equals("psd1", StringComparison.OrdinalIgnoreCase))) ||
                (b.Equals("txt", StringComparison.OrdinalIgnoreCase) && (a.Equals("ps1", StringComparison.OrdinalIgnoreCase) || a.Equals("psm1", StringComparison.OrdinalIgnoreCase) || a.Equals("psd1", StringComparison.OrdinalIgnoreCase))))
                return true;
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
                case "csv":
                case "tsv":
                    return true;
                default:
                    return false;
            }
        }

        static bool InConfigFamily(string ext)
        {
            switch ((ext ?? string.Empty).ToLowerInvariant())
            {
                case "xml":
                case "json":
                case "yml":
                case "yaml":
                case "ini":
                case "conf":
                case "cfg":
                case "properties":
                case "prop":
                case "toml":
                case "txt": // permissive: some vendors ship plain-text .config without strict format
                    return true;
                default:
                    return false;
            }
        }

        // PE family normalization: DLL/OCX/CPL/SCR belong to DLL family; SYS is driver; EXE is generic PE image
        static bool IsPeFamilyMember(string ext) => ext.Equals("exe", StringComparison.OrdinalIgnoreCase)
                                                  || ext.Equals("dll", StringComparison.OrdinalIgnoreCase)
                                                  || ext.Equals("sys", StringComparison.OrdinalIgnoreCase)
                                                  || ext.Equals("ocx", StringComparison.OrdinalIgnoreCase)
                                                  || ext.Equals("cpl", StringComparison.OrdinalIgnoreCase)
                                                  || ext.Equals("scr", StringComparison.OrdinalIgnoreCase);

        bool familyMatch = false;
        if (IsPeFamilyMember(decl) && IsPeFamilyMember(det))
        {
            // Treat DLL-family declared (dll/ocx/cpl/scr) as matching detected "exe" (generic PE)
            if (det.Equals("exe", StringComparison.OrdinalIgnoreCase) &&
                (decl.Equals("dll", StringComparison.OrdinalIgnoreCase) || decl.Equals("ocx", StringComparison.OrdinalIgnoreCase) || decl.Equals("cpl", StringComparison.OrdinalIgnoreCase) || decl.Equals("scr", StringComparison.OrdinalIgnoreCase)))
            {
                familyMatch = true;
            }
            // Drivers: treat sys as matching generic exe as well
            if (det.Equals("exe", StringComparison.OrdinalIgnoreCase) && decl.Equals("sys", StringComparison.OrdinalIgnoreCase))
            {
                familyMatch = true;
            }
            // Exact family: exe/exe or dll/dll etc.
            if (decl.Equals(det, StringComparison.OrdinalIgnoreCase)) familyMatch = true;
        }

        var mismatch = !(Equivalent(decl, det) || familyMatch);
        var reason = mismatch ? $"decl:{decl} vs det:{detLabel}" : "match";
        return (mismatch, reason);
    }

    /// <summary>
    /// Normalizes an extension by trimming whitespace and a leading dot. Returns null when empty.
    /// </summary>
    public static string? NormalizeExtension(string? extension)
    {
        var normalized = (extension ?? string.Empty).Trim().TrimStart('.');
        return string.IsNullOrWhiteSpace(normalized) ? null : normalized;       
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
        return Detect(path, null);
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
            var extDeclared = System.IO.Path.GetExtension(path)?.Trim('.').ToLowerInvariant();
            var det = Detect(fs, options, extDeclared);
            try {
                if (det != null && det.Extension != null && det.Extension.Equals("exe", StringComparison.OrdinalIgnoreCase) && PeReader.TryReadPe(path, out var pe)) {
                    const ushort IMAGE_FILE_DLL = 0x2000;
                    if ((pe.Characteristics & IMAGE_FILE_DLL) != 0) { det.Extension = "dll"; det.Reason = AppendReason(det.Reason, "pe-family-precise"); }
                    else if (pe.Subsystem == 1) { det.Extension = "sys"; det.Reason = AppendReason(det.Reason, "pe-family-precise"); }
                }
            } catch { }
            // Special-case ETL: detect by magic (preferred) and optionally validate.
            var ext = System.IO.Path.GetExtension(path)?.Trim('.').ToLowerInvariant();
            bool declaredEtl = string.Equals(ext, "etl", StringComparison.OrdinalIgnoreCase);
            bool magicOk = false;
            try { magicOk = TryMatchEtlMagic(fs); } catch { magicOk = false; }
            if (magicOk || declaredEtl)
            {
                try
                {
                    Breadcrumbs.Write("ETL_VALIDATE_BEGIN", path: path);
                    var mime = MimeMaps.Default.TryGetValue("etl", out var mm) ? mm : "application/octet-stream";
                    if (!magicOk)
                    {
                        Breadcrumbs.Write("ETL_VALIDATE_END", message: "magic-mismatch", path: path);
                    }
                    else
                    {
                        var detEtl = det ?? new ContentTypeDetectionResult();
                        detEtl.Extension = "etl";
                        detEtl.MimeType = mime;
                        detEtl.Confidence = "Low";
                        detEtl.Reason = "etl:magic";

                        var mode = Settings.EtlValidation;
                        if (mode == Settings.EtlValidationMode.Off || mode == Settings.EtlValidationMode.MagicOnly)
                        {
                            Breadcrumbs.Write("ETL_VALIDATE_END", message: "magic-ok", path: path);
                            return detEtl;
                        }

                        bool? okNative = null;
                        if (mode == Settings.EtlValidationMode.NativeThenTracerpt)
                        {
                            try { okNative = EtlNative.TryOpen(path); }
                            catch (Exception ex) { Breadcrumbs.Write("ETL_NATIVE_ERROR", message: ex.GetType().Name + ":" + ex.Message, path: path); }
                            if (okNative == true)
                            {
                                Breadcrumbs.Write("ETL_VALIDATE_END", message: "native-ok", path: path);
                                detEtl.Confidence = "Medium";
                                detEtl.Reason = "etw:ok";
                                return detEtl;
                            }
                        }

                        if (mode == Settings.EtlValidationMode.TracerptOnly || mode == Settings.EtlValidationMode.NativeThenTracerpt)
                        {
                            bool? okTr = null;
                            try { okTr = EtlProbe.TryValidate(path, Settings.EtlProbeTimeoutMs); }
                            catch (Exception ex) { Breadcrumbs.Write("ETL_TRACERPT_ERROR", message: ex.GetType().Name + ":" + ex.Message, path: path); }
                            if (okTr == true)
                            {
                                Breadcrumbs.Write("ETL_VALIDATE_END", message: "tracerpt-ok", path: path);
                                detEtl.Confidence = "Medium";
                                detEtl.Reason = "tracerpt:ok";
                                return detEtl;
                            }
                            if (okTr == false) detEtl.Reason = AppendReason(detEtl.Reason, "tracerpt-fail");
                            else if (okTr == null) detEtl.Reason = AppendReason(detEtl.Reason, "tracerpt-n/a");
                        }

                        Breadcrumbs.Write("ETL_VALIDATE_END", message: okNative == false ? "native-fail" : "no-success", path: path);
                        return detEtl;
                    }
                }
                catch (IOException ex)
                {
                    Breadcrumbs.Write("ETL_VALIDATE_IO_ERROR", message: ex.GetType().Name + ":" + ex.Message, path: path);
                    var mime = MimeMaps.Default.TryGetValue("etl", out var mm) ? mm : "application/octet-stream";
                    return new ContentTypeDetectionResult { Extension = "etl", MimeType = mime, Confidence = "Low", Reason = "etl:validation-error" };
                }
                catch (Exception ex) when (ex is not OutOfMemoryException)
                {
                    Breadcrumbs.Write("ETL_VALIDATE_ERROR", message: ex.GetType().Name + ":" + ex.Message, path: path);
                    var mime = MimeMaps.Default.TryGetValue("etl", out var mm) ? mm : "application/octet-stream";
                    return new ContentTypeDetectionResult { Extension = "etl", MimeType = mime, Confidence = "Low", Reason = "etl:validation-error" };
                }
            }
            det = ApplyDeclaredBias(det, extDeclared);
            TryValidateStructuredTextWithBudget(fs, det, skipAdmxAdml: true);
            TryValidateAdmxAdmlXmlWellFormedness(fs, path, det, extDeclared);
            return det;
        } catch (OutOfMemoryException) { throw; }
        catch { return null; }
    }

    /// <summary>
    /// Detects content type from a readable stream; the stream is rewound where possible.
    /// Fast and minimal: does not perform container/PDF/PE/permission analysis.
    /// </summary>
    public static ContentTypeDetectionResult? Detect(Stream stream, DetectionOptions? options = null, string? declaredExtension = null) {
        options ??= new DetectionOptions();
        var headLen = Math.Max(256, Math.Min(Settings.HeaderReadBytes, 1 << 20));
        var header = new byte[headLen];
        if (stream.CanSeek) stream.Seek(0, SeekOrigin.Begin);
        var read = stream.Read(header, 0, header.Length);
        var src = new ReadOnlySpan<byte>(header, 0, read);
        ContentTypeDetectionResult? Finish(ContentTypeDetectionResult? det) => ApplyDeclaredBias(det, declaredExtension);

        // TAR, RIFF, EVTX, ESE/Registry, SQLite quick checks first
        if (Signatures.TryMatchTar(src, out var tar)) return Finish(Enrich(tar, src, stream, options));
        if (Signatures.TryMatchRiff(src, out var riff)) return Finish(Enrich(riff, src, stream, options));
        if (Signatures.TryMatchEvtx(src, out var evtx)) return Finish(Enrich(evtx, src, stream, options));
        if (Signatures.TryMatchEse(src, out var ese)) return Finish(Enrich(ese, src, stream, options));
        if (Signatures.TryMatchRegistryHive(src, out var hive)) return Finish(Enrich(hive, src, stream, options));
        if (Signatures.TryMatchRegistryPol(src, out var pol)) return Finish(Enrich(pol, src, stream, options));
        if (Signatures.TryMatchFtyp(src, out var ftyp)) return Finish(Enrich(ftyp, src, stream, options));
        if (Signatures.TryMatchSqlite(src, out var sqlite)) return Finish(Enrich(sqlite, src, stream, options));
        if (Signatures.TryMatchPkcs12(src, out var p12)) return Finish(Enrich(p12, src, stream, options));
        if (Signatures.TryMatchDerCertificate(src, out var der)) return Finish(Enrich(der, src, stream, options));
        if (Signatures.TryMatchOpenPgpBinary(src, out var pgpbin)) return Finish(Enrich(pgpbin, src, stream, options));
        if (Signatures.TryMatchKeePassKdbx(src, out var kdbx)) return Finish(Enrich(kdbx, src, stream, options));
        if (Signatures.TryMatch7z(src, out var _7z)) return Finish(Enrich(_7z, src, stream, options));
        if (Signatures.TryMatchRar(src, out var rar)) return Finish(Enrich(rar, src, stream, options));
        if (Signatures.TryMatchElf(src, out var elf)) return Finish(Enrich(elf, src, stream, options));
        if (Signatures.TryMatchMachO(src, out var macho)) return Finish(Enrich(macho, src, stream, options));
        if (Signatures.TryMatchCab(src, out var cab)) return Finish(Enrich(cab, src, stream, options));
        if (Signatures.TryMatchGlb(src, out var glb)) return Finish(Enrich(glb, src, stream, options));
        if (Signatures.TryMatchTiff(src, out var tiff)) return Finish(Enrich(tiff, src, stream, options));
        // ISO requires file path offsets; skip here

        foreach (var sig in Signatures.All()) {
            if (Signatures.Match(src, sig)) {
                if (sig.Extension == "zip") {
                    var refined = TryRefineZipOOxml(stream);
                    if (refined != null) return Finish(Enrich(refined, src, stream, options));
                    var confZip = sig.Prefix != null && sig.Prefix.Length >= 4 ? "High" : (sig.Prefix != null && sig.Prefix.Length == 3 ? "Medium" : "Low");
                    var guess = TryGuessZipSubtype(stream, out var guessMime);
                    var basicZip = new ContentTypeDetectionResult {
                        Extension = sig.Extension,
                        MimeType = NormalizeMime(sig.Extension, sig.MimeType),
                        Confidence = confZip,
                        Reason = $"magic:{sig.Extension}",
                        GuessedExtension = guess
                    };
                    return Finish(Enrich(basicZip, src, stream, options));
                }
                if (sig.Extension == "ole2" && stream is not null) {
                    var refinedOle = TryRefineOle2Subtype(stream);
                    if (refinedOle != null) return Finish(Enrich(refinedOle, src, stream, options));
                }
                var conf = sig.Prefix != null && sig.Prefix.Length >= 4 ? "High" : (sig.Prefix != null && sig.Prefix.Length == 3 ? "Medium" : "Low");
                var basic = new ContentTypeDetectionResult {
                    Extension = sig.Extension,
                    MimeType = NormalizeMime(sig.Extension, sig.MimeType),
                    Confidence = conf,
                    Reason = $"magic:{sig.Extension}"
                };
                var enriched = Enrich(basic, src, stream, options);
                // Promote generic OLE2 to MSI when directory hints indicate MSI tables (extra safeguard for detection-only callers)
                if (sig.Extension == "ole2" && stream is not null)
                {
                    try { var refine = TryRefineOle2Subtype(stream); if (refine != null) return Finish(Enrich(refine, src, stream, options)); } catch { }
                }
                return Finish(enriched);
            }
        }

        if (Signatures.TryMatchText(src, out var text, declaredExtension)) {
            if (text is not null && text.Extension == "json") {
                var refined = TryRefineGltfJson(stream);
                if (refined != null) return Finish(Enrich(refined, src, stream, options));
            }
            var enriched = Enrich(text, src, stream, options);
            var finished = Finish(enriched);
            TryValidateStructuredTextWithBudget(stream, finished, skipAdmxAdml: false);
            return finished;
        }
        return Finish(Enrich(null, src, stream, options));
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

    /// <summary>
    /// Attempts to retrieve MSI file version (Windows only) using msi.dll. Returns null on failure or non‑Windows platforms.
    /// </summary>
    private static string? TryGetMsiVersion(string path)
    {
        try
        {
            if (!System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows)) return null;
            Breadcrumbs.Write("MSI_VER_BEGIN", path: path);
            int vCap = 256, lCap = 0;
            var v = new System.Text.StringBuilder(vCap);
            uint rc = MsiGetFileVersionW(path, v, ref vCap, null, ref lCap);
            if (rc == 0) { var ver = v.ToString(); Breadcrumbs.Write("MSI_VER_END", message: ver, path: path); return ver; }
        } catch (Exception ex) { Breadcrumbs.Write("MSI_VER_ERROR", message: ex.GetType().Name+":"+ex.Message, path: path); }
        finally { Breadcrumbs.Write("MSI_VER_FINALLY", path: path); }
        return null;
    }

    private static string AppendReason(string? reason, string tag)
        => string.IsNullOrEmpty(reason) ? tag : (reason + ";" + tag);

    private static readonly byte[] EtlMagicBytes = { 0x45, 0x6C, 0x66, 0x46 }; // "ElfF" ASCII

    private static bool TryMatchEtlMagic(string path) {
        try {
            using var fs = File.OpenRead(path);
            return TryMatchEtlMagic(fs);
        } catch { return false; }
    }

    private static bool TryMatchEtlMagic(Stream stream) {
        try {
            long pos = 0;
            if (stream.CanSeek) {
                pos = stream.Position;
                stream.Seek(0, SeekOrigin.Begin);
            }
            var buf = new byte[EtlMagicBytes.Length];
            int n = stream.Read(buf, 0, buf.Length);
            if (stream.CanSeek) stream.Seek(pos, SeekOrigin.Begin);
            return n == EtlMagicBytes.Length && buf.AsSpan(0, n).SequenceEqual(EtlMagicBytes);
        } catch { return false; }
    }

    private static void TryValidateAdmxAdmlXmlWellFormedness(Stream stream, string path, ContentTypeDetectionResult? det, string? declaredExt)
    {
        if (det is null) return;
        if (!Settings.AdmxAdmlXmlWellFormednessValidationEnabled) return;

        var detExt = (det.Extension ?? string.Empty).Trim().TrimStart('.').ToLowerInvariant();
        var decl = (declaredExt ?? string.Empty).Trim().TrimStart('.').ToLowerInvariant();
        bool wantsAdmxAdml = detExt == "admx" || detExt == "adml" || decl == "admx" || decl == "adml";
        if (!wantsAdmxAdml) return;

        try
        {
            var max = Settings.AdmxAdmlXmlWellFormednessMaxBytes;
            if (max > 0)
            {
                long len = -1;
                try { if (stream.CanSeek) len = stream.Length; } catch { len = -1; }
                if (len < 0)
                {
                    try { len = new FileInfo(path).Length; } catch { len = -1; }
                }
                if (len > 0 && len > max)
                {
                    det.ValidationStatus = "skipped";
                    return;
                }
            }

            long pos = 0;
            try { if (stream.CanSeek) pos = stream.Position; } catch { pos = 0; }
            try
            {
                if (stream.CanSeek) stream.Seek(0, SeekOrigin.Begin);
                var settings = new System.Xml.XmlReaderSettings
                {
                    DtdProcessing = System.Xml.DtdProcessing.Prohibit,
                    XmlResolver = null,
                    MaxCharactersInDocument = Math.Min(Settings.AdmxAdmlXmlWellFormednessMaxBytes > 0
                        ? Settings.AdmxAdmlXmlWellFormednessMaxBytes
                        : 100L * 1024L * 1024L, 100L * 1024L * 1024L),
                    MaxCharactersFromEntities = 1024,
                    CloseInput = false
                };
                int timeoutMs = Math.Max(0, Settings.XmlWellFormednessTimeoutMs);
                long timeoutTicks = TimeoutHelpers.GetTimeoutTicks(timeoutMs);
                var sw = timeoutTicks > 0 ? System.Diagnostics.Stopwatch.StartNew() : null;
                using var reader = System.Xml.XmlReader.Create(stream, settings);
                while (reader.Read())
                {
                    if (TimeoutHelpers.IsExpired(sw, timeoutTicks))
                        throw new TimeoutException("XML well-formedness validation timed out.");
                }
                det.ValidationStatus = "passed";
            }
            finally
            {
                try { if (stream.CanSeek) stream.Seek(pos, SeekOrigin.Begin); } catch { /* ignore */ }
            }
        }
            catch (System.Xml.XmlException ex)
            {
                Breadcrumbs.Write("XML_MALFORMED", message: ex.Message, path: path);
                det.Confidence = "Low";
                det.Reason = AppendReason(det.Reason, "xml:malformed");
                det.ValidationStatus = "failed";
            }
        catch (TimeoutException ex)
        {
            Breadcrumbs.Write("XML_TIMEOUT", message: ex.Message, path: path);
            det.Confidence = "Low";
            det.Reason = AppendReason(det.Reason, "xml:validation-timeout");
            det.ValidationStatus = "timeout";
        }
        catch
        {
            // Ignore validation failures (I/O, access, etc.). Detection must remain best-effort.
            if (string.IsNullOrEmpty(det.ValidationStatus))
                det.ValidationStatus = "failed";
        }
    }

    private static void TryValidateStructuredTextWithBudget(Stream? stream, ContentTypeDetectionResult? det, bool skipAdmxAdml)
    {
        if (stream == null || det == null) return;
        if (!stream.CanSeek) return;

        var ext = (det.Extension ?? string.Empty).Trim().TrimStart('.').ToLowerInvariant();
        if (string.IsNullOrEmpty(ext)) return;
        if (ext == "admx" || ext == "adml")
        {
            if (skipAdmxAdml) return;
        }
        else if (ext != "json" && ext != "xml")
        {
            return;
        }

        const long MaxStructuredValidationBytes = 100L * 1024L * 1024L;
        long budget = Settings.DetectionReadBudgetBytes;
        if (budget <= 0) return;
        if (budget > MaxStructuredValidationBytes) budget = MaxStructuredValidationBytes;

        long len = -1;
        try { len = stream.Length; } catch { len = -1; }
        long readBytes = budget;
        bool budgetLimited = len > 0 && len > budget;
        if (len > 0) readBytes = Math.Min(len, budget);
        if (readBytes <= 0) return;

        long pos = 0;
        try { pos = stream.Position; } catch { pos = 0; }
        byte[] buffer = new byte[(int)Math.Min(readBytes, int.MaxValue)];
        int n = 0;
        try
        {
            stream.Seek(0, SeekOrigin.Begin);
            n = stream.Read(buffer, 0, buffer.Length);
        }
        catch
        {
            return;
        }
        finally
        {
            try { stream.Seek(pos, SeekOrigin.Begin); } catch { /* ignore */ }
        }

        if (n <= 0) return;
        string sample = DecodeTextSample(buffer, n);
        if (string.IsNullOrWhiteSpace(sample)) return;

        bool complete = false;
        if (len > 0 && n >= len) complete = true;

        if (ext == "json")
        {
            bool looksComplete = complete || LooksLikeCompleteJson(sample);
            if (!looksComplete)
            {
                if (budgetLimited && string.IsNullOrEmpty(det.ValidationStatus))
                    det.ValidationStatus = "skipped";
                return;
            }
            bool jsonValid = JsonStructureValidator.TryValidate(sample, n, out bool jsonSkipped);
            if (!jsonValid)
            {
                if (jsonSkipped)
                {
                    if (string.IsNullOrEmpty(det.ValidationStatus))
                        det.ValidationStatus = "skipped";
                    return;
                }
                det.Confidence = "Low";
                det.Reason = AppendReason(det.Reason, "json:validation-error");
                det.ValidationStatus = "failed";
                if (det.Score.HasValue) det.Score = ScoreFromConfidence(det.Confidence);
            }
            else
            {
                det.ValidationStatus = "passed";
            }
            return;
        }

        // xml/admx/adml
        string? root = TryGetXmlRootName(sample);
        bool xmlComplete = complete || LooksLikeCompleteXml(sample, root);
        if (!xmlComplete)
        {
            if (budgetLimited && string.IsNullOrEmpty(det.ValidationStatus))
                det.ValidationStatus = "skipped";
            return;
        }
        if (!TryXmlWellFormed(sample, out _))
        {
            det.Confidence = "Low";
            det.Reason = AppendReason(det.Reason, "xml:validation-error");
            det.ValidationStatus = "failed";
            if (det.Score.HasValue) det.Score = ScoreFromConfidence(det.Confidence);
        }
        else
        {
            det.ValidationStatus = "passed";
        }
    }

    private static string DecodeTextSample(byte[] buffer, int count)
    {
        if (buffer == null || count <= 0) return string.Empty;
        int bomSkip = 0;
        System.Text.Encoding enc = System.Text.Encoding.UTF8;
        if (count >= 4 && buffer[0] == 0xFF && buffer[1] == 0xFE && buffer[2] == 0x00 && buffer[3] == 0x00)
        {
            enc = new System.Text.UTF32Encoding(false, true);
            bomSkip = 4;
        }
        else if (count >= 4 && buffer[0] == 0x00 && buffer[1] == 0x00 && buffer[2] == 0xFE && buffer[3] == 0xFF)
        {
            enc = new System.Text.UTF32Encoding(true, true);
            bomSkip = 4;
        }
        else if (count >= 2 && buffer[0] == 0xFF && buffer[1] == 0xFE)
        {
            enc = System.Text.Encoding.Unicode;
            bomSkip = 2;
        }
        else if (count >= 2 && buffer[0] == 0xFE && buffer[1] == 0xFF)
        {
            enc = System.Text.Encoding.BigEndianUnicode;
            bomSkip = 2;
        }
        else if (count >= 3 && buffer[0] == 0xEF && buffer[1] == 0xBB && buffer[2] == 0xBF)
        {
            enc = System.Text.Encoding.UTF8;
            bomSkip = 3;
        }
        else
        {
            int scan = Math.Min(count, 2048);
            int nulTotal = 0;
            int nulEven = 0;
            int nulOdd = 0;
            for (int i = 0; i < scan; i++)
            {
                if (buffer[i] == 0x00)
                {
                    nulTotal++;
                    if ((i & 1) == 0) nulEven++; else nulOdd++;
                }
            }
            if (nulTotal > 0 && ((double)nulTotal / scan) >= 0.2)
            {
                if (nulOdd > nulEven * 4) enc = System.Text.Encoding.Unicode;
                else if (nulEven > nulOdd * 4) enc = System.Text.Encoding.BigEndianUnicode;
            }
        }

        if (bomSkip >= count) return string.Empty;
        int len = count - bomSkip;
        if (len == 0) return string.Empty;
        return enc.GetString(buffer, bomSkip, len);
    }

    private static int ScoreFromConfidence(string? confidence)
    {
        if (string.Equals(confidence, "High", StringComparison.OrdinalIgnoreCase)) return 90;
        if (string.Equals(confidence, "Medium", StringComparison.OrdinalIgnoreCase)) return 70;
        if (string.Equals(confidence, "Low", StringComparison.OrdinalIgnoreCase)) return 50;
        return 40;
    }

    private static bool LooksLikeCompleteJson(string s)
    {
        if (string.IsNullOrWhiteSpace(s)) return false;
        var t = s.Trim();
        if (t.Length < 2) return false;
        char first = t[0];
        char last = t[t.Length - 1];
        return (first == '{' || first == '[') && (last == '}' || last == ']');
    }

    private static bool LooksLikeCompleteXml(string s, string? rootName)
    {
        if (string.IsNullOrWhiteSpace(s)) return false;
        var lower = s.ToLowerInvariant();
        if (!lower.Contains("</")) return false;
        if (!lower.TrimEnd().EndsWith(">")) return false;
        if (!string.IsNullOrEmpty(rootName))
        {
            var rootLower = rootName!.ToLowerInvariant();
            return lower.Contains("</" + rootLower);
        }
        return true;
    }

    private static string? TryGetXmlRootName(string s)
    {
        if (string.IsNullOrEmpty(s)) return null;
        int i = 0;
        while (i < s.Length)
        {
            int lt = s.IndexOf('<', i);
            if (lt < 0 || lt + 1 >= s.Length) return null;
            char next = s[lt + 1];
            if (next == '?' || next == '!')
            {
                int gt = s.IndexOf('>', lt + 2);
                if (gt < 0) return null;
                i = gt + 1;
                continue;
            }
            int start = lt + 1;
            while (start < s.Length && char.IsWhiteSpace(s[start])) start++;
            int end = start;
            while (end < s.Length && (char.IsLetterOrDigit(s[end]) || s[end] == ':' || s[end] == '_' || s[end] == '-')) end++;
            if (end > start) return s.Substring(start, end - start);
            i = lt + 1;
        }
        return null;
    }

    private static bool TryXmlWellFormed(string xml, out string? rootName)
    {
        rootName = null;
        if (string.IsNullOrWhiteSpace(xml)) return false;
        try
        {
            var settings = new System.Xml.XmlReaderSettings
            {
                DtdProcessing = System.Xml.DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = Math.Min(10_000_000L, Math.Max(1024L, (long)xml.Length * 4L)),
                MaxCharactersFromEntities = 1024
            };
            int timeoutMs = Math.Max(0, Settings.XmlWellFormednessTimeoutMs);
            long timeoutTicks = TimeoutHelpers.GetTimeoutTicks(timeoutMs);
            var sw = timeoutTicks > 0 ? System.Diagnostics.Stopwatch.StartNew() : null;
            using var reader = System.Xml.XmlReader.Create(new System.IO.StringReader(xml), settings);
            while (reader.Read())
            {
                if (TimeoutHelpers.IsExpired(sw, timeoutTicks)) return false;
                if (reader.NodeType == System.Xml.XmlNodeType.Element)
                {
                    rootName = reader.Name;
                    break;
                }
            }
            return !string.IsNullOrEmpty(rootName);
        }
        catch
        {
            return false;
        }
    }

    [System.Runtime.InteropServices.DllImport("msi.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true, EntryPoint = "MsiGetFileVersionW")]
    private static extern uint MsiGetFileVersionW(string szFilePath, System.Text.StringBuilder? lpVersionBuf, ref int pcchVersionBuf, System.Text.StringBuilder? lpLangBuf, ref int pcchLangBuf);

    /// <summary>
    /// Best-effort scan for TargetFramework moniker in managed binaries by searching ASCII/UTF-16 strings.
    /// Returns a compact TFM like ".NETFramework,Version=v4.7.2" or ".NETCoreApp,Version=v8.0" when found.
    /// </summary>
    internal static string? TryDetectTargetFramework(string path, int byteBudget)
    {
        try
        {
            using var fs = File.OpenRead(path);
            int cap = (int)Math.Min(Math.Max(64 * 1024, byteBudget), Math.Min(fs.Length, (long)byteBudget));
            var buf = new byte[cap];
            int n = fs.Read(buf, 0, buf.Length); if (n <= 0) return null;
            string ascii = System.Text.Encoding.ASCII.GetString(buf, 0, n);
            string uni = n >= 2 ? System.Text.Encoding.Unicode.GetString(buf, 0, n - (n % 2)) : string.Empty;
            string? Extract(string s)
            {
                foreach (var prefix in new [] { ".NETFramework,Version=v", ".NETCoreApp,Version=v", ".NETStandard,Version=v" })
                {
                    int at = s.IndexOf(prefix, StringComparison.OrdinalIgnoreCase);
                    if (at >= 0)
                    {
                        int end = at + prefix.Length; while (end < s.Length && (char.IsDigit(s[end]) || s[end] == '.' )) end++;
                        return s.Substring(at, end - at);
                    }
                }
                return null;
            }
            return Extract(ascii) ?? Extract(uni);
        } catch { return null; }
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

            // Fast-path ETL: avoid full analysis (which can be expensive/fragile on multi‑GB traces).
            try
            {
                if (!options.DetectOnly)
                {
                    long len = -1;
                    try { len = new FileInfo(path).Length; } catch { len = -1; }
                    var threshold = Settings.EtlLargeFileQuickScanBytes;
                    var mode = Settings.EtlValidation;
                    bool allowQuick = threshold > 0 && len >= threshold;
                    if (allowQuick && TryMatchEtlMagic(path))
                    {
                        Breadcrumbs.Write("ETL_QUICK_BEGIN", path: path);
                        string reason = "etl:magic";
                        string mime = MimeMaps.Default.TryGetValue("etl", out var mm) ? mm : "application/octet-stream";
                        string confidence = "Low";
                        if (mode == Settings.EtlValidationMode.Off || mode == Settings.EtlValidationMode.MagicOnly)
                        {
                            reason = "etl:magic";
                        }
                        else
                        {
                            // Tracerpt-only (safe) or native+tracerpt (native currently disabled)
                            try
                            {
                                var tr = EtlProbe.TryValidate(path, Settings.EtlProbeTimeoutMs);
                                if (tr == true) { reason = string.IsNullOrEmpty(reason) ? "tracerpt-ok" : reason + ";tracerpt-ok"; confidence = "Medium"; }
                                else if (tr == false) { reason = string.IsNullOrEmpty(reason) ? "tracerpt-fail" : reason + ";tracerpt-fail"; }
                                else { reason = string.IsNullOrEmpty(reason) ? "tracerpt-n/a" : reason + ";tracerpt-n/a"; }
                            }
                            catch (Exception ex)
                            {
                                Breadcrumbs.Write("ETL_QUICK_NATIVE_ERROR", message: ex.GetType().Name + ":" + ex.Message, path: path);
                                reason = string.IsNullOrEmpty(reason) ? "tracerpt-error" : reason + ";tracerpt-error";
                            }
                        }

                        var det = new ContentTypeDetectionResult { Extension = "etl", MimeType = mime, Confidence = confidence, Reason = reason };
                        var quick = new FileAnalysis { Detection = det, Kind = KindClassifier.Classify(det), Flags = ContentFlags.None };
                        Breadcrumbs.Write("ETL_QUICK_END", message: reason, path: path);
                        return quick;
                    }
                }
            }
            catch { /* non-fatal */ }

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
            // Walk directory stream through FAT (bounded). Increase sectors for robust MSI detection.
            const int ENDOFCHAIN = unchecked((int)0xFFFFFFFE);
            int cur = dirStartSid; int maxSectors = 64; int sectors = 0;
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
    public static ContentTypeDetectionResult? Detect(ReadOnlySpan<byte> data, DetectionOptions? options = null, string? declaredExtension = null) {
        options ??= new DetectionOptions();
        ContentTypeDetectionResult? Finish(ContentTypeDetectionResult? det) => ApplyDeclaredBias(det, declaredExtension);
        if (Signatures.TryMatchTar(data, out var tar)) return Finish(Enrich(tar, data, null, options));
        if (Signatures.TryMatchRiff(data, out var riff)) return Finish(Enrich(riff, data, null, options));
        if (Signatures.TryMatchEvtx(data, out var evtx2)) return Finish(Enrich(evtx2, data, null, options));
        if (Signatures.TryMatchEse(data, out var ese2)) return Finish(Enrich(ese2, data, null, options));
        if (Signatures.TryMatchRegistryHive(data, out var hive2)) return Finish(Enrich(hive2, data, null, options));
        if (Signatures.TryMatchRegistryPol(data, out var pol2)) return Finish(Enrich(pol2, data, null, options));
        if (Signatures.TryMatchFtyp(data, out var ftyp)) return Finish(Enrich(ftyp, data, null, options));
        if (Signatures.TryMatchSqlite(data, out var sqlite)) return Finish(Enrich(sqlite, data, null, options));
        if (Signatures.TryMatchPkcs12(data, out var p12)) return Finish(Enrich(p12, data, null, options));
        if (Signatures.TryMatchDerCertificate(data, out var der)) return Finish(Enrich(der, data, null, options));
        if (Signatures.TryMatchOpenPgpBinary(data, out var pgpbin)) return Finish(Enrich(pgpbin, data, null, options));
        if (Signatures.TryMatchKeePassKdbx(data, out var kdbx)) return Finish(Enrich(kdbx, data, null, options));
        if (Signatures.TryMatch7z(data, out var _7z)) return Finish(Enrich(_7z, data, null, options));
        if (Signatures.TryMatchRar(data, out var rar)) return Finish(Enrich(rar, data, null, options));
        if (Signatures.TryMatchElf(data, out var elf)) return Finish(Enrich(elf, data, null, options));
        if (Signatures.TryMatchMachO(data, out var macho)) return Finish(Enrich(macho, data, null, options));
        if (Signatures.TryMatchCab(data, out var cab)) return Finish(Enrich(cab, data, null, options));
        if (Signatures.TryMatchGlb(data, out var glb)) return Finish(Enrich(glb, data, null, options));
        if (Signatures.TryMatchTiff(data, out var tiff)) return Finish(Enrich(tiff, data, null, options));
        foreach (var sig in Signatures.All()) if (Signatures.Match(data, sig)) {
                var conf = sig.Prefix != null && sig.Prefix.Length >= 4 ? "High" : (sig.Prefix != null && sig.Prefix.Length == 3 ? "Medium" : "Low");
                var basic = new ContentTypeDetectionResult {
                    Extension = sig.Extension,
                    MimeType = NormalizeMime(sig.Extension, sig.MimeType),
                    Confidence = conf,
                    Reason = $"magic:{sig.Extension}"
                };
                return Finish(Enrich(basic, data, null, options));
            }
        if (Signatures.TryMatchText(data, out var text, declaredExtension)) return Finish(Enrich(text, data, null, options));
        return Finish(Enrich(null, data, null, options));
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
            int entryLimit = Math.Max(0, Settings.ZipSubtypeMaxEntries);
            if (entryLimit == 0)
            {
                if (stream.CanSeek) stream.Seek(pos, SeekOrigin.Begin);
                return null;
            }
            bool hasManifest = za.GetEntry("META-INF/MANIFEST.MF") != null;
            bool hasDex = za.GetEntry("classes.dex") != null;
            bool hasAndroidMan = za.GetEntry("AndroidManifest.xml") != null;
            bool hasAppxManifest = za.GetEntry("AppxManifest.xml") != null;
            bool hasAppxSignature = za.GetEntry("AppxSignature.p7x") != null;
            bool hasPayload = false;
            bool hasInfoPlist = false;
            bool hasNuspec = false;
            int entriesSeen = 0;
            foreach (var entry in za.Entries)
            {
                entriesSeen++;
                if (entriesSeen > entryLimit)
                {
                    if (stream.CanSeek) stream.Seek(pos, SeekOrigin.Begin);
                    return null;
                }
                var name = entry.FullName;
                if (!hasPayload && name.StartsWith("Payload/", StringComparison.Ordinal)) hasPayload = true;
                if (!hasInfoPlist && name.IndexOf(".app/Info.plist", System.StringComparison.Ordinal) >= 0) hasInfoPlist = true;
                if (!hasNuspec && name.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase)) hasNuspec = true;
                if (hasPayload && hasInfoPlist && hasNuspec) break;
            }

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
            if (hasNuspec) { mime = "application/zip"; if (stream.CanSeek) stream.Seek(pos, SeekOrigin.Begin); return "nupkg"; }

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
                    result = new ContentTypeDetectionResult { Extension = result.Extension, MimeType = result.MimeType, Confidence = result.Confidence, Reason = result.Reason, ReasonDetails = result.ReasonDetails, ValidationStatus = result.ValidationStatus, Sha256Hex = result.Sha256Hex, MagicHeaderHex = mh, GuessedExtension = result.GuessedExtension, Score = result.Score, Alternatives = result.Alternatives, Candidates = result.Candidates, IsDangerous = result.IsDangerous };
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
                    result = new ContentTypeDetectionResult { Extension = result.Extension, MimeType = result.MimeType, Confidence = result.Confidence, Reason = result.Reason, ReasonDetails = result.ReasonDetails, ValidationStatus = result.ValidationStatus, Sha256Hex = hex, MagicHeaderHex = result.MagicHeaderHex, GuessedExtension = result.GuessedExtension, Score = result.Score, Alternatives = result.Alternatives, Candidates = result.Candidates, IsDangerous = result.IsDangerous };
                }
            } catch { /* ignore */ } finally { if (stream.CanSeek) stream.Seek(0, SeekOrigin.Begin); }
        }
        if (result != null)
        {
            result.BytesInspected = inspected;
            result.IsDangerous = result.IsDangerous || DangerousExtensions.IsDangerous(result.Extension);
        }
        return result;
    }

    private static string NormalizeMime(string ext, string mime) {
        if (string.Equals(mime, "application/octet-stream", StringComparison.OrdinalIgnoreCase)) {
            if (MimeMaps.Default.TryGetValue(ext, out var better)) return better;
        }
        return mime;
    }

    private static ContentTypeDetectionResult? ApplyDeclaredBias(ContentTypeDetectionResult? det, string? declaredExt)
    {
        if (det == null) return det;
        if (string.IsNullOrWhiteSpace(declaredExt)) return det;
        var decl = (declaredExt ?? string.Empty).Trim().TrimStart('.').ToLowerInvariant();

        // Avoid biasing "unknown" detections (common when stream/span detection fails).
        if (string.IsNullOrWhiteSpace(det.Extension) &&
            string.IsNullOrWhiteSpace(det.GuessedExtension) &&
            string.Equals(det.Reason, "unknown", StringComparison.OrdinalIgnoreCase))
        {
            return det;
        }

        // Prefer the declared extension only for ambiguous/generic detections (avoid masking strong magic-byte hits).
        // This is primarily to reduce false mismatches for "well-known text containers" (cmd/admx/adml/inf/ini) where the
        // content is still plain text / XML but the extension is more specific and expected in Windows/GPO contexts.

        // Batch: detection heuristics may return "bat" for both .bat and .cmd; preserve the declared type for reporting.
        if (decl == "cmd" && string.Equals(det.Extension, "bat", StringComparison.OrdinalIgnoreCase))
        {
            det.Extension = "cmd";
            det.MimeType = NormalizeMime(det.Extension, det.MimeType);
            det.Reason = AppendReason(det.Reason, "bias:decl:cmd");
            det.IsDangerous = det.IsDangerous || DangerousExtensions.IsDangerous(det.Extension);
            return det;
        }

        // GPO templates are XML with distinct extensions.
        if ((decl == "admx" || decl == "adml") && string.Equals(det.Extension, "xml", StringComparison.OrdinalIgnoreCase))
        {
            det.Extension = decl;
            det.MimeType = NormalizeMime(det.Extension, det.MimeType);
            det.Reason = AppendReason(det.Reason, $"bias:decl:{decl}");
            det.IsDangerous = det.IsDangerous || DangerousExtensions.IsDangerous(det.Extension);
            return det;
        }

        // INF is INI-like; when detected as ini, keep declared.
        if (decl == "inf" && string.Equals(det.Extension, "ini", StringComparison.OrdinalIgnoreCase))
        {
            det.Extension = "inf";
            det.MimeType = NormalizeMime(det.Extension, det.MimeType);
            det.Reason = AppendReason(det.Reason, "bias:decl:inf");
            det.IsDangerous = det.IsDangerous || DangerousExtensions.IsDangerous(det.Extension);
            return det;
        }

        if (!string.IsNullOrEmpty(det.Confidence) && det.Confidence.Equals("Low", StringComparison.OrdinalIgnoreCase))
        {
            // Only bias when detection is generic/ambiguous text.
            var detExt = det.Extension ?? string.Empty;
            bool detectedGeneric = string.IsNullOrEmpty(detExt) ||
                                   detExt.Equals("txt", StringComparison.OrdinalIgnoreCase) ||
                                   detExt.Equals("text", StringComparison.OrdinalIgnoreCase);
            if (detectedGeneric &&
                (decl == "log" || decl == "txt" || decl == "md" || decl == "markdown" || decl == "ps1" || decl == "psm1" || decl == "psd1" ||
                 decl == "cmd" || decl == "bat" || decl == "ini" || decl == "inf"))
            {
                if (!decl.Equals(det.Extension, StringComparison.OrdinalIgnoreCase))
                {
                    det.Extension = decl;
                    det.MimeType = NormalizeMime(det.Extension, det.MimeType);
                    det.Reason = AppendReason(det.Reason, $"bias:decl:{decl}");
                }
            }

            // TOML vs INI is ambiguous for small files; if declared INI/INF, prefer declared.
            if ((decl == "ini" || decl == "inf") && detExt.Equals("toml", StringComparison.OrdinalIgnoreCase))
            {
                det.Extension = decl;
                det.MimeType = NormalizeMime(det.Extension, det.MimeType);
                det.Reason = AppendReason(det.Reason, $"bias:decl:{decl}");
            }
        }
        det.IsDangerous = det.IsDangerous || DangerousExtensions.IsDangerous(det.Extension);
        return det;
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

