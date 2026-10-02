using System.IO.Compression;
using System.Text;

namespace FileInspectorX;

/// <summary>
/// Minimal, dependency-free file inspector based on magic bytes and lightweight heuristics.
/// Provides fast content type detection and optional analysis helpers across .NET 8, .NET Framework 4.7.2 and .NET Standard 2.0.
/// </summary>
public static partial class FileInspector {
    internal sealed class NestedContainerBudgetState
    {
        private int _remainingEntries;
        private long _remainingBytes;

        internal NestedContainerBudgetState(int entries, long bytes)
        {
            _remainingEntries = Math.Max(0, entries);
            _remainingBytes = Math.Max(0, bytes);
        }

        internal bool TryConsume(long bytes)
        {
            if (bytes <= 0 || _remainingEntries <= 0 || bytes > _remainingBytes) return false;
            _remainingEntries--;
            _remainingBytes -= bytes;
            return true;
        }
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
            // HDF5 commonly uses either .h5 or .hdf5.
            if ((a.Equals("h5", StringComparison.OrdinalIgnoreCase) && b.Equals("hdf5", StringComparison.OrdinalIgnoreCase)) ||
                (a.Equals("hdf5", StringComparison.OrdinalIgnoreCase) && b.Equals("h5", StringComparison.OrdinalIgnoreCase))) return true;
            // Standard MIDI files commonly use either .mid or .midi.
            if ((a.Equals("mid", StringComparison.OrdinalIgnoreCase) && b.Equals("midi", StringComparison.OrdinalIgnoreCase)) ||
                (a.Equals("midi", StringComparison.OrdinalIgnoreCase) && b.Equals("mid", StringComparison.OrdinalIgnoreCase))) return true;
            // Matroska's document type identifies the container, not its track composition.
            if (IsMatroskaExtension(a) && IsMatroskaExtension(b)) return true;
            // The shared Outlook NDB header does not distinguish personal and offline stores.
            if (IsOutlookDataExtension(a) && IsOutlookDataExtension(b)) return true;
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
            // PowerShell scripts are also plain text. If the file is declared as PowerShell but detected as generic text,
            // treat as match. Do not treat the reverse as match because a .txt detected as PowerShell is a dangerous rename.
            if ((a.Equals("ps1", StringComparison.OrdinalIgnoreCase) || a.Equals("psm1", StringComparison.OrdinalIgnoreCase) || a.Equals("psd1", StringComparison.OrdinalIgnoreCase)) &&
                (b.Equals("txt", StringComparison.OrdinalIgnoreCase) || b.Equals("text", StringComparison.OrdinalIgnoreCase) || b.Equals("log", StringComparison.OrdinalIgnoreCase))) return true;
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
            return false;
        }

        static bool IsMatroskaExtension(string ext)
            => ext.Equals("matroska", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals("mkv", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals("mka", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals("mks", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals("mk3d", StringComparison.OrdinalIgnoreCase);

        static bool IsOutlookDataExtension(string ext)
            => ext.Equals("ndb", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals("pst", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals("ost", StringComparison.OrdinalIgnoreCase);

        if (!string.IsNullOrEmpty(detGuess) &&
            !Equivalent(decl, det) &&
            Equivalent(decl, detGuess!))
        {
            det = detGuess!;
            // Keep the detected extension as the base ZIP family while still showing that the guess resolved the declared subtype.
            detLabel = detGuess! + " (guess)";
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
            using var fs = OpenReadShared(path);
            var buf = new byte[Math.Min(bytes, 1 << 20)]; // cap at 1MB for safety
            var read = fs.Read(buf, 0, buf.Length);
            return MagicHeaderHex(new ReadOnlySpan<byte>(buf, 0, read), bytes);
        } catch { return string.Empty; }
    }

    private static Stream OpenReadShared(string path)
    {
        InspectionOperation.CheckCancellation();
        var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        var token = InspectionOperation.Current?.Options.CancellationToken ?? default;
        return token.CanBeCanceled ? new OperationReadStream(stream, token, leaveOpen: false) : stream;
    }

    private static void ValidateLearnedClassificationMode(DetectionOptions options) {
        if (!Enum.IsDefined(typeof(LearnedClassificationMode), options.LearnedClassificationMode))
            throw new ArgumentOutOfRangeException(
                nameof(options),
                options.LearnedClassificationMode,
                "The learned-classification mode is not defined.");
    }

    /// <summary>
    /// Detects content type from a file path using magic bytes and heuristics. Returns null when unknown.
    /// Fast and minimal: does not perform container/PDF/PE/permission analysis.
    /// </summary>
    public static ContentTypeDetectionResult? Detect(string path) {
        return Detect(path, null);
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
    private static readonly byte[] EvtxMagicBytes = System.Text.Encoding.ASCII.GetBytes("ElfFile\0");

    private static bool TryMatchEtlMagic(string path) {
        try {
            using var fs = OpenReadShared(path);
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
            var buf = new byte[Math.Max(EvtxMagicBytes.Length, 128)];
            int n = ReadAvailable(stream, buf, 0, buf.Length);
            if (stream.CanSeek) stream.Seek(pos, SeekOrigin.Begin);
            if (n < EtlMagicBytes.Length) return false;
            var head = buf.AsSpan(0, n);
            if (head.Slice(0, EtlMagicBytes.Length).SequenceEqual(EtlMagicBytes))
            {
                // EVTX shares the "ElfF" prefix, so require that ETL candidates do not
                // match the full EVTX header before claiming the file is an ETL trace.
                if (n >= EvtxMagicBytes.Length && head.Slice(0, EvtxMagicBytes.Length).SequenceEqual(EvtxMagicBytes)) return false;
                return true;
            }

            return LooksLikeStructuredEtlHeader(head);
        } catch { return false; }
    }

    private static bool LooksLikeStructuredEtlHeader(ReadOnlySpan<byte> head)
    {
        if (head.Length < 0x40) return false;

        static uint ReadUInt32Le(ReadOnlySpan<byte> data, int offset)
            => (uint)(data[offset]
                   | (data[offset + 1] << 8)
                   | (data[offset + 2] << 16)
                   | (data[offset + 3] << 24));

        uint bufferSize = ReadUInt32Le(head, 0x00);
        uint version = ReadUInt32Le(head, 0x04);
        uint providerVersion = ReadUInt32Le(head, 0x30);

        if (bufferSize < 1024 || bufferSize > (1024 * 1024) || (bufferSize % 1024) != 0)
            return false;
        if (version < 0x100 || version > 0x400)
            return false;
        if (providerVersion == 0)
            return false;

        int zeroBytes = 0;
        for (int i = 0x08; i < 0x30; i++)
        {
            if (head[i] == 0) zeroBytes++;
        }

        return zeroBytes >= 28;
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
            using var fs = OperationReadStream.Open(path);
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
            if (!TryReadFileBytesWithinBudget(path, GetCertificateParseReadBudgetBytes(), out var raw)) return;
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
            using var operation = InspectionOperation.Begin(options ?? new DetectionOptions());
            options = operation.Options;
            ValidateLearnedClassificationMode(options);

            // Fast-path ETL: avoid full analysis (which can be expensive/fragile on multi‑GB traces).
            try
            {
                if (!options.DetectOnly)
                {
                    long len = -1;
                    try { len = new FileInfo(path).Length; } catch { len = -1; }
                    var threshold = OperationSettings.EtlLargeFileQuickScanBytes;
                    var mode = OperationSettings.EtlValidation;
                    bool allowQuick = threshold > 0 && len >= threshold;
                    if (allowQuick)
                    {
                        using var quickStream = OpenReadShared(path);
                        if (TryMatchEtlMagic(quickStream))
                        {
                            Breadcrumbs.Write("ETL_QUICK_BEGIN", path: path);
                            string reason = "etl:magic";
                            string mime = MimeMaps.Default.TryGetValue("etl", out var mm) ? mm : "application/octet-stream";
                            string confidence = "Medium";
                            if (mode == Settings.EtlValidationMode.Off || mode == Settings.EtlValidationMode.MagicOnly)
                            {
                                reason = "etl:magic";
                            }
                            else
                            {
                                // Tracerpt-only (safe) or native+tracerpt (native currently disabled)
                                try
                                {
                                    var tr = EtlProbe.TryValidate(path, OperationSettings.EtlProbeTimeoutMs);
                                    if (tr == true) { reason = string.IsNullOrEmpty(reason) ? "tracerpt-ok" : reason + ";tracerpt-ok"; confidence = "High"; }
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
                            if (options.LearnedClassificationMode != LearnedClassificationMode.Off)
                            {
                                det = ApplyLearnedClassification(det, quickStream, options)
                                      ?? det;
                            }
                            var quick = new FileAnalysis
                            {
                                Detection = det,
                                DetectedExtension = det.Extension,
                                DetectedMimeType = det.MimeType,
                                DetectionConfidence = det.Confidence,
                                DetectionReason = det.Reason,
                                Kind = KindClassifier.Classify(det),
                                Flags = ContentFlags.None
                            };
                            PopulateDetectionSummary(quick);
                            Breadcrumbs.Write("ETL_QUICK_END", message: reason, path: path);
                            return quick;
                        }
                    }
                }
            }
            catch (OutOfMemoryException) { throw; }
            catch (LearnedClassificationException) { throw; }
            catch (OperationCanceledException) { throw; }
            catch { /* non-fatal */ }

            if (options.DetectOnly)
            {
                ContentTypeDetectionResult? det;
                try { det = DetectPathCore(path, options, propagateReadFailure: true); }
                catch (Exception ex) when (ex is not OutOfMemoryException and not LearnedClassificationException and not ArgumentOutOfRangeException and not OperationCanceledException)
                { return InputFailureAnalysis(options); }
                var detectedOnly = new FileAnalysis {
                    Detection = det,
                    Kind = ClassifyKindWithLearnedText(det),
                    Flags = ContentFlags.None
                };
                PopulateDetectionSummary(detectedOnly);
                return detectedOnly;
            }
        return Analyze(path, options);
    }

    private static string NormalizeMime(string ext, string mime) {
        if (string.Equals(mime, "application/octet-stream", StringComparison.OrdinalIgnoreCase)) {
            if (MimeMaps.TryGetByExtension(ext, out var better) && !string.IsNullOrWhiteSpace(better)) return better!;
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

        // PKCS#7 payloads often arrive as .spc/.p7s; preserve the declared subtype for reporting.
        if ((decl == "spc" || decl == "p7s") && string.Equals(det.Extension, "p7b", StringComparison.OrdinalIgnoreCase))
        {
            det.Extension = decl;
            det.MimeType = MimeMaps.TryGetByExtension(det.Extension, out var preferredMime) && !string.IsNullOrWhiteSpace(preferredMime)
                ? preferredMime!
                : NormalizeMime(det.Extension, det.MimeType);
            det.Reason = AppendReason(det.Reason, $"bias:decl:{decl}");
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
            bool declaredDangerous = DangerousExtensions.IsDangerous(decl);
            if (detectedGeneric &&
                (decl == "log" || decl == "txt" || decl == "md" || decl == "markdown" || decl == "ps1" || decl == "psm1" || decl == "psd1" ||
                 decl == "cmd" || decl == "bat" || decl == "ini" || decl == "inf"))
            {
                if (!declaredDangerous && HasStrongDangerousCandidate(det))
                    return det;
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

    private static bool HasStrongDangerousCandidate(ContentTypeDetectionResult det)
    {
        var candidates = GetAvailableBiasCandidates(det);
        if (candidates == null || candidates.Count == 0) return false;
        foreach (var candidate in candidates)
        {
            if (string.IsNullOrWhiteSpace(candidate.Extension)) continue;
            if (!DangerousExtensions.IsDangerous(candidate.Extension)) continue;
            if (candidate.Score >= 80) return true;
            if (!string.IsNullOrEmpty(candidate.Confidence) &&
                candidate.Confidence.Equals("High", StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private static IReadOnlyList<ContentTypeDetectionCandidate>? GetAvailableBiasCandidates(ContentTypeDetectionResult det)
    {
        if (det.Candidates != null && det.Candidates.Count > 0) return det.Candidates;
        if (det.Alternatives != null && det.Alternatives.Count > 0) return det.Alternatives;
        return det.Candidates ?? det.Alternatives;
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

