using System.IO.Compression;

namespace FileInspectorX;

/// <summary>
/// High-level analysis describing file type, risk flags, metadata and container hints. Produced by <see cref="FileInspector.Analyze(string, FileInspector.DetectionOptions?)"/>.
/// </summary>
public sealed class FileAnalysis {
    public ContentTypeDetectionResult? Detection { get; set; }
    public ContentKind Kind { get; set; } = ContentKind.Unknown;
    public ContentFlags Flags { get; set; } = ContentFlags.None;

    // Optional hints
    public string? GuessedExtension { get; set; }
    public string? ContainerSubtype { get; set; }
    public string? ScriptLanguage { get; set; }

    // PE triage hints
    public string? PeMachine { get; set; }
    public string? PeSubsystem { get; set; }

    // Container summary (ZIP only for now)
    public int? ContainerEntryCount { get; set; }
    public IReadOnlyList<string>? ContainerTopExtensions { get; set; }

    public IReadOnlyDictionary<string, string>? VersionInfo { get; set; }

    public SignatureSummary? Signature { get; set; }
}

public sealed class SignatureSummary {
    public bool IsSigned { get; set; }
    public int CertificateTableSize { get; set; }
    public string? CertificateBlobSha256 { get; set; }
}

public static partial class FileInspector {
    /// <summary>
    /// Runs a best-effort, dependency-free analysis of the file at <paramref name="path"/>, combining content detection,
    /// container hints, version data and lightweight risk signals into a single result.
    /// </summary>
    /// <param name="path">Path to a local file.</param>
    /// <param name="options">Optional enrichment options used by content detection.</param>
    /// <returns>A populated <see cref="FileAnalysis"/> instance.</returns>
    public static FileAnalysis Analyze(string path, DetectionOptions? options = null) {
        var det = Detect(path, options);
        var res = new FileAnalysis {
            Detection = det,
            Kind = KindClassifier.Classify(det),
            Flags = ContentFlags.None,
            GuessedExtension = det?.GuessedExtension
        };

        try {
            if (det is null) return res;

            // OOXML macros (docx/xlsx/pptx → vbaProject.bin)
            if (det.Extension is "docx" or "xlsx" or "pptx" || det.Extension == "zip") {
                TryInspectZip(path, out bool hasMacros, out var subType, out int? count, out var topExt, out bool hasExec, out bool hasScripts);
                if (hasMacros) res.Flags |= ContentFlags.HasOoxmlMacros;
                if (subType != null) res.ContainerSubtype = subType;
                if (count != null) res.ContainerEntryCount = count;
                if (topExt != null) res.ContainerTopExtensions = topExt;
                if (hasExec) res.Flags |= ContentFlags.ContainerContainsExecutables;
                if (hasScripts) res.Flags |= ContentFlags.ContainerContainsScripts;
                if (det.Extension is "docx" && hasMacros) res.GuessedExtension ??= "docm";
                if (det.Extension is "xlsx" && hasMacros) res.GuessedExtension ??= "xlsm";
                if (det.Extension is "pptx" && hasMacros) res.GuessedExtension ??= "pptm";
            }

            // TAR name scan (lightweight): detect executable/script entries
            if (det.Extension == "tar") {
                TryInspectTar(path, out int? count, out var topExt, out bool hasExec, out bool hasScripts);
                if (count != null) res.ContainerEntryCount = count;
                if (topExt != null) res.ContainerTopExtensions = topExt;
                if (hasExec) res.Flags |= ContentFlags.ContainerContainsExecutables;
                if (hasScripts) res.Flags |= ContentFlags.ContainerContainsScripts;
            }

            // Shebang/script detection for textlike files
            if (InspectHelpers.IsText(det)) {
                var first = ReadFirstLine(path, 256);
                if (first.StartsWith("#!")) {
                    res.Flags |= ContentFlags.IsScript;
                    res.ScriptLanguage = MapShebang(first);
                }
            }

            // PDF heuristics (scan limited bytes)
            if (det.Extension == "pdf") {
                var txt = ReadHeadText(path, 1 << 20); // cap 1MB
                if (ContainsIgnoreCase(txt, "/JavaScript") || ContainsIgnoreCase(txt, "/JS")) res.Flags |= ContentFlags.PdfHasJavaScript;
                if (ContainsIgnoreCase(txt, "/OpenAction")) res.Flags |= ContentFlags.PdfHasOpenAction;
                if (ContainsIgnoreCase(txt, "/AA")) res.Flags |= ContentFlags.PdfHasAA;
            }

            // PE triage (MZ/PE)
            if (IsPe(path, out var peMachine, out var peSubsystem, out bool hasClr, out bool hasSec)) {
                if (hasSec) res.Flags |= ContentFlags.PeHasAuthenticodeDirectory;
                if (hasClr) res.Flags |= ContentFlags.PeIsDotNet;
                res.PeMachine = peMachine;
                res.PeSubsystem = peSubsystem;
                // VersionInfo (Details tab)
                var ver = PeReader.TryExtractVersionStrings(path);
                if (ver != null && ver.Count > 0) res.VersionInfo = ver;
                // Signature summary (presence + blob hash)
                if (PeReader.TryReadPe(path, out var pe) && pe.SecuritySize > 0 && pe.SecurityOffset > 0) {
                    var sig = new SignatureSummary { IsSigned = true, CertificateTableSize = (int)pe.SecuritySize };
                    try {
                        using var fs2 = File.OpenRead(path);
                        if (fs2.Length >= pe.SecurityOffset + pe.SecuritySize) {
                            fs2.Seek(pe.SecurityOffset, SeekOrigin.Begin);
                            var buf = new byte[Math.Min(pe.SecuritySize, 1_000_000u)]; // cap to 1MB for hash
                            int n = fs2.Read(buf, 0, buf.Length);
                            using var sha = System.Security.Cryptography.SHA256.Create();
                            sig.CertificateBlobSha256 = ToLowerHex(sha.ComputeHash(buf, 0, n));
                        }
                    } catch { }
                    res.Signature = sig;
                }
            }
        } catch { /* swallow; analysis is best-effort */ }

        return res;
    }

    private static void TryInspectZip(string path, out bool hasMacros, out string? containerSubtype, out int? entryCount, out IReadOnlyList<string>? topExtensions, out bool hasExecutables, out bool hasScripts) {
        hasMacros = false; containerSubtype = null; entryCount = null; topExtensions = null; hasExecutables = false; hasScripts = false;
        try {
            using var fs = File.OpenRead(path);
            using var za = new ZipArchive(fs, ZipArchiveMode.Read, leaveOpen: true);
            entryCount = za.Entries.Count;
            var exts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            foreach (var e in za.Entries) {
                var name = e.FullName;
                if (name.EndsWith("/")) continue; // folder
                if (name.EndsWith("vbaProject.bin", StringComparison.OrdinalIgnoreCase)) hasMacros = true;
                var ext = GetExtension(name);
                if (!string.IsNullOrEmpty(ext)) exts[ext] = exts.TryGetValue(ext, out var c) ? c + 1 : 1;
                if (IsExecutableName(name)) hasExecutables = true;
                if (IsScriptName(name)) hasScripts = true;
            }
            topExtensions = exts.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key).Take(5).Select(kv => kv.Key).ToArray();
            var guess = TryGuessZipSubtype(fs, out var mime);
            containerSubtype = guess;
        } catch { }
    }

    private static string GetExtension(string name) {
        var i = name.LastIndexOf('.');
        if (i < 0) return string.Empty;
        return name.Substring(i + 1).ToLowerInvariant();
    }

    private static bool IsExecutableName(string name) {
        var lower = name.ToLowerInvariant();
        return lower.EndsWith(".exe") || lower.EndsWith(".dll") || lower.EndsWith(".scr") || lower.EndsWith(".com") || lower.EndsWith(".msi");
    }

    private static bool IsScriptName(string name) {
        var lower = name.ToLowerInvariant();
        return lower.EndsWith(".ps1") || lower.EndsWith(".bat") || lower.EndsWith(".cmd") || lower.EndsWith(".sh") || lower.EndsWith(".vbs") || lower.EndsWith(".js") || lower.EndsWith(".py") || lower.EndsWith(".rb");
    }

    // Minimal TAR reader: iterate first N entries, derive flags and top extensions.
    private static void TryInspectTar(string path, out int? entryCount, out IReadOnlyList<string>? topExtensions, out bool hasExecutables, out bool hasScripts) {
        entryCount = null; topExtensions = null; hasExecutables = false; hasScripts = false;
        try {
            using var fs = File.OpenRead(path);
            var exts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            int count = 0; int maxEntries = 512; // safety cap
            while (count < maxEntries) {
                var hdrArr = new byte[512];
                int read = fs.Read(hdrArr, 0, hdrArr.Length);
                if (read < 512) break;
                var hdr = new ReadOnlySpan<byte>(hdrArr);
                // End of archive: two consecutive zero blocks
                bool allZero = true; for (int i = 0; i < 512; i++) if (hdr[i] != 0) { allZero = false; break; }
                if (allZero) break;
                // name [0..99]
                string name = ReadCString(hdr.Slice(0, 100));
                // size in octal at [124..135]
                var sizeSpan = hdr.Slice(124, 12);
                long size = ParseOctal(sizeSpan);
                if (!string.IsNullOrEmpty(name) && !name.EndsWith("/")) {
                    var ext = GetExtension(name);
                    if (!string.IsNullOrEmpty(ext)) exts[ext] = exts.TryGetValue(ext, out var c) ? c + 1 : 1;
                    if (IsExecutableName(name)) hasExecutables = true;
                    if (IsScriptName(name)) hasScripts = true;
                    count++;
                }
                // advance to next header (file data padded to 512)
                long toSkip = ((size + 511) / 512) * 512;
                if (toSkip > 0) fs.Seek(toSkip, SeekOrigin.Current);
            }
            entryCount = count;
            topExtensions = exts.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key).Take(5).Select(kv => kv.Key).ToArray();
        } catch { }
    }

    private static string ReadCString(ReadOnlySpan<byte> s) {
        int n = 0; while (n < s.Length && s[n] != 0) n++;
        return System.Text.Encoding.ASCII.GetString(s.Slice(0, n).ToArray());
    }

    private static long ParseOctal(ReadOnlySpan<byte> s) {
        long v = 0;
        for (int i = 0; i < s.Length; i++) {
            byte b = s[i];
            if (b == 0 || b == (byte)' ') break;
            if (b < '0' || b > '7') break;
            v = (v << 3) + (b - '0');
        }
        return v;
    }

    private static string ReadFirstLine(string path, int max) {
        try {
            using var sr = new StreamReader(File.OpenRead(path));
            char[] buf = new char[Math.Max(2, max)];
            int n = sr.Read(buf, 0, buf.Length);
            var s = new string(buf, 0, n);
            int nl = s.IndexOf('\n');
            return nl >= 0 ? s.Substring(0, nl) : s;
        } catch { return string.Empty; }
    }

    private static string MapShebang(string line) {
        var l = line.ToLowerInvariant();
        if (l.Contains("bash")) return "bash";
        if (l.Contains("sh")) return "sh";
        if (l.Contains("python")) return "python";
        if (l.Contains("node")) return "node";
        if (l.Contains("pwsh") || l.Contains("powershell")) return "powershell";
        if (l.Contains("perl")) return "perl";
        if (l.Contains("ruby")) return "ruby";
        return "unknown";
    }

    private static string ReadHeadText(string path, int cap) {
        try {
            using var fs = File.OpenRead(path);
            int len = (int)Math.Min(fs.Length, cap);
            var buf = new byte[len];
            var n = fs.Read(buf, 0, buf.Length);
            return System.Text.Encoding.UTF8.GetString(buf, 0, n);
        } catch { return string.Empty; }
    }

    private static bool ContainsIgnoreCase(string s, string needle) {
        if (string.IsNullOrEmpty(s) || string.IsNullOrEmpty(needle)) return false;
        return s.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0;
    }

    private static bool IsPe(string path, out string? machine, out string? subsystem, out bool hasClr, out bool hasSec) {
        machine = null; subsystem = null; hasClr = false; hasSec = false;
        try {
            using var fs = File.OpenRead(path);
            var br = new BinaryReader(fs);
            if (fs.Length < 0x40) return false;
            if (br.ReadByte() != 0x4D || br.ReadByte() != 0x5A) return false; // MZ
            fs.Seek(0x3C, SeekOrigin.Begin);
            int e_lfanew = br.ReadInt32();
            if (e_lfanew <= 0 || e_lfanew > fs.Length - 256) return false;
            fs.Seek(e_lfanew, SeekOrigin.Begin);
            if (br.ReadByte() != (byte)'P' || br.ReadByte() != (byte)'E' || br.ReadByte() != 0 || br.ReadByte() != 0) return false;
            ushort mach = br.ReadUInt16();
            machine = mach switch { 0x014c => "x86", 0x8664 => "x86_64", 0x01c0 => "arm", 0xaa64 => "aarch64", _ => "unknown" };
            br.ReadUInt16(); // NumberOfSections
            br.ReadUInt32(); // TimeDateStamp
            br.ReadUInt32(); // PointerToSymbolTable
            br.ReadUInt32(); // NumberOfSymbols
            ushort sizeOptionalHeader = br.ReadUInt16();
            br.ReadUInt16(); // Characteristics
            long optStart = fs.Position;
            ushort magic = br.ReadUInt16();
            bool isPlus = magic == 0x20b;
            // skip to Subsystem
            int subsysOffset = isPlus ? 0x5C : 0x44;
            fs.Seek(optStart + subsysOffset, SeekOrigin.Begin);
            ushort subsys = br.ReadUInt16();
            subsystem = subsys switch { 2 => "Windows GUI", 3 => "Windows CUI", 9 => "Windows CE", _ => "unknown" };
            // DataDirectory: COM Descriptor (index 14), Security (index 4)
            int ddOffset = isPlus ? 0x70 : 0x60;
            fs.Seek(optStart + ddOffset, SeekOrigin.Begin);
            // Read 16 directories (VA + Size)
            uint va, sz;
            for (int i = 0; i < 16; i++) {
                va = br.ReadUInt32(); sz = br.ReadUInt32();
                if (i == 4) hasSec = sz != 0; // Security
                if (i == 14) hasClr = sz != 0; // CLR
            }
            return true;
        } catch { return false; }
    }
}