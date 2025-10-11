using System.IO.Compression;

namespace FileInspectorX;

/// <summary>
/// Analysis routines implemented as part of the <see cref="FileInspector"/> facade.
/// </summary>
public static partial class FileInspector {
    /// <summary>
    /// Runs a best-effort, dependency-free analysis of the file at <paramref name="path"/>, combining content detection,
    /// container hints, version data and lightweight risk signals into a single result.
    /// </summary>
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

            // OOXML macros and ZIP container hints
            if (det.Extension is "docx" or "xlsx" or "pptx" || det.Extension == "zip") {
                TryInspectZip(path, out bool hasMacros, out var subType, out int? count, out var topExt, out bool hasExec, out bool hasScripts, out bool hasNestedArchives);
                if (hasMacros) res.Flags |= ContentFlags.HasOoxmlMacros;
                if (subType != null) res.ContainerSubtype = subType;
                if (count != null) res.ContainerEntryCount = count;
                if (topExt != null) res.ContainerTopExtensions = topExt;
                if (hasExec) res.Flags |= ContentFlags.ContainerContainsExecutables;
                if (hasScripts) res.Flags |= ContentFlags.ContainerContainsScripts;
                if (hasNestedArchives) res.Flags |= ContentFlags.ContainerContainsArchives;
                if (det.Extension is "docx" && hasMacros) res.GuessedExtension ??= "docm";
                if (det.Extension is "xlsx" && hasMacros) res.GuessedExtension ??= "xlsm";
                if (det.Extension is "pptx" && hasMacros) res.GuessedExtension ??= "pptm";
            }

            // TAR scan hints
            if (det.Extension == "tar") {
                TryInspectTar(path, out int? count, out var topExt, out bool hasExec, out bool hasScripts, out bool hasNestedArchives);
                if (count != null) res.ContainerEntryCount = count;
                if (topExt != null) res.ContainerTopExtensions = topExt;
                if (hasExec) res.Flags |= ContentFlags.ContainerContainsExecutables;
                if (hasScripts) res.Flags |= ContentFlags.ContainerContainsScripts;
                if (hasNestedArchives) res.Flags |= ContentFlags.ContainerContainsArchives;
            }

            // Shebang/script detection for textlike files
            if (InspectHelpers.IsText(det)) {
                var first = ReadFirstLine(path, 256);
                if (first.StartsWith("#!")) {
                    res.Flags |= ContentFlags.IsScript;
                    res.ScriptLanguage = MapShebang(first);
                }
                // JS minified heuristic if file extension is .js
                var declaredExt = System.IO.Path.GetExtension(path)?.TrimStart('.').ToLowerInvariant();
                if (declaredExt == "js") {
                    if (LooksMinifiedJs(path, Settings.DetectionReadBudgetBytes,
                        Settings.JsMinifiedMinLength,
                        Settings.JsMinifiedAvgLineThreshold,
                        Settings.JsMinifiedDensityThreshold)) {
                        res.Flags |= ContentFlags.JsLooksMinified;
                    }
                }
                // Potentially dangerous scripts by type
                if (declaredExt is "ps1" or "sh" or "bat" or "cmd") {
                    res.Flags |= ContentFlags.ScriptsPotentiallyDangerous;
                }
                // Set TextSubtype for common text families
                res.TextSubtype = declaredExt switch {
                    "md" => "markdown",
                    "yml" or "yaml" => "yaml",
                    "json" => "json",
                    "xml" => "xml",
                    "csv" => "csv",
                    "tsv" => "tsv",
                    "log" => "log",
                    "ps1" or "psm1" or "psd1" => "powershell",
                    "vbs" => "vbscript",
                    "sh" or "bash" or "zsh" => "shell",
                    "bat" or "cmd" => "batch",
                    _ => res.TextSubtype
                };

                // Lightweight script security assessment
                var sf = SecurityHeuristics.AssessScript(path, declaredExt, Settings.DetectionReadBudgetBytes);
                if (sf.Count > 0) res.SecurityFindings = sf;
            }

            // Permissions/ownership snapshot (best-effort; cross-platform)
            res.Security = BuildFileSecurity(path);

            // PE Authenticode (best-effort, cross-platform) for PE files
            if (det.Extension is "exe" or "dll" or "sys" or "cpl") {
                TryPopulateAuthenticode(path, res);
            }

            // CSV/TSV row estimate (lightweight)
            if (det.Extension is "csv" or "tsv" || string.Equals(det.MimeType, "text/csv", StringComparison.OrdinalIgnoreCase) || string.Equals(det.MimeType, "text/tab-separated-values", StringComparison.OrdinalIgnoreCase)) {
                res.EstimatedLineCount = EstimateLines(path, Settings.DetectionReadBudgetBytes);
            }

            // PDF heuristics
            if (det.Extension == "pdf") {
                var txt = ReadHeadText(path, 1 << 20); // cap 1MB
                if (ContainsIgnoreCase(txt, "/JavaScript") || ContainsIgnoreCase(txt, "/JS")) res.Flags |= ContentFlags.PdfHasJavaScript;
                if (ContainsIgnoreCase(txt, "/OpenAction")) res.Flags |= ContentFlags.PdfHasOpenAction;
                if (ContainsIgnoreCase(txt, "/AA")) res.Flags |= ContentFlags.PdfHasAA;
                // Embedded files via /EmbeddedFiles name tree, /Filespec dictionary and /EF streams
                if (ContainsIgnoreCase(txt, "/EmbeddedFiles") || (ContainsIgnoreCase(txt, "/Filespec") && ContainsIgnoreCase(txt, "/EF"))) res.Flags |= ContentFlags.PdfHasEmbeddedFiles;
                if (ContainsIgnoreCase(txt, "/Launch")) res.Flags |= ContentFlags.PdfHasLaunch;
                if (ContainsIgnoreCase(txt, "/Names")) res.Flags |= ContentFlags.PdfHasNamesTree;
                // Heuristic: many embedded files (count /Filespec occurrences, threshold > 3)
                int filespecCount = 0;
                int idx = 0;
                while (true) {
                    int at = txt.IndexOf("/Filespec", idx, StringComparison.OrdinalIgnoreCase);
                    if (at < 0) break;
                    filespecCount++;
                    idx = at + 8;
                    if (filespecCount > 3) { res.Flags |= ContentFlags.PdfHasManyEmbeddedFiles; break; }
                }
            }

            // PE triage
            if (IsPe(path, out var peMachine, out var peSubsystem, out bool hasClr, out bool hasSec)) {
                if (hasSec) res.Flags |= ContentFlags.PeHasAuthenticodeDirectory;
                if (hasClr) res.Flags |= ContentFlags.PeIsDotNet;
                res.PeMachine = peMachine;
                res.PeSubsystem = peSubsystem;

                var ver = PeReader.TryExtractVersionStrings(path);
                if (ver != null && ver.Count > 0) res.VersionInfo = ver;
                if (PeReader.TryReadPe(path, out var peInfo)) {
                    if (peInfo.Sections.Any(s => string.Equals(s.Name, "UPX0", StringComparison.OrdinalIgnoreCase) || string.Equals(s.Name, "UPX1", StringComparison.OrdinalIgnoreCase))) {
                        res.Flags |= ContentFlags.PeLooksPackedUpx;
                    }
                }
            }

        } catch { }
        return res;
    }

    private static void TryInspectZip(string path, out bool hasMacros, out string? containerSubtype, out int? entryCount, out IReadOnlyList<string>? topExtensions, out bool hasExecutables, out bool hasScripts, out bool hasNestedArchives) {
        hasMacros = false; containerSubtype = null; entryCount = null; topExtensions = null; hasExecutables = false; hasScripts = false; hasNestedArchives = false;
        try {
            using var fs = File.OpenRead(path);
            using var za = new ZipArchive(fs, ZipArchiveMode.Read, leaveOpen: true);
            var exts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            int count = 0;
            hasNestedArchives = false;
            int sampled = 0; int maxSamples = 16; int headSample = 64;
            foreach (var e in za.Entries) {
                if (string.IsNullOrEmpty(e.FullName) || e.FullName.EndsWith("/")) continue;
                count++;
                var name = e.FullName;
                if (name.EndsWith("vbaProject.bin", StringComparison.OrdinalIgnoreCase)) hasMacros = true;
                var ext = GetExtension(name);
                if (!string.IsNullOrEmpty(ext)) exts[ext] = exts.TryGetValue(ext, out var c) ? c + 1 : 1;
                if (IsExecutableName(name)) hasExecutables = true;
                if (IsScriptName(name)) hasScripts = true;

                // Light inner-archive sampler: detect nested archives by magic (bounded by samples and size)
                if (!hasNestedArchives && sampled < maxSamples && e.Length >= 4) {
                    try {
                        using var es = e.Open();
                        var head = new byte[Math.Min(headSample, (int)Math.Min(e.Length, headSample))];
                        int n = es.Read(head, 0, head.Length);
                        if (n > 0) {
                            var span = new ReadOnlySpan<byte>(head, 0, n);
                            var det = Detect(span, null);
                            if (det != null) {
                                var de = det.Extension?.ToLowerInvariant();
                                if (de is "zip" or "7z" or "rar" or "tar" or "gz" or "bz2" or "xz" or "zst" or "iso" or "udf") {
                                    hasNestedArchives = true;
                                }
                            }
                        }
                    } catch { /* ignore per-entry errors */ }
                    sampled++;
                }
            }
            entryCount = count;
            topExtensions = exts.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key).Take(5).Select(kv => kv.Key).ToArray();
            var guess = TryGuessZipSubtype(fs, out var _);
            containerSubtype = guess;
            if (hasNestedArchives && containerSubtype == null) containerSubtype = "nested-archive";
        } catch { }
    }

    private static void TryInspectTar(string path, out int? entryCount, out IReadOnlyList<string>? topExtensions, out bool hasExecutables, out bool hasScripts, out bool hasNestedArchives) {
        entryCount = null; topExtensions = null; hasExecutables = false; hasScripts = false; hasNestedArchives = false;
        try {
            using var fs = File.OpenRead(path);
            var exts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            int count = 0; int maxEntries = 512; // safety cap
            while (count < maxEntries) {
                var hdrArr = new byte[512];
                int read = fs.Read(hdrArr, 0, hdrArr.Length);
                if (read < 512) break;
                var hdr = new ReadOnlySpan<byte>(hdrArr);
                bool allZero = true; for (int i = 0; i < 512; i++) if (hdr[i] != 0) { allZero = false; break; }
                if (allZero) break;
                string name = ReadCString(hdr.Slice(0, 100));
                var sizeSpan = hdr.Slice(124, 12);
                long size = ParseOctal(sizeSpan);
                if (!string.IsNullOrEmpty(name) && !name.EndsWith("/")) {
                    var ext = GetExtension(name);
                    if (!string.IsNullOrEmpty(ext)) exts[ext] = exts.TryGetValue(ext, out var c) ? c + 1 : 1;
                    if (IsExecutableName(name)) hasExecutables = true;
                    if (IsScriptName(name)) hasScripts = true;
                    count++;
                    // Sample small entry head to detect nested archives
                    if (!hasNestedArchives && size > 0 && size <= 128) {
                        int sample = (int)Math.Min(64, size);
                        var head = new byte[sample];
                        int nhead = fs.Read(head, 0, head.Length);
                        long pad = ((size + 511) / 512) * 512;
                        long toSkipRem = pad - nhead;
                        if (nhead > 0) {
                            var span = new ReadOnlySpan<byte>(head, 0, nhead);
                            var det = Detect(span, null);
                            if (det != null) {
                                var de = det.Extension?.ToLowerInvariant();
                                if (de is "zip" or "7z" or "rar" or "tar" or "gz" or "bz2" or "xz" or "zst" or "iso" or "udf") {
                                    hasNestedArchives = true;
                                }
                            }
                        }
                        if (toSkipRem > 0) fs.Seek(toSkipRem, SeekOrigin.Current);
                        continue;
                    }
                }
                long toSkip = ((size + 511) / 512) * 512;
                if (toSkip > 0) fs.Seek(toSkip, SeekOrigin.Current);
            }
            entryCount = count;
            topExtensions = exts.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key).Take(5).Select(kv => kv.Key).ToArray();
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

    private static bool LooksMinifiedJs(string path, int cap, int minLen, int avgLineThreshold, double densityThreshold) {
        try {
            var text = ReadHeadText(path, Math.Min(cap, 512 * 1024));
            if (string.IsNullOrEmpty(text) || text.Length < minLen) return false;
            int lines = 1; for (int i = 0; i < text.Length; i++) if (text[i] == '\n') lines++;
            int nonWs = 0; for (int i = 0; i < text.Length; i++) { char c = text[i]; if (!char.IsWhiteSpace(c)) nonWs++; }
            double avgLineLen = (double)text.Length / Math.Max(1, lines);
            double density = (double)nonWs / text.Length; // closer to 1 => denser
            // Heuristic thresholds: long lines, few line breaks, high density
            return (avgLineLen > avgLineThreshold && lines < text.Length / 300 && density > densityThreshold);
        } catch { return false; }
    }

    private static int? EstimateLines(string path, int cap) {
        try {
            using var fs = File.OpenRead(path);
            long len = Math.Min(fs.Length, cap);
            var buf = new byte[(int)len];
            int n = fs.Read(buf, 0, buf.Length);
            if (n <= 0) return 0;
            int lines = 0; for (int i = 0; i < n; i++) if (buf[i] == (byte)'\n') lines++;
            if (fs.Length > n && n > 0) {
                double ratio = (double)fs.Length / n;
                lines = (int)Math.Round(lines * ratio);
            }
            return lines;
        } catch { return null; }
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
            int subsysOffset = isPlus ? 0x5C : 0x44;
            fs.Seek(optStart + subsysOffset, SeekOrigin.Begin);
            ushort subsys = br.ReadUInt16();
            subsystem = subsys switch { 2 => "Windows GUI", 3 => "Windows CUI", 9 => "Windows CE", _ => "unknown" };
            int ddOffset = isPlus ? 0x70 : 0x60;
            fs.Seek(optStart + ddOffset, SeekOrigin.Begin);
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
