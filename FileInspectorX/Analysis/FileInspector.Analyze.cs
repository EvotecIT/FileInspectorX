using System.IO.Compression;
using System.Runtime.InteropServices;

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
            if ((options?.IncludeContainer != false) && (det.Extension is "docx" or "xlsx" or "pptx" || det.Extension == "zip")) {
                TryInspectZip(path, out bool hasMacros, out var subType, out int? count, out var topExt, out bool hasExec, out bool hasScripts, out bool hasNestedArchives,
                    out bool hasTraversal, out bool hasSymlink, out bool hasAbs, out bool hasInstallers, out bool hasRemoteTemplate, out bool hasDde, out bool hasExtLinks, out int extLinksCount,
                    out bool hasEncryptedEntries, out bool isOoxmlEncrypted, out bool hasDisguisedExec, out List<string>? findings);
                if (hasMacros) res.Flags |= ContentFlags.HasOoxmlMacros;
                if (subType != null) res.ContainerSubtype = subType;
                if (count != null) res.ContainerEntryCount = count;
                if (topExt != null) res.ContainerTopExtensions = topExt;
                if (hasExec) res.Flags |= ContentFlags.ContainerContainsExecutables;
                if (hasScripts) res.Flags |= ContentFlags.ContainerContainsScripts;
                if (hasNestedArchives) res.Flags |= ContentFlags.ContainerContainsArchives;
                if (hasInstallers) res.Flags |= ContentFlags.ContainerContainsInstallers;
                if (hasTraversal) res.Flags |= ContentFlags.ArchiveHasPathTraversal;
                if (hasSymlink) res.Flags |= ContentFlags.ArchiveHasSymlinks;
                if (hasAbs) res.Flags |= ContentFlags.ArchiveHasAbsolutePaths;
                if (hasEncryptedEntries) res.Flags |= ContentFlags.ArchiveHasEncryptedEntries;
                if (isOoxmlEncrypted) res.Flags |= ContentFlags.OoxmlEncrypted;
                if (det.Extension is "docx" && hasMacros) res.GuessedExtension ??= "docm";
                if (det.Extension is "xlsx" && hasMacros) res.GuessedExtension ??= "xlsm";
                if (det.Extension is "pptx" && hasMacros) res.GuessedExtension ??= "pptm";
                // Package signature extraction for APPX/MSIX
                if (subType is "appx" or "msix") { TryPopulateAppxSignature(path, res); TryPopulateAppxManifest(path, res); }
                if (subType is "vsix") { TryPopulateVsixManifest(path, res); }
                if (hasRemoteTemplate) res.Flags |= ContentFlags.OfficeRemoteTemplate;
                if (hasDde) res.Flags |= ContentFlags.OfficePossibleDde;
                if (hasExtLinks) {
                    res.Flags |= ContentFlags.OfficeExternalLinks;
                    res.OfficeExternalLinksCount = extLinksCount;
                }
                if (hasDisguisedExec) res.Flags |= ContentFlags.ContainerHasDisguisedExecutables;
                if (findings != null && findings.Count > 0)
                {
                    var list = new List<string>(res.SecurityFindings ?? Array.Empty<string>());
                    list.AddRange(findings);
                    res.SecurityFindings = list;
                }
            }

            // TAR scan hints
            if ((options?.IncludeContainer != false) && det.Extension == "tar") {
                TryInspectTar(path, out int? count, out var topExt, out bool hasExec, out bool hasScripts, out bool hasNestedArchives);
                if (count != null) res.ContainerEntryCount = count;
                if (topExt != null) res.ContainerTopExtensions = topExt;
                if (hasExec) res.Flags |= ContentFlags.ContainerContainsExecutables;
                if (hasScripts) res.Flags |= ContentFlags.ContainerContainsScripts;
                if (hasNestedArchives) res.Flags |= ContentFlags.ContainerContainsArchives;
                // Lightweight TAR safety preflight for traversal/absolute/symlink
                try {
                    using var fs2 = File.OpenRead(path);
                    bool tHasTrav = false, tHasAbs = false, tHasSym = false;
                    while (true) {
                        var hdr = new byte[512]; int r = fs2.Read(hdr, 0, 512); if (r < 512) break;
                        bool zero = true; for (int i = 0; i < 512; i++) if (hdr[i] != 0) { zero = false; break; }
                        if (zero) break;
                        string name = ReadCString(new ReadOnlySpan<byte>(hdr, 0, 100));
                        byte typeflag = hdr[156];
                        if (name.StartsWith("../") || name.StartsWith("..\\")) tHasTrav = true;
                        if (name.StartsWith("/") || (name.Length >= 3 && char.IsLetter(name[0]) && name[1] == ':' && (name[2] == '/' || name[2] == '\\'))) tHasAbs = true;
                        if (typeflag == (byte)'2') tHasSym = true; // symlink
                        long size = ParseOctal(new ReadOnlySpan<byte>(hdr, 124, 12));
                        long skip = ((size + 511) / 512) * 512; if (skip > 0) fs2.Seek(skip, SeekOrigin.Current);
                    }
                    if (tHasTrav) res.Flags |= ContentFlags.ArchiveHasPathTraversal;
                    if (tHasAbs) res.Flags |= ContentFlags.ArchiveHasAbsolutePaths;
                    if (tHasSym) res.Flags |= ContentFlags.ArchiveHasSymlinks;
                } catch { }
            }

            // RAR/7z quick flags
            if ((options?.IncludeContainer != false) && (det.Extension == "rar"))
            {
                if (TryInspectRarQuick(path)) res.Flags |= ContentFlags.ArchiveHasEncryptedEntries;
            }
            // 7z encryption detection is non-trivial; reserved for a deeper pass in future

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
                if (Settings.SecretsScanEnabled)
                {
                    var ss = SecurityHeuristics.CountSecrets(path, Settings.DetectionReadBudgetBytes);
                    if (ss.PrivateKeyCount > 0 || ss.JwtLikeCount > 0 || ss.KeyPatternCount > 0) res.Secrets = ss;
                }
            }

            // Permissions/ownership snapshot (best-effort; cross-platform)
            if (options?.IncludePermissions != false) res.Security = BuildFileSecurity(path);

            // PE Authenticode (best-effort, cross-platform) for PE files
            if ((options?.IncludeAuthenticode != false) && (det.Extension is "exe" or "dll" or "sys" or "cpl")) {
                TryPopulateAuthenticode(path, res);
            }
            // MSI package properties (Windows only)
            if ((options?.IncludeInstaller != false) && (det.Extension?.Equals("msi", StringComparison.OrdinalIgnoreCase) ?? false))
            {
                TryPopulateMsiProperties(path, res);
            }
            // On Windows, attempt WinVerifyTrust for MSI and general files (policy validation)
#if NET8_0_OR_GREATER || NET472
            var declaredExt2 = System.IO.Path.GetExtension(path)?.TrimStart('.').ToLowerInvariant();
            if ((options?.IncludeAuthenticode != false) && RuntimeInformation.IsOSPlatform(OSPlatform.Windows) && (declaredExt2 == "msi" || declaredExt2 == "msix" || declaredExt2 == "appx"))
            {
                if (res.Authenticode == null) res.Authenticode = new AuthenticodeInfo();
                TryVerifyAuthenticodeWinTrust(path, res);
            }
#endif

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
                // XFA and Encrypt markers
                if (ContainsIgnoreCase(txt, "/XFA")) res.Flags |= ContentFlags.PdfHasXfa;
                if (ContainsIgnoreCase(txt, "/Encrypt")) res.Flags |= ContentFlags.PdfEncrypted;
                // Incremental updates: multiple startxref
                int sxf = 0; int pos = 0; while (true) { int at = txt.IndexOf("startxref", pos, StringComparison.OrdinalIgnoreCase); if (at < 0) break; sxf++; pos = at + 8; if (sxf > 2) break; }
                if (sxf > 2) res.Flags |= ContentFlags.PdfManyIncrementalUpdates;
            }

            // Extract generic references (optional)
            if (options?.IncludeReferences != false)
                res.References = BuildReferences(path, det);

            // File name/path checks (always cheap)
            res.NameIssues = AnalyzeName(path, det);

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
                    // Hardening flags from DllCharacteristics
                    var dc = peInfo.DllCharacteristics;
                    bool hasAslr = (dc & 0x0040) != 0; // IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
                    bool hasNx = (dc & 0x0100) != 0;   // IMAGE_DLLCHARACTERISTICS_NX_COMPAT
                    bool hasCfg = (dc & 0x4000) != 0;  // IMAGE_DLLCHARACTERISTICS_GUARD_CF (may require Win10 toolchain)
                    bool hasHighEntropy = (dc & 0x0020) != 0; // IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
                    if (!hasAslr) res.Flags |= ContentFlags.PeNoAslr;
                    if (!hasNx) res.Flags |= ContentFlags.PeNoNx;
                    if (!hasCfg) res.Flags |= ContentFlags.PeNoCfg;
                    if (peInfo.IsPEPlus && !hasHighEntropy) res.Flags |= ContentFlags.PeNoHighEntropyVa;
                }
            }

            // Assessment (optional)
            if (options?.IncludeAssessment != false)
                res.Assessment = Assess(res);

        } catch { }
        return res;
    }

    private static void TryInspectZip(string path, out bool hasMacros, out string? containerSubtype, out int? entryCount, out IReadOnlyList<string>? topExtensions, out bool hasExecutables, out bool hasScripts, out bool hasNestedArchives,
        out bool hasTraversal, out bool hasSymlinks, out bool hasAbs, out bool hasInstallers, out bool hasRemoteTemplate, out bool hasDde, out bool hasExternalLinks, out int externalLinksCount,
        out bool hasEncryptedEntries, out bool isOoxmlEncrypted, out bool hasDisguisedExecutables, out List<string>? findingsOut) {
        hasMacros = false; containerSubtype = null; entryCount = null; topExtensions = null; hasExecutables = false; hasScripts = false; hasNestedArchives = false; hasTraversal = false; hasSymlinks = false; hasAbs = false; hasInstallers = false; hasRemoteTemplate = false; hasDde = false; hasExternalLinks = false; externalLinksCount = 0; hasEncryptedEntries = false; isOoxmlEncrypted = false; hasDisguisedExecutables = false; findingsOut = null;
        try {
            using var fs = File.OpenRead(path);
            using var za = new ZipArchive(fs, ZipArchiveMode.Read, leaveOpen: true);
            var exts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            int count = 0;
            hasNestedArchives = false;
            int sampled = 0; int maxSamples = 16; int headSample = 64;
            bool ooxmlRemoteTemplate = false; bool ooxmlDde = false; bool ooxmlExtLinks = false; int extLinksCount = 0;
            bool sawEncryptionInfo = false; bool sawEncryptedPackage = false;
            int deepScanned = 0; int deepMax = Settings.DeepContainerMaxEntries;
            int deepBytes = Settings.DeepContainerMaxEntryBytes;
            bool deep = Settings.DeepContainerScanEnabled;
            var localFindings = new List<string>(8);
            foreach (var e in za.Entries) {
                if (string.IsNullOrEmpty(e.FullName) || e.FullName.EndsWith("/")) continue;
                count++;
                var name = e.FullName;
                if (name.Equals("EncryptionInfo", StringComparison.OrdinalIgnoreCase)) sawEncryptionInfo = true;
                if (name.Equals("EncryptedPackage", StringComparison.OrdinalIgnoreCase)) sawEncryptedPackage = true;
                if (name.EndsWith("vbaProject.bin", StringComparison.OrdinalIgnoreCase)) hasMacros = true;
                var ext = GetExtension(name);
                if (!string.IsNullOrEmpty(ext)) exts[ext] = exts.TryGetValue(ext, out var c) ? c + 1 : 1;
                if (IsExecutableName(name)) hasExecutables = true;
                if (IsScriptName(name)) hasScripts = true;
                if (!hasInstallers && IsInstallerName(name)) hasInstallers = true;

                // OOXML remote template / DDE cues (Word primary targets)
                try {
                    if (!ooxmlRemoteTemplate && (name.EndsWith("word/_rels/document.xml.rels", StringComparison.OrdinalIgnoreCase) || name.EndsWith("_rels/.rels", StringComparison.OrdinalIgnoreCase)))
                    {
                        using var s = e.Open(); using var sr = new StreamReader(s);
                        var rels = sr.ReadToEnd();
                        if (rels.IndexOf("attachedTemplate", StringComparison.OrdinalIgnoreCase) >= 0 && (rels.IndexOf("TargetMode=\"External\"", StringComparison.OrdinalIgnoreCase) >= 0 || rels.IndexOf("http://", StringComparison.OrdinalIgnoreCase) >= 0 || rels.IndexOf("https://", StringComparison.OrdinalIgnoreCase) >= 0 || rels.IndexOf("\\\\", StringComparison.OrdinalIgnoreCase) >= 0))
                            ooxmlRemoteTemplate = true;
                    }
                    if (!ooxmlDde && (name.Equals("word/document.xml", StringComparison.OrdinalIgnoreCase) || name.EndsWith("/document.xml", StringComparison.OrdinalIgnoreCase)))
                    {
                        using var s2 = e.Open(); using var sr2 = new StreamReader(s2);
                        var docxml = sr2.ReadToEnd();
                        if (docxml.IndexOf("DDEAUTO", StringComparison.OrdinalIgnoreCase) >= 0 || docxml.IndexOf(" DDE ", StringComparison.OrdinalIgnoreCase) >= 0)
                            ooxmlDde = true;
                    }
                    if (name.StartsWith("xl/externalLinks/", StringComparison.OrdinalIgnoreCase) && name.EndsWith(".xml", StringComparison.OrdinalIgnoreCase))
                    {
                        ooxmlExtLinks = true; extLinksCount++;
                    }
                    if (name.Equals("xl/_rels/workbook.xml.rels", StringComparison.OrdinalIgnoreCase))
                    {
                        using var s3 = e.Open(); using var sr3 = new StreamReader(s3);
                        var rels = sr3.ReadToEnd();
                        // Count targets that point to externalLinks folder
                        int pos = 0; int local = 0; while (true) { int at = rels.IndexOf("externalLinks/", pos, StringComparison.OrdinalIgnoreCase); if (at < 0) break; local++; pos = at + 8; }
                        if (local > 0) { ooxmlExtLinks = true; extLinksCount += local; }
                    }
                } catch { }

                // Safety preflight: traversal/absolute
                if (!hasTraversal && (name.Contains("../") || name.Contains("..\\") || name.StartsWith("/"))) hasTraversal = true;
                if (!hasAbs && (name.StartsWith("/") || (name.Length >= 3 && char.IsLetter(name[0]) && name[1] == ':' && (name[2] == '/' || name[2] == '\\')))) hasAbs = true;

                // Symlink check (POSIX mode in external attributes high 16 bits: 0120000)
                try {
#if NET8_0_OR_GREATER || NET472
                    int attrs = e.ExternalAttributes;
                    int unixMode = (attrs >> 16) & 0xFFFF;
                    const int IFMT = 0xF000, IFLNK = 0xA000;
                    if ((unixMode & IFMT) == IFLNK) hasSymlinks = true;
#endif
                } catch { }

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

                // Deep scan of entries for disguised executables and known tool names (bounded by budgets)
                if (deep && deepScanned < deepMax)
                {
                    try {
                        // Known tool names by filename
                        var lowerName = name.ToLowerInvariant();
                        foreach (var ind in Settings.KnownToolNameIndicators)
                        {
                            if (!string.IsNullOrWhiteSpace(ind) && lowerName.Contains(ind))
                            {
                                localFindings.Add($"tool:{ind}"); break;
                            }
                        }
                        // Content-based disguise check
                        using var es2 = e.Open();
                        int cap = (int)Math.Min(Math.Min(e.Length, deepBytes), deepBytes);
                        var buf = new byte[Math.Max(64, cap)];
                        int nn = es2.Read(buf, 0, buf.Length);
                        if (nn > 0)
                        {
                            var det2 = Detect(new ReadOnlySpan<byte>(buf, 0, nn), null);
                            var declExt = GetExtension(name);
                            var looksExe = det2?.Extension is "exe" or "dll" || (nn >= 2 && buf[0] == (byte)'M' && buf[1] == (byte)'Z');
                            if (looksExe)
                            {
                                // if declared ext does not indicate executable
                                if (!(declExt is "exe" or "dll")) hasDisguisedExecutables = true;
                                hasExecutables = true;
                            }
                            // Installer hint by name or magic (best-effort)
                            if (!hasInstallers && (declExt is "msi" || lowerName.EndsWith(".msi"))) hasInstallers = true;

                            // Optional hash match for known tools (only when entry small enough)
                            if (Settings.KnownToolHashes.Count > 0 && nn > 0 && e.Length <= deepBytes)
                            {
                                try {
                                    using var sha = System.Security.Cryptography.SHA256.Create();
                                    // Compute on first buffer; if entry is larger but within deepBytes, read fully
                                    var ms = new System.IO.MemoryStream();
                                    ms.Write(buf, 0, nn);
                                    if (nn < cap)
                                    {
                                        int left = cap - nn; var tmp = new byte[8192]; int r2;
                                        while (left > 0 && (r2 = es2.Read(tmp, 0, Math.Min(tmp.Length, left))) > 0) { ms.Write(tmp, 0, r2); left -= r2; }
                                    }
                                    var hash = sha.ComputeHash(ms.ToArray());
                                    var hex = ToLowerHex(hash);
                                    foreach (var kv in Settings.KnownToolHashes)
                                    {
                                        if (string.Equals(kv.Value, hex, StringComparison.OrdinalIgnoreCase)) { localFindings.Add($"toolhash:{kv.Key}"); break; }
                                    }
                                } catch { }
                            }
                        }
                    } catch { }
                    deepScanned++;
                }
            }
            entryCount = count;
            topExtensions = exts.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key).Take(5).Select(kv => kv.Key).ToArray();
            var guess = TryGuessZipSubtype(fs, out var _);
            containerSubtype = guess;
            if (hasNestedArchives && containerSubtype == null) containerSubtype = "nested-archive";
            hasRemoteTemplate = ooxmlRemoteTemplate;
            hasDde = ooxmlDde;
            hasExternalLinks = ooxmlExtLinks;
            externalLinksCount = extLinksCount;
            // Check encryption flags by scanning central directory
            if (!hasEncryptedEntries) hasEncryptedEntries = ZipCentralDirectoryHasEncryptedEntries(fs);
            // OOXML encrypted packages present these two entries at root
            isOoxmlEncrypted = sawEncryptionInfo && sawEncryptedPackage;
            findingsOut = localFindings.Count > 0 ? localFindings : null;
        } catch { }
    }

    private static bool ZipCentralDirectoryHasEncryptedEntries(Stream fs)
    {
        try {
            if (!fs.CanSeek || fs.Length < 22) return false;
            long maxScan = Math.Min(fs.Length, 1 << 16); // EOCD must be within last 64KB
            var buf = new byte[maxScan];
            fs.Seek(fs.Length - maxScan, SeekOrigin.Begin);
            int n = fs.Read(buf, 0, buf.Length);
            if (n <= 0) return false;
            int eocdSig = 0x06054b50;
            int cdSig = 0x02014b50;
            for (int i = n - 22; i >= 0; i--)
            {
                if (ReadLe32(buf, i) == eocdSig)
                {
                    int entries = ReadLe16(buf, i + 10);
                    int cdOffset = ReadLe32(buf, i + 16);
                    // Seek to central directory and scan flags per entry
                    long abs = cdOffset;
                    if (abs < 0 || abs >= fs.Length) break;
                    long remain = fs.Length - abs;
                    fs.Seek(abs, SeekOrigin.Begin);
                    var cdbuf = new byte[Math.Min(remain, 1 << 20)];
                    int m = fs.Read(cdbuf, 0, cdbuf.Length);
                    int p = 0; int scanned = 0;
                    while (p + 46 <= m && scanned < entries)
                    {
                        if (ReadLe32(cdbuf, p) != cdSig) break;
                        int flags = ReadLe16(cdbuf, p + 8);
                        if ((flags & 0x1) != 0) return true; // encrypted
                        int fnLen = ReadLe16(cdbuf, p + 28);
                        int exLen = ReadLe16(cdbuf, p + 30);
                        int cmLen = ReadLe16(cdbuf, p + 32);
                        p += 46 + fnLen + exLen + cmLen;
                        scanned++;
                    }
                    break;
                }
            }
        } catch { }
        return false;
    }

    private static int ReadLe16(byte[] a, int o) => a[o] | (a[o+1] << 8);
    private static int ReadLe32(byte[] a, int o) => a[o] | (a[o+1] << 8) | (a[o+2] << 16) | (a[o+3] << 24);

    private static bool TryInspectRarQuick(string path)
    {
        // Best-effort: detect RAR4 header-encryption flag in main header (not extraction)
        try {
            using var fs = File.OpenRead(path);
            var sig = new byte[8];
            int r = fs.Read(sig, 0, sig.Length);
            if (r < 7) return false;
            bool rar4 = sig[0] == 0x52 && sig[1] == 0x61 && sig[2] == 0x72 && sig[3] == 0x21 && sig[4] == 0x1A && sig[5] == 0x07 && sig[6] == 0x00;
            if (!rar4) return false; // RAR5 skipped for now
            // Read next header: CRC(2), Type(1), Flags(2), Size(2)
            var hdr = new byte[7];
            if (fs.Read(hdr, 0, 7) != 7) return false;
            byte type = hdr[2];
            int flags = hdr[3] | (hdr[4] << 8);
            // Type 0x73 (MAIN_HEADER), bit 0x0080 = encrypted headers
            if (type == 0x73 && (flags & 0x0080) != 0) return true;
        } catch { }
        return false;
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
        return lower.EndsWith(".exe") || lower.EndsWith(".dll") || lower.EndsWith(".scr") || lower.EndsWith(".com") || lower.EndsWith(".msi") || lower.EndsWith(".msix") || lower.EndsWith(".appx") || lower.EndsWith(".msixbundle");
    }

    private static bool IsScriptName(string name) {
        var lower = name.ToLowerInvariant();
        return lower.EndsWith(".ps1") || lower.EndsWith(".bat") || lower.EndsWith(".cmd") || lower.EndsWith(".sh") || lower.EndsWith(".vbs") || lower.EndsWith(".js") || lower.EndsWith(".py") || lower.EndsWith(".rb");
    }

    private static bool IsInstallerName(string name)
    {
        var l = name.ToLowerInvariant();
        return l.EndsWith(".msi") || l.EndsWith(".msix") || l.EndsWith(".appx") || l.EndsWith(".msixbundle") || l.EndsWith(".msu") || l.EndsWith("setup.exe") || l.EndsWith("install.exe");
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

    private static void TryPopulateAppxSignature(string path, FileAnalysis res)
    {
#if NET8_0_OR_GREATER || NET472
        try {
            using var fs = File.OpenRead(path);
            using var za = new ZipArchive(fs, ZipArchiveMode.Read, leaveOpen: true);
            var sigEntry = za.GetEntry("AppxSignature.p7x") ?? za.GetEntry("AppxSignature.p7s");
            if (sigEntry == null) return;
            using var s = sigEntry.Open();
            using var ms = new MemoryStream();
            s.CopyTo(ms);
            var data = ms.ToArray();
            var cms = new System.Security.Cryptography.Pkcs.SignedCms();
            cms.Decode(data);
            var ai = res.Authenticode ?? new AuthenticodeInfo();
            ai.Present = true;
            ai.VerificationNote = "Package signature (AppxSignature)";
            var signer = cms.SignerInfos.Count > 0 ? cms.SignerInfos[0] : null;
            var cert = signer?.Certificate;
            if (cert != null)
            {
                ai.SignerSubject = cert.Subject; ai.SignerIssuer = cert.Issuer; ai.SignatureAlgorithm = cert.SignatureAlgorithm?.FriendlyName;
                ai.NotBefore = cert.NotBefore; ai.NotAfter = cert.NotAfter; ai.DigestAlgorithm = signer?.DigestAlgorithm?.FriendlyName;
                ai.SignerThumbprint = cert.Thumbprint; ai.SignerSerialHex = cert.SerialNumber; FillCertFields(cert, ai);
                try { var ch = new System.Security.Cryptography.X509Certificates.X509Chain(); ch.ChainPolicy.RevocationMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck; ai.ChainValid = ch.Build(cert); } catch { }
                try { cms.CheckSignature(true); ai.EnvelopeSignatureValid = true; } catch { ai.EnvelopeSignatureValid = false; }
            }
            res.Authenticode = ai;
        } catch { }
#endif
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
