using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace FileInspectorX;

/// <summary>
/// Analysis routines implemented as part of the <see cref="FileInspector"/> facade.
/// </summary>
public static partial class FileInspector {
    private struct ContainerInnerSample
    {
        public int ExecSampled;
        public int Signed;
        public int Valid;
        public Dictionary<string,int> Publishers;
        public ContainerInnerSample(int e, int s, int v, Dictionary<string,int> p) { ExecSampled = e; Signed = s; Valid = v; Publishers = p; }
    }
    private static ContainerInnerSample? _lastContainerInnerSample;
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
                    out bool hasEncryptedEntries, out int encryptedCount, out bool isOoxmlEncrypted, out bool hasDisguisedExec, out List<string>? findings,
                    out int innerExecSampled, out int innerSignedAny, out int innerValid, out Dictionary<string,int>? innerPublishers, out Dictionary<string,int>? innerPublishersValid, out Dictionary<string,int>? innerPublishersSelf, out List<InnerEntryPreview>? previewOut);
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
                if (encryptedCount > 0) res.EncryptedEntryCount = encryptedCount;
                if (findings != null && findings.Count > 0)
                {
                    var list = new List<string>(res.SecurityFindings ?? Array.Empty<string>());
                    list.AddRange(findings);
                    res.SecurityFindings = list;
                    res.InnerFindings = findings.Take(Settings.DeepContainerMaxEntries).ToArray();
                }
                if (innerExecSampled > 0)
                {
                    res.InnerExecutablesSampled = innerExecSampled;
                    res.InnerSignedExecutables = innerSignedAny;
                    res.InnerValidSignedExecutables = innerValid;
                    if (innerPublishers != null && innerPublishers.Count > 0) res.InnerPublisherCounts = new Dictionary<string,int>(innerPublishers);
                    if (innerPublishersValid != null && innerPublishersValid.Count > 0) res.InnerPublisherValidCounts = new Dictionary<string,int>(innerPublishersValid);
                    if (innerPublishersSelf != null && innerPublishersSelf.Count > 0) res.InnerPublisherSelfSignedCounts = new Dictionary<string,int>(innerPublishersSelf);
                }
                if (previewOut != null && previewOut.Count > 0)
                {
                    res.ArchivePreviewEntries = previewOut.Take(Settings.DeepContainerMaxEntries).ToList();
                }
            }

            // TAR scan hints
            if ((options?.IncludeContainer != false) && det.Extension == "tar") {
                TryInspectTar(path, out int? count, out var topExt, out bool hasExec, out bool hasScripts, out bool hasNestedArchives, out var tarPreview);
                if (count != null) res.ContainerEntryCount = count;
                if (topExt != null) res.ContainerTopExtensions = topExt;
                if (hasExec) res.Flags |= ContentFlags.ContainerContainsExecutables;
                if (hasScripts) res.Flags |= ContentFlags.ContainerContainsScripts;
                if (hasNestedArchives) res.Flags |= ContentFlags.ContainerContainsArchives;
                if (tarPreview != null && tarPreview.Count > 0) res.ArchivePreviewEntries = tarPreview.Take(Settings.DeepContainerMaxEntries).ToList();
                // Attach inner signer sampling results if available
                if (_lastContainerInnerSample.HasValue)
                {
                    var s = _lastContainerInnerSample.Value;
                    if (s.ExecSampled > 0)
                    {
                        res.InnerExecutablesSampled = s.ExecSampled;
                        res.InnerSignedExecutables = s.Signed;
                        res.InnerValidSignedExecutables = s.Valid;
                        if (s.Publishers != null && s.Publishers.Count > 0) res.InnerPublisherCounts = new Dictionary<string,int>(s.Publishers);
                    }
                    _lastContainerInnerSample = null;
                }
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

            // RAR/7z quick flags + (best-effort) encrypted entries accounting under budget
            if ((options?.IncludeContainer != false) && (det.Extension == "rar"))
            {
                // Distinguish RAR4 vs RAR5 by signature
                try {
                    using var fsr = File.OpenRead(path);
                    var head = new byte[8]; int nr = fsr.Read(head, 0, head.Length);
                    bool isRar5 = nr >= 8 && head[0]==0x52 && head[1]==0x61 && head[2]==0x72 && head[3]==0x21 && head[4]==0x1A && head[5]==0x07 && head[6]==0x01 && head[7]==0x00;
                    bool isRar4 = !isRar5;
                    if (isRar4)
                    {
                        if (TryCountRar4EncryptedFiles(path, Settings.DeepContainerMaxEntries, out int encCount, out int totalCount))
                        {
                            if (encCount > 0) res.Flags |= ContentFlags.ArchiveHasEncryptedEntries;
                            res.EncryptedEntryCount = encCount;
                            var list = new List<string>(res.SecurityFindings ?? Array.Empty<string>());
                            list.Add($"rar4:enc={encCount}/{totalCount}");
                            res.SecurityFindings = list;
                            res.InnerFindings = (res.InnerFindings ?? Array.Empty<string>()).Concat(new[]{ $"rar4:enc={encCount}/{totalCount}" }).ToArray();
                        }
                        // Optional deep signer sampling for uncompressed, non-encrypted entries (store-only), bounded by budgets
                        if (Settings.DeepContainerScanEnabled)
                        {
                            if (TrySampleRar4InnerSigners(path, Settings.DeepContainerMaxEntries, Settings.DeepContainerMaxEntryBytes,
                                out int innerExecSampled, out int innerSignedAny, out int innerValid, out var innerPublishers))
                            {
                                if (innerExecSampled > 0)
                                {
                                    res.InnerExecutablesSampled = innerExecSampled;
                                    res.InnerSignedExecutables = innerSignedAny;
                                    res.InnerValidSignedExecutables = innerValid;
                                    if (innerPublishers != null && innerPublishers.Count > 0) res.InnerPublisherCounts = innerPublishers;
                                }
                            }
                        }
                    }
                    else
                    {
                        if (TryInspectRarQuick(path)) res.Flags |= ContentFlags.ArchiveHasEncryptedEntries;
                        var list = new List<string>(res.SecurityFindings ?? Array.Empty<string>());
                        list.Add("rar5:headers-encrypted");
                        res.SecurityFindings = list;
                    }
                } catch { if (TryInspectRarQuick(path)) res.Flags |= ContentFlags.ArchiveHasEncryptedEntries; }
            }
            if ((options?.IncludeContainer != false) && (det.Extension == "7z"))
            {
                if (TryDetect7zEncryptedHeaders(path))
                {
                    res.Flags |= ContentFlags.ArchiveHasEncryptedEntries;
                    var list = new List<string>(res.SecurityFindings ?? Array.Empty<string>());
                    list.Add("7z:headers-encrypted");
                    res.SecurityFindings = list;
                }
                else if (TryCount7zFilesQuick(path, Settings.DetectionReadBudgetBytes, out int files))
                {
                    var list = new List<string>(res.SecurityFindings ?? Array.Empty<string>());
                    list.Add($"7z:files={files}");
                    res.SecurityFindings = list;
                    // Best-effort: extract likely executable names from unencoded Next Header
                    if (Settings.DeepContainerScanEnabled && TryScan7zExecutablesFromHeader(path, Settings.DetectionReadBudgetBytes, out var exeNames, out var dllNames))
                    {
                        int count = (exeNames?.Count ?? 0) + (dllNames?.Count ?? 0);
                        if (count > 0)
                        {
                            res.Flags |= ContentFlags.ContainerContainsExecutables;
                            var list2 = new List<string>(res.SecurityFindings ?? Array.Empty<string>());
                            list2.Add($"7z:names-exe={count}");
                            res.SecurityFindings = list2;
                            // Preview a few
                            var previews = new List<InnerEntryPreview>();
                            foreach (var n in (exeNames ?? System.Linq.Enumerable.Empty<string>()).Take(5)) previews.Add(new InnerEntryPreview { Name = n, DetectedExtension = "exe" });
                            foreach (var n in (dllNames ?? System.Linq.Enumerable.Empty<string>()).Take(Math.Max(0, 5 - previews.Count))) previews.Add(new InnerEntryPreview { Name = n, DetectedExtension = "dll" });
                            if (previews.Count > 0) res.ArchivePreviewEntries = previews;
                        }
                    }
                }
            }
            // 7z encryption detection is non-trivial; reserved for a deeper pass in future

            // MSI metadata enrichment (Windows): product version via msi.dll
            if ((options?.IncludeInstaller != false) && det.Extension == "msi")
            {
                try {
                    var msiVer = FileInspector.TryGetMsiVersion(path);
                    if (!string.IsNullOrWhiteSpace(msiVer))
                    {
                        var dict = res.VersionInfo != null ? new Dictionary<string,string>(res.VersionInfo.ToDictionary(kv => kv.Key, kv => kv.Value)) : new Dictionary<string,string>();
                        dict["ProductVersion"] = msiVer!;
                        res.VersionInfo = dict;
                    }
                } catch { }
            }
            // If we discovered MSI installer metadata later but detection stayed at generic OLE2, promote it to MSI
            try
            {
                if ((options?.IncludeInstaller != false) && res.Installer?.Kind == InstallerKind.Msi && det != null && string.Equals(det.Extension, "ole2", StringComparison.OrdinalIgnoreCase))
                {
                    det.Extension = "msi";
                    det.MimeType = "application/x-msi";
                    det.Confidence = "High";
                    det.Reason = string.IsNullOrEmpty(det.Reason) ? "ole2:msi-confirmed" : det.Reason + ";msi-confirmed";
                }
            } catch { }

            // Best-effort service entry indicator (ASCII scan for 'ServiceMain')
            try
            {
                using var fsSvc = File.OpenRead(path);
                int capSvc = (int)Math.Min(256 * 1024, fsSvc.Length);
                var bufSvc = new byte[capSvc]; int ns = fsSvc.Read(bufSvc, 0, bufSvc.Length);
                if (ns > 0)
                {
                    var ascii = System.Text.Encoding.ASCII.GetString(bufSvc, 0, ns);
                    if (ascii.IndexOf("ServiceMain", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        var list = new List<string>(res.SecurityFindings ?? Array.Empty<string>());
                        list.Add("pe:servicemain"); res.SecurityFindings = list;
                    }
                }
            } catch { }

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

                // Citrix ICA (INI-like) and ReceiverConfig.cr (XML) detection
                try {
                    var headTxt = ReadHeadText(path, 8192);
                    var lower = headTxt?.ToLowerInvariant() ?? string.Empty;
                    if (declaredExt == "ica" || lower.Contains("[wfclient]") || lower.Contains("[applicationservers]"))
                    {
                        res.TextSubtype = "citrix-ica";
                    }
                    else if (declaredExt == "cr" || System.IO.Path.GetFileName(path).ToLowerInvariant().EndsWith("receiverconfig.cr"))
                    {
                        // Heuristic: XML with Receiver/Store config cues
                        if (lower.Contains("<") && (lower.Contains("receiver") || lower.Contains("workspace") || lower.Contains("store")))
                            res.TextSubtype = "citrix-receiver-config";
                    }
                } catch { }

                // Lightweight script security assessment
                var sf = SecurityHeuristics.AssessScript(path, declaredExt, Settings.DetectionReadBudgetBytes);
                if (sf.Count > 0) res.SecurityFindings = sf;
                // Generic text/log/schema cues
                var tf = SecurityHeuristics.AssessTextGeneric(path, declaredExt, Settings.DetectionReadBudgetBytes);
                if (tf.Count > 0)
                {
                    var list = new List<string>(res.SecurityFindings ?? Array.Empty<string>());
                    foreach (var x in tf) if (!list.Contains(x, StringComparer.OrdinalIgnoreCase)) list.Add(x);
                    res.SecurityFindings = list;
                }
                // Very permissive fallback for common JWT test token
                try {
                    var headTxt = ReadHeadText(path, 4096);
                    if (!string.IsNullOrEmpty(headTxt) && headTxt.IndexOf("header.payload.signature", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        var list = new List<string>(res.SecurityFindings ?? Array.Empty<string>());
                        if (!list.Contains("secret:jwt")) list.Add("secret:jwt");
                        res.SecurityFindings = list;
                    }
                } catch { }
                if (Settings.SecretsScanEnabled)
                {
                    var ss = SecurityHeuristics.CountSecrets(path, Settings.DetectionReadBudgetBytes);
                    if (ss.PrivateKeyCount > 0 || ss.JwtLikeCount > 0 || ss.KeyPatternCount > 0)
                    {
                        res.Secrets = ss;
                        // Ensure corresponding category notes are visible in neutral findings
                        var list2 = new List<string>(res.SecurityFindings ?? Array.Empty<string>());
                        if (ss.PrivateKeyCount > 0 && !list2.Contains("secret:privkey")) list2.Add("secret:privkey");
                        if (ss.JwtLikeCount > 0    && !list2.Contains("secret:jwt"))     list2.Add("secret:jwt");
                        if (ss.KeyPatternCount > 0 && !list2.Contains("secret:keypattern")) list2.Add("secret:keypattern");
                        res.SecurityFindings = list2;
                    }
                }
            }

            // Permissions/ownership snapshot (best-effort; cross-platform)
            if (options?.IncludePermissions != false) res.Security = BuildFileSecurity(path);

            // PE Authenticode (best-effort, cross-platform) for PE files
            if ((options?.IncludeAuthenticode != false) && (det.Extension is "exe" or "dll" or "sys" or "cpl")) {
                TryPopulateAuthenticode(path, res);
            }
            // PKCS#7 certificate bundle (.p7b/.spc)
            if (det.Extension is "p7b" or "spc")
            {
                TryParseP7b(path, res);
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

            // Standalone certificate parsing for .cer/.crt/.der/.pem
            if (det.Extension is "cer" or "crt" or "der" or "pem")
            {
                if (TryLoadCertificateFromFile(path, det.Extension!, out var cert))
                {
                    var ci = new CertificateInfo();
                    try { ci.Subject = cert.Subject; } catch { }
                    try { ci.Issuer = cert.Issuer; } catch { }
                    try { ci.NotBeforeUtc = cert.NotBefore.ToUniversalTime(); } catch { }
                    try { ci.NotAfterUtc = cert.NotAfter.ToUniversalTime(); } catch { }
                    try { ci.Thumbprint = cert.Thumbprint; } catch { }
                    try { ci.KeyAlgorithm = cert.PublicKey?.Oid?.FriendlyName ?? cert.PublicKey?.Oid?.Value; } catch { }
                    try { ci.SelfSigned = string.Equals(cert.Subject, cert.Issuer, StringComparison.OrdinalIgnoreCase); } catch { }
                    try {
                        using var chain = new X509Chain();
                        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
                        if (chain.Build(cert))
                        {
                            ci.ChainTrusted = true;
                            try { var last = chain.ChainElements[chain.ChainElements.Count - 1]?.Certificate; if (last != null) ci.RootSubject = last.Subject; } catch { }
                        }
                        else ci.ChainTrusted = false;
                    } catch { }
                    try { var san = cert.Extensions["2.5.29.17"]; if (san != null) ci.SanPresent = true; } catch { }
                    res.Certificate = ci;
                }
            }

            // Name + type based heuristics for high-signal artifacts (browsers, AD/registry, transcripts)
            try {
                var fname = System.IO.Path.GetFileName(path);
                var lowerName = fname?.ToLowerInvariant() ?? string.Empty;
                var list = new List<string>(res.SecurityFindings ?? Array.Empty<string>());

                // AD DS database candidate: ESE database named ntds.dit (or .dit extension)
                if ((det.Extension is "edb" || string.Equals(det.MimeType, "application/x-ese-database", StringComparison.OrdinalIgnoreCase))
                    && (string.Equals(lowerName, "ntds.dit", StringComparison.OrdinalIgnoreCase) || lowerName.EndsWith(".dit", StringComparison.Ordinal)))
                {
                    if (!list.Contains("ad:ntds-dit")) list.Add("ad:ntds-dit");
                }
                // Registry hives: SAM, SYSTEM, SECURITY (frequently exfiltrated together)
                if ((det.Extension is "hive" || string.Equals(det.MimeType, "application/x-windows-registry-hive", StringComparison.OrdinalIgnoreCase)))
                {
                    if (string.Equals(lowerName, "sam", StringComparison.OrdinalIgnoreCase) && !list.Contains("reg:sam")) list.Add("reg:sam");
                    if (string.Equals(lowerName, "system", StringComparison.OrdinalIgnoreCase) && !list.Contains("reg:system")) list.Add("reg:system");
                    if (string.Equals(lowerName, "security", StringComparison.OrdinalIgnoreCase) && !list.Contains("reg:security")) list.Add("reg:security");
                }
                // Browser credential stores (SQLite/JSON): Chrome/Edge/Firefox common filenames
                if (det.Extension is "sqlite")
                {
                    if (string.Equals(lowerName, "login data", StringComparison.Ordinal) || string.Equals(lowerName, "logindata", StringComparison.Ordinal))
                        if (!list.Contains("browser:login-data")) list.Add("browser:login-data");
                    if (string.Equals(lowerName, "web data", StringComparison.Ordinal) || string.Equals(lowerName, "webdata", StringComparison.Ordinal))
                        if (!list.Contains("browser:web-data")) list.Add("browser:web-data");
                    if (string.Equals(lowerName, "history", StringComparison.Ordinal))
                        if (!list.Contains("browser:history")) list.Add("browser:history");
                    if (string.Equals(lowerName, "key4.db", StringComparison.Ordinal))
                        if (!list.Contains("browser:key-store")) list.Add("browser:key-store");
                }
                if (det.Extension is "json" && string.Equals(lowerName, "logins.json", StringComparison.Ordinal))
                {
                    if (!list.Contains("browser:logins-json")) list.Add("browser:logins-json");
                }
                // PowerShell transcript logs (plain text)
                if (InspectHelpers.IsText(det))
                {
                    var head = ReadFirstLine(path, 256);
                    // Very common header string in transcripts
                    if (head.IndexOf("Windows PowerShell transcript start", StringComparison.OrdinalIgnoreCase) >= 0)
                        if (!list.Contains("ps:transcript")) list.Add("ps:transcript");
                }

                // Assign back if we added anything
                if (list.Count > (res.SecurityFindings?.Count ?? 0)) res.SecurityFindings = list;
            } catch { }

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

            // OLE2 Office macros (VBA) check for legacy formats (.doc/.xls/.ppt)
            if (det.Extension is "doc" or "xls" or "ppt")
            {
                try
                {
                    if (TryGetOleDirectoryNames(File.OpenRead(path), out var names))
                    {
                        bool hasVba = names.Any(nm => nm.IndexOf("VBA", StringComparison.OrdinalIgnoreCase) >= 0 || nm.IndexOf("_VBA_PROJECT_CUR", StringComparison.OrdinalIgnoreCase) >= 0 || nm.IndexOf("dir", StringComparison.OrdinalIgnoreCase) >= 0);
                        if (hasVba) { res.Flags |= ContentFlags.OleHasVbaMacros; var list = new List<string>(res.SecurityFindings ?? Array.Empty<string>()); if (!list.Contains("office:vba")) list.Add("office:vba"); res.SecurityFindings = list; }
                    }
                }
                catch { }
            }

            // Extract generic references (optional)
            if (options?.IncludeReferences != false)
            {
                res.References = BuildReferences(path, det);
                // HTML external links summary flag
                try
                {
                    var htmlUrls = res.References?.Where(r => r.Kind == ReferenceKind.Url && (r.SourceTag?.StartsWith("html:", StringComparison.OrdinalIgnoreCase) ?? false)).ToList() ?? new List<Reference>();
                    int htmlExtLinks = htmlUrls.Count;
                    int uncCount = res.References?.Count(r => r.Kind == ReferenceKind.FilePath && (r.SourceTag?.StartsWith("html:", StringComparison.OrdinalIgnoreCase) ?? false) && (r.Issues & ReferenceIssue.UncPath) != 0) ?? 0;
                    int allowed = 0;
                    if (htmlExtLinks > 0 && Settings.HtmlAllowedDomains.Length > 0)
                    {
                        foreach (var uref in htmlUrls)
                        {
                            try
                            {
                                var v = uref.Value; if (v.StartsWith("//")) v = "http:" + v;
                                if (Uri.TryCreate(v, UriKind.Absolute, out var u) && !string.IsNullOrEmpty(u.Host))
                                {
                                    var host = u.Host.ToLowerInvariant();
                                    foreach (var dom in Settings.HtmlAllowedDomains)
                                    {
                                        var d = (dom ?? string.Empty).Trim().ToLowerInvariant(); if (string.IsNullOrEmpty(d)) continue;
                                        if (host.Equals(d) || host.EndsWith("." + d)) { allowed++; break; }
                                    }
                                }
                            } catch { }
                        }
                    }
                    int disallowed = Math.Max(0, htmlExtLinks - allowed);
                    if (disallowed > 0) res.Flags |= ContentFlags.HtmlHasExternalLinks;
                    if (htmlExtLinks > 0)
                    {
                        var list = new List<string>(res.SecurityFindings ?? Array.Empty<string>());
                        void AddMarker(string s) { if (!list.Contains(s)) list.Add(s); }
                        AddMarker($"html:ext-links={htmlExtLinks}");
                        if (allowed > 0) AddMarker($"html:ext-allowed={allowed}");
                        if (disallowed > 0) AddMarker($"html:ext-disallowed={disallowed}");
                        if (uncCount > 0) AddMarker($"html:unc={uncCount}");
                        res.SecurityFindings = list;
                    }
                } catch { }
            }

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

                // DLL export quick signals: highlight COM registration exports
                try
                {
                    var extLower = System.IO.Path.GetExtension(path)?.TrimStart('.').ToLowerInvariant();
                    if (extLower is "dll" || extLower is "exe")
                    {
                        if (PeReader.TryListExportNames(path, out var expNames) && expNames != null && expNames.Count > 0)
                        {
                            var list = new List<string>(res.SecurityFindings ?? Array.Empty<string>());
                            list.Add($"pe:exports={expNames.Count}");
                            // Common COM registration entry points
                            bool reg = false; foreach (var n in expNames) { var ln = n.ToLowerInvariant(); if (ln == "dllregisterserver" || ln == "dllinstall" || ln == "dllunregisterserver") { reg = true; break; } }
                            if (reg) list.Add("pe:regsvr");
                            // Top export names (3 max)
                            try { var top = string.Join(",", expNames.Take(3)); if (!string.IsNullOrWhiteSpace(top)) list.Add($"pe:top={top}"); } catch { }
                            res.SecurityFindings = list;
                        }
                    }
                } catch { }
            }

            // Best-effort .NET TargetFramework detection for managed PE
            try
            {
                if ((res.Flags & ContentFlags.PeIsDotNet) != 0)
                {
                    var tfm = TryDetectTargetFramework(path, Settings.DetectionReadBudgetBytes);
                    if (!string.IsNullOrWhiteSpace(tfm))
                    {
                        var dict = res.VersionInfo != null ? new Dictionary<string,string>(res.VersionInfo.ToDictionary(kv => kv.Key, kv => kv.Value)) : new Dictionary<string,string>();
                        dict["TargetFramework"] = tfm!;
                        res.VersionInfo = dict;
                    }
                }
            } catch { }

            // Assessment (optional)
            if (options?.IncludeAssessment != false)
                res.Assessment = Assess(res);

        } catch { }
        return res;
    }

    // Parse OOXML .rels fragments to count external targets and categorize by allowed domains.
    private static void CountOoxmlExternalTargets(string xml, ref int allowed, ref int disallowed, ref int unc)
    {
        try
        {
            int idx = 0;
            while (idx < xml.Length)
            {
                int at = xml.IndexOf("Target=\"", idx, StringComparison.OrdinalIgnoreCase);
                if (at < 0) break; at += 8; // after Target="
                int end = xml.IndexOf('"', at);
                if (end < 0) break;
                var raw = xml.Substring(at, end - at).Trim();
                idx = end + 1;
                if (string.IsNullOrWhiteSpace(raw)) continue;
                if (raw.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || raw.StartsWith("https://", StringComparison.OrdinalIgnoreCase) || raw.StartsWith("//"))
                {
                    var host = TryGetHost(raw);
                    if (!string.IsNullOrEmpty(host))
                    {
                        if (IsAllowedDomain(host!)) allowed++; else disallowed++;
                    }
                }
                else if (raw.StartsWith("\\\\") || raw.StartsWith("file://", StringComparison.OrdinalIgnoreCase))
                {
                    unc++;
                }
            }
        } catch { }
    }

    // Overload: also captures up to 5 unique hosts encountered (order of first appearance)
    private static void CountOoxmlExternalTargets(string xml, ref int allowed, ref int disallowed, ref int unc, List<string> hosts)
    {
        try
        {
            int idx = 0;
            while (idx < xml.Length)
            {
                int at = xml.IndexOf("Target=\"", idx, StringComparison.OrdinalIgnoreCase);
                if (at < 0) break; at += 8;
                int end = xml.IndexOf('"', at);
                if (end < 0) break;
                var raw = xml.Substring(at, end - at).Trim();
                idx = end + 1;
                if (string.IsNullOrWhiteSpace(raw)) continue;
                if (raw.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || raw.StartsWith("https://", StringComparison.OrdinalIgnoreCase) || raw.StartsWith("//"))
                {
                    var host = TryGetHost(raw);
                    if (!string.IsNullOrEmpty(host))
                    {
                        if (IsAllowedDomain(host!)) allowed++; else disallowed++;
                        if (hosts.Count < 5 && !hosts.Contains(host!, StringComparer.OrdinalIgnoreCase)) hosts.Add(host!);
                    }
                }
                else if (raw.StartsWith("\\\\") || raw.StartsWith("file://", StringComparison.OrdinalIgnoreCase))
                {
                    unc++;
                }
            }
        } catch { }
    }

    private static string? TryGetHost(string url)
    {
        try
        {
            if (url.StartsWith("//")) url = "http:" + url;
            if (Uri.TryCreate(url, UriKind.Absolute, out var u)) return u.Host;
        } catch { }
        return null;
    }

    private static bool IsAllowedDomain(string host)
    {
        try
        {
            var h = (host ?? string.Empty).Trim().ToLowerInvariant(); if (string.IsNullOrEmpty(h)) return false;
            foreach (var dom in Settings.HtmlAllowedDomains)
            {
                var d = (dom ?? string.Empty).Trim().ToLowerInvariant(); if (string.IsNullOrEmpty(d)) continue;
                if (h.Equals(d) || h.EndsWith("." + d)) return true;
            }
        } catch { }
        return false;
    }

    // Counts RAR4 encrypted files by walking file headers quickly under a simple budget.
    // Returns true when parsing succeeded, with 'enc' and 'total' counts.
    private static bool TryCountRar4EncryptedFiles(string path, int maxFiles, out int enc, out int total)
    {
        enc = 0; total = 0;
        try {
            using var fs = File.OpenRead(path);
            var sig = new byte[]{ (byte)'R',(byte)'a',(byte)'r', (byte)'!', 0x1A, 0x07, 0x00 };
            var head = new byte[sig.Length];
            if (fs.Read(head, 0, head.Length) != head.Length) return false;
            for (int i=0;i<sig.Length;i++) if (head[i]!=sig[i]) return false;
            // RAR4 blocks: [HEAD_CRC(2)][HEAD_TYPE(1)][HEAD_FLAGS(2)][HEAD_SIZE(2)] ...
            var br = new BinaryReader(fs);
            int filesSeen = 0;
            while (fs.Position + 7 <= fs.Length && filesSeen < maxFiles)
            {
                ushort headCrc = br.ReadUInt16();
                byte headType = br.ReadByte();
                ushort headFlags = br.ReadUInt16();
                ushort headSize = br.ReadUInt16();
                if (headSize < 7) break; // guard
                long next = fs.Position + headSize - 7; // subtract header bytes already read
                // File header
                if (headType == 0x74) // HEAD_TYPE_FILE
                {
                    filesSeen++; total = filesSeen;
                    // In RAR v2/3/4, FILE_HEADER flags bit 0x04 means password/encrypted
                    if ((headFlags & 0x04) != 0) enc++;
                    // Skip extra fields (pack & unpack sizes already inside header; we just jump to next)
                }
                // Move to next block
                if (next < fs.Position) break;
                fs.Seek(next, SeekOrigin.Begin);
            }
            if (total == 0) total = filesSeen;
            return true;
        } catch { return false; }
    }

    /// <summary>
    /// Best-effort inner signer sampling for RAR4 archives, limited to entries stored without compression (method 0x30) and not encrypted.
    /// Walks headers and reads up to <paramref name="maxEntryBytes"/> for at most <paramref name="maxEntries"/> executable-looking entries.
    /// </summary>
    private static bool TrySampleRar4InnerSigners(string path, int maxEntries, int maxEntryBytes, out int innerExecutablesSampled, out int innerSigned, out int innerValid, out Dictionary<string,int>? publishers)
    {
        innerExecutablesSampled = 0; innerSigned = 0; innerValid = 0; publishers = null;
        try
        {
            using var fs = File.OpenRead(path);
            // Verify RAR4 signature
            var sig = new byte[]{ (byte)'R',(byte)'a',(byte)'r', (byte)'!', 0x1A, 0x07, 0x00 };
            var head = new byte[sig.Length];
            if (fs.Read(head, 0, head.Length) != head.Length) return false;
            for (int i=0;i<sig.Length;i++) if (head[i]!=sig[i]) return false;

            var br = new BinaryReader(fs);
            int sampled = 0; var pubs = new Dictionary<string,int>(StringComparer.OrdinalIgnoreCase);
            while (fs.Position + 7 <= fs.Length && sampled < maxEntries)
            {
                long hdrStart = fs.Position;
                ushort headCrc = br.ReadUInt16();
                byte headType = br.ReadByte();
                ushort headFlags = br.ReadUInt16();
                ushort headSize = br.ReadUInt16();
                if (headSize < 7) break; // guard
                long headerEnd = hdrStart + headSize;

                if (headType == 0x74) // FILE_HEADER
                {
                    // Parse fixed fields relative to after base header
                    long afterBase = fs.Position; // position right after 7-byte base header
                    // Required fields exist within header size budget; if not readable, break
                    if (afterBase + 4 + 4 + 1 + 4 + 4 + 1 + 1 + 2 + 4 > headerEnd) { fs.Seek(headerEnd, SeekOrigin.Begin); continue; }
                    uint packLow = br.ReadUInt32();
                    uint unpLow  = br.ReadUInt32();
                    br.ReadByte(); // hostOS
                    br.ReadUInt32(); // fileCRC
                    br.ReadUInt32(); // ftime
                    br.ReadByte();   // unpVer
                    byte method = br.ReadByte();
                    ushort nameSize = br.ReadUInt16();
                    br.ReadUInt32(); // attr
                    ulong packSize = packLow; ulong unpSize = unpLow;
                    if ((headFlags & 0x0100) != 0)
                    {
                        if (fs.Position + 8 > headerEnd) { fs.Seek(headerEnd, SeekOrigin.Begin); continue; }
                        uint hPack = br.ReadUInt32(); uint hUnp = br.ReadUInt32();
                        packSize |= ((ulong)hPack << 32); unpSize |= ((ulong)hUnp << 32);
                    }
                    // Read name (best-effort) to decide if it's executable by name; if can't, leave empty
                    string name = string.Empty;
                    try
                    {
                        int toRead = (int)Math.Min((long)nameSize, headerEnd - fs.Position);
                        if (toRead > 0)
                        {
                            var nb = br.ReadBytes(toRead);
                            name = Latin1String(nb);
                        }
                    } catch { }
                    // Skip any remaining header fields to reach data start
                    fs.Seek(headerEnd, SeekOrigin.Begin);

                    bool encrypted = (headFlags & 0x0004) != 0;
                    bool store = method == 0x30; // '0' => stored without compression
                    if (!encrypted && store && packSize > 0 && (long)packSize <= maxEntryBytes && sampled < maxEntries)
                    {
                        long dataStart = headerEnd; long dataEnd = Math.Min(fs.Length, dataStart + (long)packSize);
                        long save = fs.Position; fs.Seek(dataStart, SeekOrigin.Begin);
                        var cap = (int)Math.Min(maxEntryBytes, (long)packSize);
                        var tmp = System.IO.Path.GetTempFileName();
                        try
                        {
                            using (var outFs = System.IO.File.Create(tmp))
                            {
                                int left = cap; var buf = new byte[Math.Min(8192, cap)];
                                while (left > 0)
                                {
                                    int r = fs.Read(buf, 0, Math.Min(buf.Length, left)); if (r <= 0) break; outFs.Write(buf, 0, r); left -= r;
                                }
                            }
                            // Analyze extracted sample and update stats if it is an executable
                            var ia = FileInspector.Analyze(tmp);
                            sampled++;
                            // Decide if it was an executable by original name or detection
                            bool looksExec = (!string.IsNullOrEmpty(name) && IsExecutableName(name)) || (ia?.Detection?.Extension is "exe" or "dll" or "sys" or "cpl");
                            if (looksExec)
                            {
                                innerExecutablesSampled++;
                                if (ia?.Authenticode?.Present == true)
                                {
                                    innerSigned++;
                                    bool v = ia.Authenticode.IsTrustedWindowsPolicy == true || ia.Authenticode.ChainValid == true;
                                    if (v) innerValid++;
                                    var pub = ia.Authenticode.SignerSubjectCN ?? ia.Authenticode.SignerSubject ?? "<unknown>";
                                    if (publishers == null) publishers = pubs;
                                    if (publishers!.TryGetValue(pub, out var pc)) publishers[pub] = pc + 1; else publishers[pub] = 1;
                                }
                            }
                        }
                        catch { /* ignore per-entry errors */ }
                        finally
                        {
                            try { System.IO.File.Delete(tmp); } catch { }
                            // Move to end of this file's packed data to continue with the next block
                            fs.Seek(dataEnd, SeekOrigin.Begin);
                        }
                        continue;
                    }
                    else
                    {
                        // Skip packed data of this entry to reach the next block
                        fs.Seek((long)Math.Min((ulong)fs.Length, (ulong)headerEnd + packSize), SeekOrigin.Begin);
                        continue;
                    }
                }
                // Non-file header: just skip to header end
                fs.Seek(headerEnd, SeekOrigin.Begin);
            }
            if (publishers == null && pubs.Count > 0) publishers = pubs;
            return true;
        }
        catch { return false; }
    }

    private static void TryInspectZip(string path, out bool hasMacros, out string? containerSubtype, out int? entryCount, out IReadOnlyList<string>? topExtensions, out bool hasExecutables, out bool hasScripts, out bool hasNestedArchives,
        out bool hasTraversal, out bool hasSymlinks, out bool hasAbs, out bool hasInstallers, out bool hasRemoteTemplate, out bool hasDde, out bool hasExternalLinks, out int externalLinksCount,
        out bool hasEncryptedEntries, out int encryptedEntryCount, out bool isOoxmlEncrypted, out bool hasDisguisedExecutables, out List<string>? findingsOut,
        out int innerExecutablesSampled, out int innerSignedExecutables, out int innerValidSignedExecutables, out Dictionary<string,int>? innerPublisherCounts, out Dictionary<string,int>? innerPublisherValidCounts, out Dictionary<string,int>? innerPublisherSelfCounts, out List<InnerEntryPreview>? previewOut) {
        hasMacros = false; containerSubtype = null; entryCount = null; topExtensions = null; hasExecutables = false; hasScripts = false; hasNestedArchives = false; hasTraversal = false; hasSymlinks = false; hasAbs = false; hasInstallers = false; hasRemoteTemplate = false; hasDde = false; hasExternalLinks = false; externalLinksCount = 0; hasEncryptedEntries = false; encryptedEntryCount = 0; isOoxmlEncrypted = false; hasDisguisedExecutables = false; findingsOut = null;
        innerExecutablesSampled = 0; innerSignedExecutables = 0; innerValidSignedExecutables = 0; innerPublisherCounts = null; innerPublisherValidCounts = null; innerPublisherSelfCounts = null; previewOut = null;
        try {
            using var fs = File.OpenRead(path);
            using var za = new ZipArchive(fs, ZipArchiveMode.Read, leaveOpen: true);
            var exts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            int count = 0;
            hasNestedArchives = false;
            int sampled = 0; int maxSamples = 16; int headSample = 64;
            bool ooxmlRemoteTemplate = false; bool ooxmlDde = false; bool ooxmlExtLinks = false; int extLinksCount = 0;
            int ooxmlAllowed = 0, ooxmlDisallowed = 0, ooxmlUnc = 0;
            var ooxmlHosts = new List<string>(5);
            bool sawEncryptionInfo = false; bool sawEncryptedPackage = false;
            int deepScanned = 0; int deepMax = Settings.DeepContainerMaxEntries;
            int deepBytes = Settings.DeepContainerMaxEntryBytes;
            bool deep = Settings.DeepContainerScanEnabled;
            var localFindings = new List<string>(8);
            var innerPublishers = new Dictionary<string,int>(StringComparer.OrdinalIgnoreCase);
            var innerPublisherValid = new Dictionary<string,int>(StringComparer.OrdinalIgnoreCase);
            var innerPublisherSelf = new Dictionary<string,int>(StringComparer.OrdinalIgnoreCase);
            var previews = new List<InnerEntryPreview>();
            // JAR/APK/Vendored package cues
            bool hasManifestMf = false; bool hasClass = false; bool hasJarSig = false;
            bool hasAndroidManifest = false; bool hasDex = false; bool hasApkSig = false;
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

                // JAR/APK cues
                var low = name.ToLowerInvariant();
                if (low == "meta-inf/manifest.mf") hasManifestMf = true;
                if (low.StartsWith("meta-inf/") && (low.EndsWith(".rsa") || low.EndsWith(".dsa"))) { hasJarSig = true; hasApkSig = true; }
                if (low.EndsWith(".class")) hasClass = true;
                if (low == "androidmanifest.xml") hasAndroidManifest = true;
                if (low == "classes.dex") hasDex = true;

                // GPO/SYSVOL indicators within archives
                if (Settings.DeepContainerScanEnabled)
                {
                    var nlow = name.ToLowerInvariant();
                    if (nlow.EndsWith("/gpt.ini") || nlow.EndsWith("\\gpt.ini") || nlow.Contains("/policies/") || nlow.Contains("\\policies\\") || nlow.EndsWith("registry.pol", StringComparison.OrdinalIgnoreCase))
                    {
                        if (!localFindings.Contains("gpo:backup")) localFindings.Add("gpo:backup");
                    }
                    if (nlow.Contains("sysvol") && (nlow.Contains("policies") || nlow.Contains("scripts")))
                    {
                        if (!localFindings.Contains("sysvol:policy")) localFindings.Add("sysvol:policy");
                    }
                }

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
                        // Roughly count external http(s) and UNC targets in workbook relationships
                        CountOoxmlExternalTargets(rels, ref ooxmlAllowed, ref ooxmlDisallowed, ref ooxmlUnc, ooxmlHosts);
                    }
                    if (name.StartsWith("xl/externalLinks/_rels/", StringComparison.OrdinalIgnoreCase) && name.EndsWith(".rels", StringComparison.OrdinalIgnoreCase))
                    {
                        using var s4 = e.Open(); using var sr4 = new StreamReader(s4);
                        var rels2 = sr4.ReadToEnd();
                        CountOoxmlExternalTargets(rels2, ref ooxmlAllowed, ref ooxmlDisallowed, ref ooxmlUnc, ooxmlHosts);
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
                                if (previews.Count < 10)
                                    previews.Add(new InnerEntryPreview { Name = name, DetectedExtension = det2?.Extension ?? declExt });
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
                            // Inner signer sampling for executables
                            if (looksExe && e.Length > 0 && e.Length <= deepBytes)
                            {
                                try
                                {
                                    var tmp = System.IO.Path.GetTempFileName();
                                    // write full entry within deepBytes
                                    // rebuild buffer from es2: ensure full up-to-cap content
                                    using (var fsout = System.IO.File.Create(tmp))
                                    {
                                        // write what we already read
                                        fsout.Write(buf, 0, nn);
                                        if (nn < cap)
                                        {
                                            int left = cap - nn; var tmpbuf = new byte[8192]; int r2;
                                            while (left > 0 && (r2 = es2.Read(tmpbuf, 0, Math.Min(tmpbuf.Length, left))) > 0) { fsout.Write(tmpbuf, 0, r2); left -= r2; }
                                        }
                                    }
                                    var ia = FileInspector.Analyze(tmp);
                                    try { System.IO.File.Delete(tmp); } catch { }
                                    innerExecutablesSampled++;
                                    if (ia?.Authenticode?.Present == true)
                                    {
                                        innerSignedExecutables++;
                                        bool v = ia.Authenticode.IsTrustedWindowsPolicy == true || ia.Authenticode.ChainValid == true;
                                        if (v) innerValidSignedExecutables++;
                                        var pub = ia.Authenticode.SignerSubjectCN ?? ia.Authenticode.SignerSubject ?? "<unknown>";
                                        if (innerPublishers.TryGetValue(pub, out var pc)) innerPublishers[pub] = pc + 1; else innerPublishers[pub] = 1;
                                        if (v) { if (innerPublisherValid.TryGetValue(pub, out var pv)) innerPublisherValid[pub] = pv + 1; else innerPublisherValid[pub] = 1; }
                                        if (ia.Authenticode.IsSelfSigned == true) { if (innerPublisherSelf.TryGetValue(pub, out var ps)) innerPublisherSelf[pub] = ps + 1; else innerPublisherSelf[pub] = 1; }
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
            // Refine subtype based on cues collected
            if (containerSubtype == null)
            {
                if (hasManifestMf && hasClass) containerSubtype = "jar";
                if (hasAndroidManifest && hasDex) containerSubtype = "apk";
            }
            // Signed JAR/APK hints
            if (containerSubtype == "jar" && hasJarSig)
            {
                if (!localFindings.Contains("jar:signed")) localFindings.Add("jar:signed");
            }
            if (containerSubtype == "apk" && hasApkSig)
            {
                if (!localFindings.Contains("apk:signed")) localFindings.Add("apk:signed");
            }
            if (hasNestedArchives && containerSubtype == null) containerSubtype = "nested-archive";
            hasRemoteTemplate = ooxmlRemoteTemplate;
            hasDde = ooxmlDde;
            hasExternalLinks = ooxmlExtLinks;
            externalLinksCount = extLinksCount;
            // Attach OOXML external link markers
            if (ooxmlExtLinks)
            {
                if (!localFindings.Contains($"ooxml:ext-links={extLinksCount}")) localFindings.Add($"ooxml:ext-links={extLinksCount}");
                if (ooxmlAllowed > 0 && !localFindings.Contains($"ooxml:ext-allowed={ooxmlAllowed}")) localFindings.Add($"ooxml:ext-allowed={ooxmlAllowed}");
                if (ooxmlDisallowed > 0 && !localFindings.Contains($"ooxml:ext-disallowed={ooxmlDisallowed}")) localFindings.Add($"ooxml:ext-disallowed={ooxmlDisallowed}");
                if (ooxmlUnc > 0 && !localFindings.Contains($"ooxml:unc={ooxmlUnc}")) localFindings.Add($"ooxml:unc={ooxmlUnc}");
                if (ooxmlHosts.Count > 0)
                {
                    var top = ooxmlHosts.Take(3);
                    var joined = string.Join(",", top);
                    if (!localFindings.Any(x => x.StartsWith("ooxml:hosts=", StringComparison.OrdinalIgnoreCase)))
                        localFindings.Add($"ooxml:hosts={joined}");
                }
            }
            // Check encryption flags and count by scanning central directory
            int encCount = ZipEncryptedEntryCount(fs);
            if (encCount > 0) { hasEncryptedEntries = true; encryptedEntryCount = encCount; }
            // OOXML encrypted packages present these two entries at root
            isOoxmlEncrypted = sawEncryptionInfo && sawEncryptedPackage;
            findingsOut = localFindings.Count > 0 ? localFindings : null;
            if (innerExecutablesSampled > 0)
            {
                innerPublisherCounts = innerPublishers.Count > 0 ? new Dictionary<string,int>(innerPublishers) : null;
                innerPublisherValidCounts = innerPublisherValid.Count > 0 ? new Dictionary<string,int>(innerPublisherValid) : null;
                innerPublisherSelfCounts = innerPublisherSelf.Count > 0 ? new Dictionary<string,int>(innerPublisherSelf) : null;
            }
            if (previews.Count > 0) previewOut = previews;
            // Attach inner findings via the caller's FileAnalysis when available (handled by Analyze caller)
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
                        // Extra field scan for AES (0x9901)
                        if (exLen > 4 && p + 46 + fnLen + exLen <= m)
                        {
                            int exOff = p + 46 + fnLen; int exEnd = exOff + exLen;
                            int q = exOff;
                            while (q + 4 <= exEnd)
                            {
                                int headerId = ReadLe16(cdbuf, q);
                                int dataSize = ReadLe16(cdbuf, q + 2);
                                q += 4;
                                if (headerId == 0x9901) return true; // AES extra field
                                q += dataSize;
                            }
                        }
                        p += 46 + fnLen + exLen + cmLen;
                        scanned++;
                    }
                    break;
                }
            }
        } catch { }
        return false;
    }

    private static int ZipEncryptedEntryCount(Stream fs)
    {
        int count = 0;
        try {
            if (!fs.CanSeek || fs.Length < 22) return 0;
            long maxScan = Math.Min(fs.Length, 1 << 16);
            var buf = new byte[maxScan];
            fs.Seek(fs.Length - maxScan, SeekOrigin.Begin);
            int n = fs.Read(buf, 0, buf.Length);
            if (n <= 0) return 0;
            int eocdSig = 0x06054b50;
            int cdSig = 0x02014b50;
            for (int i = n - 22; i >= 0; i--)
            {
                if (ReadLe32(buf, i) == eocdSig)
                {
                    int entries = ReadLe16(buf, i + 10);
                    int cdOffset = ReadLe32(buf, i + 16);
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
                        bool encrypted = (flags & 0x1) != 0;
                        int fnLen = ReadLe16(cdbuf, p + 28);
                        int exLen = ReadLe16(cdbuf, p + 30);
                        int cmLen = ReadLe16(cdbuf, p + 32);
                        if (!encrypted && exLen > 4 && p + 46 + fnLen + exLen <= m)
                        {
                            int exOff = p + 46 + fnLen; int exEnd = exOff + exLen;
                            int q = exOff;
                            while (q + 4 <= exEnd)
                            {
                                int headerId = ReadLe16(cdbuf, q);
                                int dataSize = ReadLe16(cdbuf, q + 2);
                                q += 4;
                                if (headerId == 0x9901) { encrypted = true; break; }
                                q += dataSize;
                            }
                        }
                        if (encrypted) count++;
                        p += 46 + fnLen + exLen + cmLen;
                        scanned++;
                    }
                    break;
                }
            }
        } catch { }
        return count;
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
            if (rar4)
            {
                // Read next header: CRC(2), Type(1), Flags(2), Size(2)
                var hdr = new byte[7];
                if (fs.Read(hdr, 0, 7) != 7) return false;
                byte type = hdr[2];
                int flags = hdr[3] | (hdr[4] << 8);
                // Type 0x73 (MAIN_HEADER), bit 0x0080 = encrypted headers
                if (type == 0x73 && (flags & 0x0080) != 0) return true;
                return false;
            }
            // RAR5 quick probe: after signature, RAR5 uses a block with CRC32 (4), header size (varint), type (1), flags (2)
            bool rar5 = sig[0] == 0x52 && sig[1] == 0x61 && sig[2] == 0x72 && sig[3] == 0x21 && sig[4] == 0x1A && sig[5] == 0x07 && sig[6] == 0x01 && sig[7] == 0x00;
            if (!rar5) return false;
            var buf = new byte[16];
            if (fs.Read(buf, 0, 7) < 7) return false; // Read CRC32 (4) + at least 3 bytes of header
            // Very rough varint skip: header size is little-endian base-128; read until high bit cleared
            int idx = 4; long hdrSize = 0; int shift = 0; int guard = 0;
            while (idx < buf.Length && guard++ < 8)
            {
                byte b = buf[idx++]; hdrSize |= (long)(b & 0x7F) << shift; shift += 7; if ((b & 0x80) == 0) break;
                if (idx >= buf.Length) { var ext = new byte[8]; int rr = fs.Read(ext, 0, ext.Length); if (rr <= 0) break; buf = buf.Concat(ext).ToArray(); }
            }
            if (idx + 3 > buf.Length) { var more = new byte[8]; fs.Read(more, 0, more.Length); buf = buf.Concat(more).ToArray(); }
            byte bType = buf[idx++];
            if (idx + 2 > buf.Length) return false;
            int bFlags = buf[idx++] | (buf[idx++] << 8);
            // RAR5: bit 0x04 in flags of MAIN block indicates that headers are encrypted
            const byte RAR5_MAIN = 0x01;
            if (bType == RAR5_MAIN && (bFlags & 0x0004) != 0) return true;
            // Read next header: CRC(2), Type(1), Flags(2), Size(2)
        } catch { }
        return false;
    }

    private static bool TryDetect7zEncryptedHeaders(string path)
    {
        // Heuristic: parse Start Header to locate Next Header region, then check for kEncodedHeader (0x17)
        try {
            using var fs = File.OpenRead(path);
            if (fs.Length < 32) return false;
            var head = new byte[32];
            if (fs.Read(head, 0, head.Length) != head.Length) return false;
            // Verify 7z signature
            if (!(head[0] == 0x37 && head[1] == 0x7A && head[2] == 0xBC && head[3] == 0xAF && head[4] == 0x27 && head[5] == 0x1C)) return false;
            // Next Header offset and size (LE 64-bit)
            long nextOff = System.BitConverter.ToInt64(head, 12);
            long nextSz  = System.BitConverter.ToInt64(head, 20);
            if (nextOff < 0 || nextSz <= 0 || nextOff + nextSz > fs.Length) return false;
            fs.Seek(nextOff + 32, SeekOrigin.Begin); // Next Header is offset from after the 32-byte Start Header
            int toRead = (int)System.Math.Min(nextSz, Settings.DetectionReadBudgetBytes);
            var buf = new byte[toRead];
            int n = fs.Read(buf, 0, toRead);
            if (n <= 0) return false;
            // Search for property id 0x17 (kEncodedHeader) in the next header region
            for (int i = 0; i < n; i++) if (buf[i] == 0x17) return true;
        } catch { }
        return false;
    }

    // Best-effort: count files in 7z when Next Header is not encoded/compressed and headers are not encrypted.
    private static bool TryCount7zFilesQuick(string path, int byteBudget, out int fileCount)
    {
        fileCount = 0;
        try {
            using var fs = File.OpenRead(path);
            if (fs.Length < 32) return false;
            var head = new byte[32];
            if (fs.Read(head, 0, head.Length) != head.Length) return false;
            if (!(head[0] == 0x37 && head[1] == 0x7A && head[2] == 0xBC && head[3] == 0xAF && head[4] == 0x27 && head[5] == 0x1C)) return false;
            long nextOff = System.BitConverter.ToInt64(head, 12);
            long nextSz  = System.BitConverter.ToInt64(head, 20);
            if (nextOff < 0 || nextSz <= 0 || nextOff + nextSz > fs.Length) return false;
            fs.Seek(nextOff + 32, SeekOrigin.Begin);
            int toRead = (int)System.Math.Min(nextSz, byteBudget);
            var buf = new byte[toRead]; int n = fs.Read(buf, 0, toRead); if (n <= 0) return false;
            var span = new ReadOnlySpan<byte>(buf, 0, n);
            // If encoded header is present, bail out
            for (int i = 0; i < n; i++) if (buf[i] == 0x17) return false; // kEncodedHeader
            // Expect kHeader (0x01)
            int idx = 0; if (idx >= span.Length || span[idx++] != 0x01) return false;
            // Naive scan for kFilesInfo (0x0C) and then read next varuint as number of files
            int pos = idx; while (pos < span.Length) { if (span[pos++] == 0x0C) { idx = pos; break; } }
            if (idx >= span.Length) return false;
            if (!TryRead7zVarUInt(span, ref idx, out ulong files)) return false;
            if (files == 0 || files > 10_000_000) return false;
            fileCount = (int)files; return true;
        } catch { return false; }
    }

    private static bool TryRead7zVarUInt(ReadOnlySpan<byte> s, ref int idx, out ulong value)
    {
        value = 0; int shift = 0; int guard = 0;
        while (idx < s.Length && guard++ < 10)
        {
            byte b = s[idx++]; value |= (ulong)(b & 0x7Fu) << shift; shift += 7; if ((b & 0x80) == 0) return true;
        }
        return false;
    }

    // Best-effort: read Next Header plain buffer and scan for UTF-16LE file names that end with .exe or .dll
    private static bool TryScan7zExecutablesFromHeader(string path, int byteBudget, out List<string> exeNames, out List<string> dllNames)
    {
        exeNames = new List<string>(); dllNames = new List<string>();
        try
        {
            using var fs = File.OpenRead(path);
            if (fs.Length < 32) return false;
            var head = new byte[32]; if (fs.Read(head, 0, head.Length) != head.Length) return false;
            if (!(head[0] == 0x37 && head[1] == 0x7A && head[2] == 0xBC && head[3] == 0xAF && head[4] == 0x27 && head[5] == 0x1C)) return false;
            long nextOff = System.BitConverter.ToInt64(head, 12);
            long nextSz  = System.BitConverter.ToInt64(head, 20);
            if (nextOff < 0 || nextSz <= 0 || nextOff + nextSz > fs.Length) return false;
            fs.Seek(nextOff + 32, SeekOrigin.Begin);
            int toRead = (int)System.Math.Min(nextSz, byteBudget);
            var buf = new byte[toRead]; int n = fs.Read(buf, 0, toRead); if (n <= 0) return false;
            // If encoded header present, bail (we don't parse it)
            for (int i = 0; i < n; i++) if (buf[i] == 0x17) return false;
            // Scan for UTF-16LE strings
            int iPos = 0; int cap = Math.Min(n, toRead);
            while (iPos + 2 < cap && (exeNames.Count + dllNames.Count) < 12)
            {
                // Attempt to read a UTF-16LE run until NUL
                int start = iPos; int lenBytes = 0; bool hasZero = false;
                for (int p = iPos; p + 1 < cap; p += 2)
                {
                    ushort ch = (ushort)(buf[p] | (buf[p+1] << 8));
                    if (ch == 0) { hasZero = true; break; }
                    // keep consuming printable-ish chars; break if too long
                    lenBytes += 2; if (lenBytes > 512) break;
                }
                if (hasZero && lenBytes >= 6)
                {
                    try
                    {
                        var s = System.Text.Encoding.Unicode.GetString(buf, start, lenBytes);
                        if (!string.IsNullOrWhiteSpace(s) && s.IndexOf('.') >= 0)
                        {
                            var name = s.Trim('\0').Trim();
                            var lower = name.ToLowerInvariant();
                            if (lower.EndsWith(".exe")) { if (!exeNames.Contains(name)) exeNames.Add(name); }
                            else if (lower.EndsWith(".dll")) { if (!dllNames.Contains(name)) dllNames.Add(name); }
                        }
                    } catch { }
                    iPos += lenBytes + 2; // skip NUL
                }
                else
                {
                    iPos += 2;
                }
            }
            return (exeNames.Count + dllNames.Count) > 0;
        } catch { return false; }
    }

    private static void TryInspectTar(string path, out int? entryCount, out IReadOnlyList<string>? topExtensions, out bool hasExecutables, out bool hasScripts, out bool hasNestedArchives, out List<InnerEntryPreview>? previews) {
        entryCount = null; topExtensions = null; hasExecutables = false; hasScripts = false; hasNestedArchives = false; previews = null;
        var localPreviews = new List<InnerEntryPreview>();
        int innerExecutablesSampled = 0, innerSignedExecutables = 0, innerValidSignedExecutables = 0;
        var innerPublishers = new Dictionary<string,int>(StringComparer.OrdinalIgnoreCase);
        int deepScanned = 0; int deepMax = Settings.DeepContainerMaxEntries; int deepBytes = Settings.DeepContainerMaxEntryBytes; bool deep = Settings.DeepContainerScanEnabled;
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
                    // Deep sampling for small executables/scripts and nested-archive head peeks
                    if (size > 0)
                    {
                        long pad = ((size + 511) / 512) * 512;
                        // 1) Quick nested-archive peek (up to 64 bytes) without moving beyond current entry
                        if (!hasNestedArchives && size <= 128)
                        {
                            int sample = (int)Math.Min(64, size);
                            var head = new byte[sample];
                            int nhead = fs.Read(head, 0, head.Length);
                            if (nhead > 0)
                            {
                                var span = new ReadOnlySpan<byte>(head, 0, nhead);
                                var det = Detect(span, null);
                                if (det != null)
                                {
                                    var de = det.Extension?.ToLowerInvariant();
                                    if (de is "zip" or "7z" or "rar" or "tar" or "gz" or "bz2" or "xz" or "zst" or "iso" or "udf")
                                        hasNestedArchives = true;
                                    if (IsExecutableName(name) && localPreviews.Count < 10)
                                        localPreviews.Add(new InnerEntryPreview { Name = name, DetectedExtension = de ?? ext });
                                }
                            }
                            long toSkipRem = pad - nhead;
                            if (toSkipRem > 0) fs.Seek(toSkipRem, SeekOrigin.Current);
                            continue;
                        }

                        // 2) Deep signers sampling for executable entries within budget
                        if (deep && IsExecutableName(name) && size <= deepBytes && deepScanned < deepMax)
                        {
                            try
                            {
                                int cap = (int)Math.Min(size, deepBytes);
                                var tmp = System.IO.Path.GetTempFileName();
                                using (var outFs = System.IO.File.Create(tmp))
                                {
                                    int left = cap;
                                    var buf = new byte[Math.Min(8192, cap)];
                                    while (left > 0)
                                    {
                                        int r = fs.Read(buf, 0, Math.Min(buf.Length, left));
                                        if (r <= 0) break;
                                        outFs.Write(buf, 0, r);
                                        left -= r;
                                    }
                                }
                                // Skip any remaining bytes of this entry to the padded boundary
                                long consumed = Math.Min(size, deepBytes);
                                long toSkipRem = pad - consumed;
                                if (toSkipRem > 0) fs.Seek(toSkipRem, SeekOrigin.Current);

                                var ia = FileInspector.Analyze(tmp);
                                try { System.IO.File.Delete(tmp); } catch { }
                                deepScanned++;
                                innerExecutablesSampled++;
                                if (ia?.Authenticode?.Present == true)
                                {
                                    innerSignedExecutables++;
                                    bool v = ia.Authenticode.IsTrustedWindowsPolicy == true || ia.Authenticode.ChainValid == true;
                                    if (v) innerValidSignedExecutables++;
                                    var pub = ia.Authenticode.SignerSubjectCN ?? ia.Authenticode.SignerSubject ?? "<unknown>";
                                    if (innerPublishers.TryGetValue(pub, out var pc)) innerPublishers[pub] = pc + 1; else innerPublishers[pub] = 1;
                                }
                                continue;
                            }
                            catch
                            {
                                // On error, seek to next padded header position to keep parser stable
                                long toSkipRem = pad;
                                if (toSkipRem > 0) fs.Seek(toSkipRem, SeekOrigin.Current);
                                continue;
                            }
                        }
                        // 3) Not sampled – skip entire entry payload to next header
                        fs.Seek(pad, SeekOrigin.Current);
                        continue;
                    }
                }
                long toSkip = ((size + 511) / 512) * 512;
                if (toSkip > 0) fs.Seek(toSkip, SeekOrigin.Current);
            }
            entryCount = count;
            topExtensions = exts.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key).Take(5).Select(kv => kv.Key).ToArray();
            if (localPreviews.Count > 0) previews = localPreviews;
            // Attach inner signer stats (if used) back to FileAnalysis via the caller
            if (innerExecutablesSampled > 0)
            {
                _lastContainerInnerSample = new(innerExecutablesSampled, innerSignedExecutables, innerValidSignedExecutables, innerPublishers);
            }
            // TAR is not a JAR/APK container; subtype/signing hints handled in ZIP logic.
        } catch { }
    }

    private static bool TryLoadCertificateFromFile(string path, string ext, out X509Certificate2 cert)
    {
        cert = null!;
        try
        {
#if NET5_0_OR_GREATER || NET8_0_OR_GREATER
            if (string.Equals(ext, "pem", StringComparison.OrdinalIgnoreCase))
            {
                cert = X509Certificate2.CreateFromPemFile(path);
                return cert != null;
            }
#endif
            // DER/CRT/CER or fallback for PEM (manual decode)
            if (string.Equals(ext, "pem", StringComparison.OrdinalIgnoreCase))
            {
                var text = System.IO.File.ReadAllText(path);
                const string begin = "-----BEGIN CERTIFICATE-----";
                const string end = "-----END CERTIFICATE-----";
                int s = text.IndexOf(begin, StringComparison.OrdinalIgnoreCase);
                int e = text.IndexOf(end, StringComparison.OrdinalIgnoreCase);
                if (s >= 0 && e > s)
                {
                    var b64 = text.Substring(s + begin.Length, e - (s + begin.Length)).Replace("\r", string.Empty).Replace("\n", string.Empty).Trim();
                    var der = System.Convert.FromBase64String(b64);
                    cert = new X509Certificate2(der);
                    return true;
                }
                return false;
            }
            cert = new X509Certificate2(path);
            return cert != null;
        }
        catch { return false; }
    }

    private static string GetExtension(string name) {
        var i = name.LastIndexOf('.');
        if (i < 0) return string.Empty;
        return name.Substring(i + 1).ToLowerInvariant();
    }

    private static string Latin1String(byte[] bytes)
    {
        try
        {
#if NET5_0_OR_GREATER || NET8_0_OR_GREATER
            return System.Text.Encoding.Latin1.GetString(bytes);
#else
            return System.Text.Encoding.GetEncoding(28591).GetString(bytes); // ISO-8859-1 for .NET Framework / netstandard
#endif
        }
        catch { return System.Text.Encoding.ASCII.GetString(bytes); }
    }

    private static bool IsExecutableName(string name) {
        var lower = name.ToLowerInvariant();
        return lower.EndsWith(".exe") || lower.EndsWith(".dll") || lower.EndsWith(".scr") || lower.EndsWith(".com") || lower.EndsWith(".msi") || lower.EndsWith(".msix") || lower.EndsWith(".appx") || lower.EndsWith(".msixbundle");
    }

    private static bool IsScriptName(string name) {
        var lower = name.ToLowerInvariant();
        return lower.EndsWith(".ps1") || lower.EndsWith(".psm1") || lower.EndsWith(".psd1") ||
               lower.EndsWith(".bat") || lower.EndsWith(".cmd") ||
               lower.EndsWith(".sh") || lower.EndsWith(".bash") || lower.EndsWith(".zsh") || lower.EndsWith(".ksh") ||
               lower.EndsWith(".vbs") || lower.EndsWith(".js") || lower.EndsWith(".mjs") ||
               lower.EndsWith(".py") || lower.EndsWith(".rb");
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
