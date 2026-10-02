using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace FileInspectorX;

/// <summary>
/// Analysis routines implemented as part of the <see cref="FileInspector"/> facade.
/// </summary>
public static partial class FileInspector {
    // thresholds configured via Settings

    /// <summary>
    /// Runs a best-effort, dependency-free analysis of the file at <paramref name="path"/>, combining content detection,
    /// container hints, version data and lightweight risk signals into a single result.
    /// </summary>
    public static FileAnalysis Analyze(string path, DetectionOptions? options = null)
        => AnalyzeCore(InspectionInput.FromPath(path), options);

    private static FileAnalysis AnalyzeCore(InspectionInput input, DetectionOptions? options) {
        var path = input.Name;
        using var operation = InspectionOperation.Begin(options);
        options = operation.Options;
        Breadcrumbs.Write("ANALYZE_BEGIN", path: path);
        var includeInstaller = input.HasPath && ShouldIncludeInstaller(options);
        options ??= new DetectionOptions();
        ValidateLearnedClassificationMode(options);
        ContentTypeDetectionResult? det;
        try { using var timing = operation.Measure(InspectionStage.Detection); det = DetectInput(input, options); }
        catch (Exception ex) when (ex is not OutOfMemoryException and not LearnedClassificationException and not ArgumentOutOfRangeException and not OperationCanceledException)
        {
            return InputFailureAnalysis(options, hasFileSystemSource: input.HasPath);
        }
        var learnedApplied = det?.LearnedClassification != null;
        if (learnedApplied && det != null)
            PrepareDeterministicDetectionForAnalysis(det);
        var res = new FileAnalysis {
            SettingsSnapshot = options.Settings,
            HasFileSystemSource = input.HasPath,
            SourceFileName = input.Name,
            Detection = det,
            Kind = KindClassifier.Classify(det),
            Flags = ContentFlags.None,
            GuessedExtension = det?.GuessedExtension
        };
        bool msiPropsDone = false;


        try {
            if (det is null)
            {
                RecordUnavailablePathStages(res, options);
                if (options.IncludeAssessment) { using var timing = operation.Measure(InspectionStage.Assessment); res.Assessment = Assess(res); res.AssessmentProfiles = AssessMulti(res.Assessment); }
                return CompleteAnalysis(res, options);
            }
            string? headTextCached = null;
            int headTextCap = 0;
            string ReadHeadTextCached(int cap)
            {
                if (cap <= 0) return string.Empty;
                if (headTextCached == null || headTextCap < cap)
                {
                    headTextCached = ReadHeadText(input, cap);
                    headTextCap = cap;
                }
                if (headTextCached == null) return string.Empty;
                if (headTextCached.Length > cap) return headTextCached.Substring(0, cap);
                return headTextCached;
            }

            InspectionOperation.CheckCancellation();
            using (operation.Measure(InspectionStage.Container))
                AnalyzeContainers(input, options, det, res, includeInstaller);
            InspectionOperation.CheckCancellation();

            // MSI metadata enrichment (Windows): product version via msi.dll
            if (includeInstaller && det.Extension == "msi")
            {
                try {
                    Breadcrumbs.Write("MSI_META_BEGIN", path: path);
                    var msiVer = FileInspector.TryGetMsiVersion(path);
                    if (!string.IsNullOrWhiteSpace(msiVer))
                    {
                        var dict = res.VersionInfo != null ? new Dictionary<string,string>(res.VersionInfo.ToDictionary(kv => kv.Key, kv => kv.Value)) : new Dictionary<string,string>();
                        dict["ProductVersion"] = msiVer!;
                        res.VersionInfo = dict;
                    }
                } catch (Exception ex) {
                    Breadcrumbs.Write("MSI_META_ERROR", message: ex.GetType().Name+":"+ex.Message, path: path);
                }
            }
            // If the file name declares .msi, promote detection to MSI even if the magic stayed at OLE2.
            // This avoids mislabeling MSI packages as generic OLE2 or Office when installer enrichment is disabled.
            try
            {
                var declaredExtM = System.IO.Path.GetExtension(path)?.TrimStart('.').ToLowerInvariant();
                if (string.Equals(declaredExtM, "msi", StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(det.Extension, "ole2", StringComparison.OrdinalIgnoreCase))
                {
                    if (!string.Equals(det.Extension, "msi", StringComparison.OrdinalIgnoreCase))
                    {
                        det.Extension = "msi"; det.MimeType = "application/x-msi"; det.Confidence = string.IsNullOrEmpty(det.Confidence) ? "High" : det.Confidence;
                        det.Reason = string.IsNullOrEmpty(det.Reason) ? "declared:msi" : det.Reason + ";declared:msi";
                    }
                    // MSI property enrichment is optional and may be disabled for stability; only attempt when enabled
                    if (includeInstaller && !msiPropsDone) { TryPopulateMsiProperties(path, res); msiPropsDone = true; }
                }
            } catch (Exception ex) { Breadcrumbs.Write("MSI_PROMOTE_ERROR", message: ex.GetType().Name+":"+ex.Message, path: path); }
            // If we discovered MSI installer metadata later but detection stayed at generic OLE2, promote it to MSI
            try
            {
                if (includeInstaller && res.Installer?.Kind == InstallerKind.Msi && det != null && string.Equals(det.Extension, "ole2", StringComparison.OrdinalIgnoreCase))
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
                using var fsSvc = input.OpenRead();
                int capSvc = (int)Math.Min(256 * 1024, fsSvc.Length);
                var bufSvc = new byte[capSvc]; int ns = ReadAvailable(fsSvc, bufSvc, 0, bufSvc.Length);
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

            // Shebang/script and text subtypes for textlike files (treat PEM/PGP ASCII‑armored as text-like too)
            bool IsTextLike(ContentTypeDetectionResult? d)
            {
                if (InspectHelpers.IsText(d)) return true;
                var e = (d?.Extension ?? string.Empty).ToLowerInvariant();
                var m = (d?.MimeType ?? string.Empty).ToLowerInvariant();
                if (e is "pem" or "key" or "csr" or "crt" or "cer" or "asc" or "pgp" or "gpg") return true;
                if (m.StartsWith("application/x-pem") || m.StartsWith("application/pkix") || m.StartsWith("application/pkcs") || m.StartsWith("application/pgp")) return true;
                return false;
            }
            if (IsTextLike(det)) {
                var first = ReadFirstLine(input, 256);
                if (first.StartsWith("#!")) {
                    res.Flags |= ContentFlags.IsScript;
                    res.ScriptLanguage = MapShebang(first);
                }
                // JS minified heuristic if file extension is .js
                var declaredExt = System.IO.Path.GetExtension(path)?.TrimStart('.').ToLowerInvariant();
                var detectedExt = (det?.Extension ?? string.Empty).Trim().TrimStart('.').ToLowerInvariant();
                string? mappedScript = MapScriptLanguageFromExtension(detectedExt) ??
                                       MapScriptLanguageFromExtension(declaredExt);
                if (!string.IsNullOrEmpty(mappedScript))
                {
                    if (string.IsNullOrEmpty(res.ScriptLanguage)) res.ScriptLanguage = mappedScript;
                    res.Flags |= ContentFlags.IsScript;
                    if (string.IsNullOrEmpty(res.TextSubtype)) res.TextSubtype = mappedScript;
                    if (DangerousExtensions.IsDangerous(detectedExt) || DangerousExtensions.IsDangerous(declaredExt))
                        res.Flags |= ContentFlags.ScriptsPotentiallyDangerous;
                }
                if (declaredExt == "js" || detectedExt == "js") {
                    var jsHead = ReadHeadTextCached(Math.Min(OperationSettings.DetectionReadBudgetBytes, 512 * 1024));
                    if (LooksMinifiedJs(input, OperationSettings.DetectionReadBudgetBytes,
                        OperationSettings.JsMinifiedMinLength,
                        OperationSettings.JsMinifiedAvgLineThreshold,
                        OperationSettings.JsMinifiedDensityThreshold,
                        jsHead)) {
                        res.Flags |= ContentFlags.JsLooksMinified;
                    }
                }
                // PowerShell classification for plain text files (avoid false positives on changelogs)
                try {
                    var headTxt = ReadHeadTextCached(Math.Min(OperationSettings.DetectionReadBudgetBytes, 256*1024));
                    var psClass = SecurityHeuristics.ClassifyPowerShellFromText(headTxt);
                    if (psClass.level == SecurityHeuristics.PsClassLevel.Strong)
                    {
                        res.Flags |= ContentFlags.IsScript | ContentFlags.ScriptsPotentiallyDangerous;
                        res.ScriptLanguage = "powershell";
                        // Make subtype visible for non-ps1 files
                        if (string.IsNullOrEmpty(res.TextSubtype)) res.TextSubtype = "powershell";
                        // Ensure a neutral finding to explain classification
                        var list = new List<string>(res.SecurityFindings ?? Array.Empty<string>());
                        if (!list.Contains("ps:structure")) list.Add("ps:structure");
                        res.SecurityFindings = list;
                        // Promote detection to ps1 when previous text-like detection was ambiguous (e.g., yml/txt/json/xml/conf/md)
                        if (res.Detection != null)
                        {
                            var de = (res.Detection.Extension ?? string.Empty).ToLowerInvariant();
                            if (de is "yml" or "yaml" or "txt" or "log" or "json" or "xml" or "conf" or "cfg" or "md")
                            {
                                res.Detection.Extension = "ps1";
                                res.Detection.MimeType = "text/x-powershell";
                                res.Detection.Confidence = string.IsNullOrEmpty(res.Detection.Confidence) ? "Medium" : res.Detection.Confidence;
                                res.Detection.Reason = string.IsNullOrEmpty(res.Detection.Reason) ? "ps1:structure" : res.Detection.Reason + ";ps1:structure";
                            }
                        }
                    }
                    else if (psClass.level == SecurityHeuristics.PsClassLevel.Weak)
                    {
                        // Cues only; do not reclassify subtype
                        var list = new List<string>(res.SecurityFindings ?? Array.Empty<string>());
                        if (!list.Contains("ps:cues")) list.Add("ps:cues");
                        res.SecurityFindings = list;
                    }
                    // Text log detection
                    var log = SecurityHeuristics.ClassifyLogFromText(headTxt);
                    bool activeScript = psClass.level != SecurityHeuristics.PsClassLevel.None ||
                        DangerousExtensions.IsDangerous(res.Detection?.Extension) ||
                        DangerousExtensions.IsDangerous(declaredExt);
                    if (log.isLog && !activeScript)
                    {
                        res.TextSubtype = "log";
                        var list = new List<string>(res.SecurityFindings ?? Array.Empty<string>());
                        if (!list.Contains("text:log")) list.Add("text:log");
                        if (log.info+log.warn+log.error > 0) list.Add($"log:levels={log.info}/{log.warn}/{log.error}");
                        res.SecurityFindings = list;
                    }
                } catch { }

                // Potentially dangerous scripts by declared type
                if (MapScriptLanguageFromExtension(declaredExt) != null && DangerousExtensions.IsDangerous(declaredExt)) {
                    res.Flags |= ContentFlags.ScriptsPotentiallyDangerous;
                }
                // Set TextSubtype for common text families
                if (string.IsNullOrEmpty(res.TextSubtype))
                {
                    var mappedDecl = MapTextSubtypeFromExtension(declaredExt);
                    if (!string.IsNullOrEmpty(mappedDecl)) res.TextSubtype = mappedDecl;
                }

                // Fallback to detected extension when no declared type is available
                if (string.IsNullOrEmpty(res.TextSubtype))
                {
                    var mappedDet = MapTextSubtypeFromExtension(detectedExt);
                    if (!string.IsNullOrEmpty(mappedDet)) res.TextSubtype = mappedDet;
                }

                // Backfill TextSubtype from ScriptLanguage if needed
                if (string.IsNullOrEmpty(res.TextSubtype) && IsScriptTextSubtype(res.ScriptLanguage))
                {
                    res.TextSubtype = res.ScriptLanguage;
                }

                // Ensure ScriptLanguage is filled when TextSubtype implies a script
                if (string.IsNullOrEmpty(res.ScriptLanguage) && !string.IsNullOrEmpty(res.TextSubtype))
                {
                    var scriptSubtype = res.TextSubtype;
                    if (IsScriptTextSubtype(scriptSubtype))
                    {
                        res.ScriptLanguage = scriptSubtype;
                        res.Flags |= ContentFlags.IsScript;
                        if (scriptSubtype is "powershell" or "javascript" or "vbscript" or "shell" or "batch")
                            res.Flags |= ContentFlags.ScriptsPotentiallyDangerous;
                    }
                }

                // Citrix ICA (INI-like) and ReceiverConfig.cr (XML) detection
                try {
                    var headTxt = ReadHeadTextCached(8192);
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

                int heuristicsCap = Math.Max(8 * 1024, Math.Min(OperationSettings.DetectionReadBudgetBytes, 512 * 1024));
                var heuristicsText = ReadHeadTextCached(heuristicsCap);

                // Lightweight script security assessment
                var sf = SecurityHeuristics.AssessScriptFromText(heuristicsText, declaredExt, includeSecrets: false);
                if (sf.Count > 0) res.SecurityFindings = sf;
                var sfEvidence = SecurityHeuristics.AssessScriptEvidenceFromText(heuristicsText, declaredExt);
                sfEvidence = sfEvidence
                    .Where(detail => !SecurityHeuristics.IsDuplicateCredentialDumpHint(detail.Code, sf))
                    .ToList();
                if (sfEvidence.Count > 0)
                {
                    res.SecurityFindingEvidence = sfEvidence;
                    var list = new List<string>(res.SecurityFindings ?? Array.Empty<string>());
                    foreach (var detail in sfEvidence)
                    {
                        if (!string.IsNullOrWhiteSpace(detail.Code) &&
                            !list.Contains(detail.Code, StringComparer.OrdinalIgnoreCase))
                        {
                            list.Add(detail.Code);
                        }
                    }
                    res.SecurityFindings = list;
                }
                // Cmdlets: best-effort extraction for presentation (PowerShell only)
                if (string.Equals(res.ScriptLanguage, "powershell", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(res.TextSubtype, "powershell", StringComparison.OrdinalIgnoreCase))
                {
                    var cmdlets = SecurityHeuristics.GetCmdletsFromText(heuristicsText);
                    if (cmdlets != null && cmdlets.Count > 0) res.ScriptCmdlets = cmdlets;
                }
                // Generic text/log/schema cues
                var tf = SecurityHeuristics.AssessTextGenericFromText(heuristicsText, declaredExt, includeSecrets: false);
                if (tf.Count > 0)
                {
                    var list = new List<string>(res.SecurityFindings ?? Array.Empty<string>());
                    foreach (var x in tf) if (!list.Contains(x, StringComparer.OrdinalIgnoreCase)) list.Add(x);
                    res.SecurityFindings = list;
                }
                if (OperationSettings.SecretsScanEnabled)
                {
                    var ss = SecurityHeuristics.CountSecretsFromText(heuristicsText);
                    if (ss.PrivateKeyCount > 0 || ss.JwtLikeCount > 0 || ss.KeyPatternCount > 0 || ss.TokenFamilyCount > 0)
                    {
                        res.Secrets = ss;
                        // Ensure corresponding category notes are visible in neutral findings
                        var list2 = new List<string>(res.SecurityFindings ?? Array.Empty<string>());
                        foreach (var code in SecurityHeuristics.GetSecretFindingCodes(ss))
                        {
                            if (!list2.Contains(code, StringComparer.OrdinalIgnoreCase))
                                list2.Add(code);
                        }
                        res.SecurityFindings = list2;
                    }
                }
            }

            // Permissions/ownership snapshot (best-effort; cross-platform)
            InspectionOperation.CheckCancellation();
            if (input.HasPath && options?.IncludePermissions != false) res.Security = BuildFileSecurity(input.Path!);

            // PE Authenticode (best-effort, cross-platform) for PE files
            InspectionOperation.CheckCancellation();
            if ((options?.IncludeAuthenticode != false) && (det?.Extension is "exe" or "dll" or "sys" or "cpl")) {
                TryPopulateAuthenticode(input, res);
            }
            // PKCS#7 certificate/signature payload (.p7b/.spc/.p7s)
            if (det?.Extension is "p7b" or "spc" or "p7s")
            {
                TryParseP7b(input, res);
            }
            // MSI package properties (Windows only)
            if (includeInstaller && (det?.Extension?.Equals("msi", StringComparison.OrdinalIgnoreCase) ?? false))
            {
                if (!msiPropsDone) { TryPopulateMsiProperties(path, res); msiPropsDone = true; }
            }
            // On Windows, attempt WinVerifyTrust for PEs and package formats (policy validation, including catalog support).
#if NET8_0_OR_GREATER || NET472
            var declaredExt2 = System.IO.Path.GetExtension(path)?.TrimStart('.').ToLowerInvariant();
            var detectedExt2 = det?.Extension?.Trim().ToLowerInvariant();
            bool peOrExecutableFamily =
                detectedExt2 is "exe" or "dll" or "sys" or "cpl" or "ocx" or "scr" or "com" or "pif" ||
                declaredExt2 is "exe" or "dll" or "sys" or "cpl" or "ocx" or "scr" or "com" or "pif";
            bool packageFamily =
                detectedExt2 is "msi" or "msp" or "msix" or "appx" ||
                declaredExt2 is "msi" or "msp" or "msix" or "appx";

            if ((options?.IncludeAuthenticode != false) &&
                input.HasPath && OperationSettings.VerifyAuthenticodeWithWinTrust &&
                RuntimeInformation.IsOSPlatform(OSPlatform.Windows) &&
                (peOrExecutableFamily || packageFamily))
            {
                if (res.Authenticode == null) res.Authenticode = new AuthenticodeInfo();
                TryVerifyAuthenticodeWinTrust(path, res);
            }
#endif

            // Standalone certificate parsing for .cer/.crt/.der/.pem
            var detExtStandalone = det?.Extension?.Trim().ToLowerInvariant();
            var declaredExtStandalone = System.IO.Path.GetExtension(path)?.TrimStart('.').ToLowerInvariant();
            var certificateExt =
                detExtStandalone is "cer" or "crt" or "der" or "pem" ? detExtStandalone :
                declaredExtStandalone is "cer" or "crt" or "der" or "pem" ? declaredExtStandalone :
                null;
            if (certificateExt != null)
            {
                if (TryLoadCertificateFromFile(input, certificateExt, out var cert))
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
                if (((det!.Extension is "edb") || string.Equals(det.MimeType, "application/x-ese-database", StringComparison.OrdinalIgnoreCase))
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
                    var head = ReadFirstLine(input, 256);
                    // Very common header string in transcripts
                    if (head.IndexOf("Windows PowerShell transcript start", StringComparison.OrdinalIgnoreCase) >= 0)
                        if (!list.Contains("ps:transcript")) list.Add("ps:transcript");
                }

                // Assign back if we added anything
                if (list.Count > (res.SecurityFindings?.Count ?? 0)) res.SecurityFindings = list;
            } catch { }

            TryPopulateTextMetrics(res, det, input, ReadHeadTextCached);

            // PDF heuristics
            if (det != null && det.Extension == "pdf") {
                var txt = ReadHeadTextCached(1 << 20); // cap 1MB
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
            if (det != null && det.Extension is "doc" or "xls" or "ppt")
            {
                try
                {
                    if (TryGetOleDirectoryNames(input.OpenRead(), out var names))
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
                InspectionOperation.CheckCancellation();
                res.References = MergeReferences(BuildReferences(input, det), res.References);
                // HTML external links summary flag
                try
                {
                    var htmlUrls = res.References?.Where(r => r.Kind == ReferenceKind.Url && (r.SourceTag?.StartsWith("html:", StringComparison.OrdinalIgnoreCase) ?? false)).ToList() ?? new List<Reference>();
                    int htmlExtLinks = htmlUrls.Count;
                    int uncCount = res.References?.Count(r => r.Kind == ReferenceKind.FilePath && (r.SourceTag?.StartsWith("html:", StringComparison.OrdinalIgnoreCase) ?? false) && (r.Issues & ReferenceIssue.UncPath) != 0) ?? 0;
                    int allowed = 0;
                    if (htmlExtLinks > 0 && OperationSettings.HtmlAllowedDomains.Count > 0)
                    {
                        foreach (var uref in htmlUrls)
                        {
                            try
                            {
                                var v = uref.Value; if (v.StartsWith("//")) v = "http:" + v;
                                if (Uri.TryCreate(v, UriKind.Absolute, out var u) && !string.IsNullOrEmpty(u.Host))
                                {
                                    var host = u.Host.ToLowerInvariant();
                                    if (SecurityHeuristics.IsHostAllowedByDomains(host, OperationSettings.HtmlAllowedDomains)) allowed++;
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

                    // Embedded data: URI summaries from references
                    if (res.References != null)
                    {
                        var list = new List<string>(res.SecurityFindings ?? Array.Empty<string>());
                        foreach (var r in res.References.Where(r => string.Equals(r.SourceTag, "summary", StringComparison.OrdinalIgnoreCase)))
                        {
                            var v = r.Value ?? string.Empty;
                            if (v.StartsWith("html:data-uri=", StringComparison.OrdinalIgnoreCase) ||
                                v.StartsWith("html:data-b64=", StringComparison.OrdinalIgnoreCase) ||
                                v.StartsWith("html:data-exts=", StringComparison.OrdinalIgnoreCase) ||
                                v.StartsWith("script:data-uri=", StringComparison.OrdinalIgnoreCase) ||
                                v.StartsWith("script:data-b64=", StringComparison.OrdinalIgnoreCase) ||
                                v.StartsWith("script:data-exts=", StringComparison.OrdinalIgnoreCase))
                            {
                                if (!list.Contains(v)) list.Add(v);
                            }
                        }
                        if (list.Count > (res.SecurityFindings?.Count ?? 0)) res.SecurityFindings = list;
                    }
                } catch { }
            }

            // Windows shell properties (Explorer Details)
            if (input.HasPath && options?.IncludeShellProperties != false)
            {
                InspectionOperation.CheckCancellation();
                res.ShellProperties = ReadShellProperties(path, new ShellPropertiesOptions { IncludeEmpty = false });
            }

            // File name/path checks (always cheap)
            res.NameIssues = string.IsNullOrEmpty(path) ? default : AnalyzeName(path, det);

            AnalyzePe(input, res);

            if (options!.LearnedClassificationMode != LearnedClassificationMode.Off)
            {
                if (det != null)
                    det.GuessedExtension ??= res.GuessedExtension;
                det = learnedApplied && det != null
                    ? ReconcileLearnedClassificationAfterAnalysis(det)
                    : det;
                res.Detection = det;
                res.Kind = ClassifyKindWithLearnedText(det);
                res.GuessedExtension ??= det?.GuessedExtension;
            }
            if (det != null)
                RefreshDerivedAnalysisAfterLearnedPromotion(res, input, det);

            PopulateDetectionSummary(res);
            RecordUnavailablePathStages(res, options);

            // Assessment (optional)
            InspectionOperation.CheckCancellation();
            if (options?.IncludeAssessment != false)
            {
                using var timing = operation.Measure(InspectionStage.Assessment);
                res.Assessment = Assess(res);
                res.AssessmentProfiles = AssessMulti(res.Assessment);
            }

        }
        catch (OutOfMemoryException) { throw; }
        catch (LearnedClassificationException) { throw; }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            res.AnalysisComplete = false;
            res.AnalysisIssues = MergeAnalysisIssues(res.AnalysisIssues, new[] { "analysis:unhandled-error" });
            Breadcrumbs.Write("ANALYZE_ERROR", message: ex.GetType().Name, path: path);
        }
        finally
        {
            Breadcrumbs.Write("ANALYZE_END", path: path);
        }
        return CompleteAnalysis(res, operation.Options);
    }

    /// <summary>
    /// Resolves installer enrichment from the per-call option when supplied and otherwise
    /// preserves the process-wide compatibility setting.
    /// </summary>
    internal static bool ShouldIncludeInstaller(DetectionOptions? options)
        => options?.IncludeInstaller ?? OperationSettings.IncludeInstaller;

    private static string GetExtension(string name) {
        var i = name.LastIndexOf('.');
        if (i < 0) return string.Empty;
        return name.Substring(i + 1).ToLowerInvariant();
    }

    private static string Latin1String(byte[] bytes)
    {
        try
        {
#if NET5_0_OR_GREATER
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

    private static bool IsScriptName(string name)
        => IsScriptLikeExtension(Path.GetExtension(name));

    private static bool IsInstallerName(string name)
    {
        var l = name.ToLowerInvariant();
        return l.EndsWith(".msi") || l.EndsWith(".msix") || l.EndsWith(".appx") || l.EndsWith(".msixbundle") || l.EndsWith(".msu") || l.EndsWith("setup.exe") || l.EndsWith("install.exe");
    }

}
