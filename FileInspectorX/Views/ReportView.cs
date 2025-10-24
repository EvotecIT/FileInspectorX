namespace FileInspectorX;

/// <summary>
/// Flattened, presentation-friendly summary of a FileAnalysis, with helpers to export a key/value map.
/// Intended to let hosts (like TierBridge) present findings without reassembling logic.
/// </summary>
/// <summary>
/// Flattened analysis summary for presentation.
/// </summary>
public sealed class ReportView
{
    /// <summary>Detected extension.</summary>
    public string? DetectedTypeExtension { get; set; }
    /// <summary>Detected MIME type.</summary>
    public string? DetectedTypeName { get; set; }
    /// <summary>User-friendly type label (e.g., "Word document", "ZIP archive").</summary>
    public string? DetectedTypeFriendly { get; set; }
    /// <summary>Detection confidence (High/Medium/Low).</summary>
    public string? DetectionConfidence { get; set; }
    /// <summary>Short textual reason describing the detection.</summary>
    public string? DetectionReason { get; set; }
    /// <summary>Best-guess extension when ambiguous.</summary>
    public string? GuessedExtension { get; set; }

    /// <summary>WinVerifyTrust final policy verdict (Windows only).</summary>
    public bool? IsTrustedWindowsPolicy { get; set; }
    /// <summary>Raw WinVerifyTrust status code (0 = success).</summary>
    public int? WinTrustStatusCode { get; set; }

    /// <summary>Raw version information as a name/value map.</summary>
    public IReadOnlyDictionary<string,string>? VersionInfo { get; set; }
    /// <summary>Company name from version info.</summary>
    public string? CompanyName { get; set; }
    /// <summary>Product name from version info.</summary>
    public string? ProductName { get; set; }
    /// <summary>File description from version info.</summary>
    public string? FileDescription { get; set; }
    /// <summary>File version string.</summary>
    public string? FileVersion { get; set; }
    /// <summary>Product version string.</summary>
    public string? ProductVersion { get; set; }
    /// <summary>Original filename from version info.</summary>
    public string? OriginalFilename { get; set; }
    /// <summary>Inferred script language when applicable.</summary>
    public string? ScriptLanguage { get; set; }
    /// <summary>Human-friendly script language label.</summary>
    public string? ScriptLanguageHuman { get; set; }
    /// <summary>High-level content kind for the file.</summary>
    public ContentKind Kind { get; set; } = ContentKind.Unknown;
    /// <summary>Guidance for hosts on which sections to display.</summary>
    public PresentationAdvice Advice { get; set; } = new PresentationAdvice();
    /// <summary>Compact non-empty fields grouped by logical section.</summary>
    public IReadOnlyDictionary<string, IReadOnlyList<string>>? CompactFields { get; set; }

    /// <summary>Compact comma-separated flag codes suitable for humanization by hosts.</summary>
    public string? FlagsCsv { get; set; }
    /// <summary>Human-friendly flags (short form), produced by FileInspectorX.</summary>
    public string? FlagsHumanShort { get; set; }
    /// <summary>Human-friendly flags (long form), produced by FileInspectorX.</summary>
    public string? FlagsHumanLong { get; set; }

    /// <summary>Size of the certificate table (PE) when present.</summary>
    public int? CertificateTableSize { get; set; }
    /// <summary>SHA-256 of the raw certificate blob (PE) when present.</summary>
    public string? CertificateBlobSha256 { get; set; }
    /// <summary>Enhanced key usages (EKUs) from signer certificate.</summary>
    public IReadOnlyList<string>? EnhancedKeyUsages { get; set; }
    /// <summary>Timestamp authority common name.</summary>
    public string? TimestampAuthorityCN { get; set; }

    /// <summary>Risk score 0-100.</summary>
    public int? AssessmentScore { get; set; }
    /// <summary>Decision label (Allow/Warn/Block/Defer).</summary>
    public string? AssessmentDecision { get; set; }
    /// <summary>Finding codes that drove the score.</summary>
    public IReadOnlyList<string>? AssessmentCodes { get; set; }
    /// <summary>Human-friendly summary of assessment codes (short form).</summary>
    public string? AssessmentCodesHuman { get; set; }
    /// <summary>Human-friendly summary of assessment codes (long form).</summary>
    public string? AssessmentCodesHumanLong { get; set; }
    /// <summary>Score contributions by code.</summary>
    public IReadOnlyDictionary<string,int>? AssessmentFactors { get; set; }
    /// <summary>Number of encrypted entries in ZIP (if applicable).</summary>
    public int? EncryptedEntryCount { get; set; }
    /// <summary>Neutral security findings emitted by heuristics (e.g., ps:encoded, js:activex).</summary>
    public IReadOnlyList<string>? SecurityFindings { get; set; }
    /// <summary>Humanized security findings (short form).</summary>
    public string? SecurityFindingsHumanShort { get; set; }
    /// <summary>Humanized security findings (long form).</summary>
    public string? SecurityFindingsHumanLong { get; set; }
    /// <summary>Per-entry findings collected during deep scan (bounded).</summary>
    public IReadOnlyList<string>? InnerFindings { get; set; }
    /// <summary>Humanized inner findings (short form).</summary>
    public string? InnerFindingsHumanShort { get; set; }
    /// <summary>Humanized inner findings (long form).</summary>
    public string? InnerFindingsHumanLong { get; set; }
    /// <summary>Total inner executables sampled during deep scan.</summary>
    public int? InnerExecutablesSampled { get; set; }
    /// <summary>Number of sampled inner executables that are signed.</summary>
    public int? InnerSignedExecutables { get; set; }
    /// <summary>Number of sampled inner executables with valid chain/policy.</summary>
    public int? InnerValidSignedExecutables { get; set; }
    /// <summary>Top publishers with counts as a human string.</summary>
    public string? InnerPublishersHuman { get; set; }
    /// <summary>Human lines for archive preview entries ("name (ext)").</summary>
    public IReadOnlyList<string>? ArchivePreview { get; set; }
    

    // Archive + MOTW/ADS summaries
    /// <summary>Number of entries sampled inside an archive (ZIP/TAR), when available.</summary>
    public int? ArchiveEntryCount { get; set; }
    /// <summary>Top-N extensions encountered inside an archive (ordered by frequency).</summary>
    public IReadOnlyList<string>? ArchiveTopExtensions { get; set; }
    /// <summary>Windows MOTW ZoneId when present on the file.</summary>
    public int? MotwZoneId { get; set; }
    /// <summary>Windows MOTW ReferrerUrl when present.</summary>
    public string? MotwReferrerUrl { get; set; }
    /// <summary>Windows MOTW HostUrl when present.</summary>
    public string? MotwHostUrl { get; set; }
    /// <summary>Windows: number of alternate data streams on the file.</summary>
    public int? AlternateStreamCount { get; set; }

    // Secrets (category counts)
    /// <summary>Number of private key indicators found.</summary>
    public int? SecretsPrivateKeyCount { get; set; }
    /// <summary>Number of JWT-like tokens found.</summary>
    public int? SecretsJwtLikeCount { get; set; }
    /// <summary>Number of long key=/secret= value patterns found.</summary>
    public int? SecretsKeyPatternCount { get; set; }

    /// <summary>
    /// Creates a report view from a FileAnalysis instance.
    /// </summary>
    public static ReportView From(FileAnalysis a)
    {
        var r = new ReportView();
        if (a.Detection != null)
        {
            r.DetectedTypeExtension = a.Detection.Extension;
            r.DetectedTypeName = a.Detection.MimeType;
            r.DetectionConfidence = a.Detection.Confidence;
            r.DetectionReason = a.Detection.Reason;
            if (!string.IsNullOrEmpty(a.Detection.GuessedExtension)) r.GuessedExtension = a.Detection.GuessedExtension;
        }
        if (a.Authenticode != null)
        {
            r.IsTrustedWindowsPolicy = a.Authenticode.IsTrustedWindowsPolicy;
            r.WinTrustStatusCode = a.Authenticode.WinTrustStatusCode;
            r.EnhancedKeyUsages = a.Authenticode.EnhancedKeyUsages;
            r.TimestampAuthorityCN = a.Authenticode.TimestampAuthorityCN;
        }
        if (a.VersionInfo != null)
        {
            r.VersionInfo = a.VersionInfo;
            a.VersionInfo.TryGetValue("CompanyName", out var company);
            a.VersionInfo.TryGetValue("ProductName", out var product);
            a.VersionInfo.TryGetValue("FileDescription", out var fileDesc);
            a.VersionInfo.TryGetValue("FileVersion", out var fver);
            a.VersionInfo.TryGetValue("ProductVersion", out var pver);
            a.VersionInfo.TryGetValue("OriginalFilename", out var origFile);
            r.CompanyName = company; r.ProductName = product; r.FileDescription = fileDesc; r.FileVersion = fver; r.ProductVersion = pver; r.OriginalFilename = origFile;
        }
        // Script language
        if (!string.IsNullOrEmpty(a.ScriptLanguage))
        {
            r.ScriptLanguage = a.ScriptLanguage;
            r.ScriptLanguageHuman = ScriptLanguageLegend.Humanize(a.ScriptLanguage, HumanizeStyle.Short);
        }
        // Flags → compact CSV codes for presentation layers to humanize
        var codes = new List<string>(12);
        var f = a.Flags;
        if ((f & ContentFlags.HasOoxmlMacros) != 0) codes.Add("Macros");
        if ((f & ContentFlags.ContainerContainsExecutables) != 0) codes.Add("HasExe");
        if ((f & ContentFlags.ContainerContainsScripts) != 0) codes.Add("HasScript");
        if ((f & ContentFlags.PdfHasJavaScript) != 0) codes.Add("PdfJS");
        if ((f & ContentFlags.PdfHasOpenAction) != 0) codes.Add("PdfOpen");
        if ((f & ContentFlags.PdfHasAA) != 0) codes.Add("PdfAA");
        if ((f & ContentFlags.PdfEncrypted) != 0) codes.Add("PdfEnc");
        if ((f & ContentFlags.PeIsDotNet) != 0) codes.Add("DotNet");
        if ((f & ContentFlags.ArchiveHasEncryptedEntries) != 0) codes.Add("ZipEnc");
        if ((f & ContentFlags.OoxmlEncrypted) != 0) codes.Add("OoxmlEnc");
        if ((f & ContentFlags.ContainerHasDisguisedExecutables) != 0) codes.Add("DisgExec");
        if ((f & ContentFlags.PeHasAuthenticodeDirectory) != 0) codes.Add("SigPresent");
        if (codes.Count > 0)
        {
            r.FlagsCsv = string.Join(",", codes);
            r.FlagsHumanShort = Legend.HumanizeFlagsCsv(r.FlagsCsv, HumanizeStyle.Short);
            r.FlagsHumanLong  = Legend.HumanizeFlagsCsv(r.FlagsCsv, HumanizeStyle.Long);
        }

        if (a.Signature != null)
        {
            r.CertificateTableSize = a.Signature.CertificateTableSize;
            if (!string.IsNullOrEmpty(a.Signature.CertificateBlobSha256)) r.CertificateBlobSha256 = a.Signature.CertificateBlobSha256;
        }

        try
        {
            var assess = FileInspector.Assess(a);
            r.AssessmentScore = assess.Score;
            r.AssessmentDecision = assess.Decision.ToString();
            r.AssessmentCodes = assess.Codes;
            r.AssessmentFactors = assess.Factors;
            if (r.AssessmentCodes != null && r.AssessmentCodes.Count > 0)
            {
                r.AssessmentCodesHuman = AssessmentLegend.HumanizeCodes(r.AssessmentCodes, HumanizeStyle.Short);
                r.AssessmentCodesHumanLong = AssessmentLegend.HumanizeCodes(r.AssessmentCodes, HumanizeStyle.Long);
            }
        } catch { }
        r.EncryptedEntryCount = a.EncryptedEntryCount;
        r.SecurityFindings = a.SecurityFindings;
        r.InnerFindings = a.InnerFindings;
        r.InnerExecutablesSampled = a.InnerExecutablesSampled;
        r.InnerSignedExecutables = a.InnerSignedExecutables;
        r.InnerValidSignedExecutables = a.InnerValidSignedExecutables;
        if (a.InnerPublisherCounts != null && a.InnerPublisherCounts.Count > 0)
        {
            var top = a.InnerPublisherCounts.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key).Take(5).Select(kv => $"{kv.Key}({kv.Value})");
            r.InnerPublishersHuman = string.Join(", ", top);
        }
        if (a.ArchivePreviewEntries != null && a.ArchivePreviewEntries.Count > 0)
        {
            r.ArchivePreview = a.ArchivePreviewEntries
                .Select(ep => string.IsNullOrWhiteSpace(ep.DetectedExtension) ? ep.Name : $"{ep.Name} ({ep.DetectedExtension})")
                .Take(10)
                .ToArray();
        }
        // Archive + MOTW/ADS
        r.ArchiveEntryCount = a.ContainerEntryCount;
        r.ArchiveTopExtensions = a.ContainerTopExtensions;
        if (a.Security != null)
        {
            r.MotwZoneId = a.Security.MotwZoneId;
            r.MotwReferrerUrl = a.Security.MotwReferrerUrl;
            r.MotwHostUrl = a.Security.MotwHostUrl;
            r.AlternateStreamCount = a.Security.AlternateStreamCount;
        }
        // Secrets summary
        if (a.Secrets != null)
        {
            r.SecretsPrivateKeyCount = a.Secrets.PrivateKeyCount;
            r.SecretsJwtLikeCount = a.Secrets.JwtLikeCount;
            r.SecretsKeyPatternCount = a.Secrets.KeyPatternCount;
        }
        if (r.SecurityFindings != null && r.SecurityFindings.Count > 0)
        {
            r.SecurityFindingsHumanShort = Legend.HumanizeFindings(r.SecurityFindings, HumanizeStyle.Short);
            r.SecurityFindingsHumanLong  = Legend.HumanizeFindings(r.SecurityFindings, HumanizeStyle.Long);
        }
        if (r.InnerFindings != null && r.InnerFindings.Count > 0)
        {
            r.InnerFindingsHumanShort = Legend.HumanizeFindings(r.InnerFindings, HumanizeStyle.Short);
            r.InnerFindingsHumanLong  = Legend.HumanizeFindings(r.InnerFindings, HumanizeStyle.Long);
        }
        // Friendly type label
        try { r.DetectedTypeFriendly = FriendlyNames.GetTypeLabel(a.Detection, a); } catch { }

        // Kind/advice/compact fields
        r.Kind = a.Kind;
        var groups = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        void AddField(string group, string key, string? value)
        {
            if (string.IsNullOrWhiteSpace(value)) return;
            if (!groups.TryGetValue(group, out var list)) { list = new List<string>(); groups[group] = list; }
            list.Add(key);
        }
        AddField("Properties", "CompanyName", r.CompanyName);
        AddField("Properties", "ProductName", r.ProductName);
        AddField("Properties", "FileDescription", r.FileDescription);
        AddField("Properties", "FileVersion", r.FileVersion);
        AddField("Properties", "ProductVersion", r.ProductVersion);
        AddField("Properties", "OriginalFilename", r.OriginalFilename);
        AddField("Signature", "CertificateBlobSha256", r.CertificateBlobSha256);
        AddField("Signature", "WinTrustStatusCode", r.WinTrustStatusCode?.ToString());
        AddField("Signature", "EnhancedKeyUsages", (r.EnhancedKeyUsages != null && r.EnhancedKeyUsages.Count > 0) ? string.Join(", ", r.EnhancedKeyUsages) : null);
        AddField("Signature", "TimestampAuthorityCN", r.TimestampAuthorityCN);
        AddField("Script", "ScriptLanguageHuman", r.ScriptLanguageHuman);
        if (r.EncryptedEntryCount.HasValue) AddField("Archive", "EncryptedEntryCount", r.EncryptedEntryCount.Value.ToString());
        if (a.ContainerEntryCount.HasValue) AddField("Archive", "EntryCount", a.ContainerEntryCount.Value.ToString());
        if (a.ContainerTopExtensions != null && a.ContainerTopExtensions.Count > 0) AddField("Archive", "TopExtensions", string.Join(", ", a.ContainerTopExtensions));
        if (r.SecurityFindings is { Count: > 0 } || r.InnerFindings is { Count: > 0 }) AddField("Heuristics", "Findings", "1");
        r.CompactFields = groups.ToDictionary(k => k.Key, k => (IReadOnlyList<string>)k.Value);
        r.Advice = new PresentationAdvice
        {
            ShowTypeAnalysis = !string.IsNullOrEmpty(r.DetectedTypeName) || !string.IsNullOrEmpty(r.DetectedTypeExtension) || !string.IsNullOrEmpty(r.DetectedTypeFriendly),
            ShowProperties = r.CompactFields.TryGetValue("Properties", out var pf) && pf.Count > 0,
            ShowSignature = (!string.IsNullOrEmpty(r.CertificateBlobSha256)) || r.WinTrustStatusCode.HasValue || (r.EnhancedKeyUsages != null && r.EnhancedKeyUsages.Count > 0),
            ShowScript = !string.IsNullOrEmpty(r.ScriptLanguageHuman),
            ShowAssessment = r.AssessmentScore.HasValue || (r.AssessmentCodes != null && r.AssessmentCodes.Count > 0),
            ShowHeuristics = (r.SecurityFindings != null && r.SecurityFindings.Count > 0) || (r.InnerFindings != null && r.InnerFindings.Count > 0),
            ShowArchiveDetails = r.EncryptedEntryCount.HasValue || a.ContainerEntryCount.HasValue || (a.ContainerTopExtensions != null && a.ContainerTopExtensions.Count > 0)
        };

        return r;
    }

    /// <summary>
    /// Exports the report as a dictionary compatible with typical templating and logging sinks.
    /// </summary>
    /// <summary>Exports the report as a key/value map.</summary>
    public Dictionary<string, object?> ToDictionary()
    {
        var d = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        if (DetectedTypeExtension != null) d["DetectedTypeExtension"] = DetectedTypeExtension;
        if (DetectedTypeName != null) d["DetectedTypeName"] = DetectedTypeName;
        if (!string.IsNullOrEmpty(DetectedTypeFriendly)) d["DetectedTypeFriendly"] = DetectedTypeFriendly;
        if (DetectionConfidence != null) d["DetectionConfidence"] = DetectionConfidence;
        if (DetectionReason != null) d["DetectionReason"] = DetectionReason;
        if (!string.IsNullOrEmpty(GuessedExtension)) d["GuessedExtension"] = GuessedExtension;
        if (IsTrustedWindowsPolicy.HasValue) d["IsTrustedWindowsPolicy"] = IsTrustedWindowsPolicy.Value;
        if (WinTrustStatusCode.HasValue) d["WinTrustStatusCode"] = WinTrustStatusCode.Value;
        if (VersionInfo != null) d["VersionInfo"] = VersionInfo;
        if (CompanyName != null) d["CompanyName"] = CompanyName;
        if (ProductName != null) d["ProductName"] = ProductName;
        if (FileDescription != null) d["FileDescription"] = FileDescription;
        if (FileVersion != null) d["FileVersion"] = FileVersion;
        if (ProductVersion != null) d["ProductVersion"] = ProductVersion;
        if (OriginalFilename != null) d["OriginalFilename"] = OriginalFilename;
        if (!string.IsNullOrEmpty(FlagsCsv)) d["AnalysisFlags"] = FlagsCsv;
        if (!string.IsNullOrEmpty(FlagsHumanShort)) d["AnalysisFlagsHuman"] = FlagsHumanShort;
        if (!string.IsNullOrEmpty(FlagsHumanLong))  d["AnalysisFlagsHumanLong"] = FlagsHumanLong;
        if (!string.IsNullOrEmpty(ScriptLanguage)) d["ScriptLanguage"] = ScriptLanguage;
        if (!string.IsNullOrEmpty(ScriptLanguageHuman)) d["ScriptLanguageHuman"] = ScriptLanguageHuman;
        if (CertificateTableSize.HasValue) d["CertificateTableSize"] = CertificateTableSize.Value;
        if (!string.IsNullOrEmpty(CertificateBlobSha256)) d["CertificateBlobSha256"] = CertificateBlobSha256;
        if (AssessmentScore.HasValue) d["AssessmentScore"] = AssessmentScore.Value;
        if (!string.IsNullOrEmpty(AssessmentDecision)) d["AssessmentDecision"] = AssessmentDecision;
        if (AssessmentCodes != null && AssessmentCodes.Count > 0) d["AssessmentCodes"] = AssessmentCodes;
        if (AssessmentFactors != null && AssessmentFactors.Count > 0) d["AssessmentFactors"] = AssessmentFactors;
        if (!string.IsNullOrEmpty(AssessmentCodesHuman)) d["AssessmentCodesHuman"] = AssessmentCodesHuman;
        if (!string.IsNullOrEmpty(AssessmentCodesHumanLong)) d["AssessmentCodesHumanLong"] = AssessmentCodesHumanLong;
        if (EnhancedKeyUsages != null && EnhancedKeyUsages.Count > 0) d["EnhancedKeyUsages"] = EnhancedKeyUsages;
        if (!string.IsNullOrEmpty(TimestampAuthorityCN)) d["TimestampAuthorityCN"] = TimestampAuthorityCN;
        if (EncryptedEntryCount.HasValue) d["EncryptedEntryCount"] = EncryptedEntryCount.Value;
        // Archive inventory
        if (ArchiveEntryCount.HasValue) d["ArchiveEntryCount"] = ArchiveEntryCount.Value;
        if (ArchiveTopExtensions != null && ArchiveTopExtensions.Count > 0) d["ArchiveTopExtensions"] = ArchiveTopExtensions;
        if (SecurityFindings != null && SecurityFindings.Count > 0) d["SecurityFindings"] = SecurityFindings;
        if (!string.IsNullOrEmpty(SecurityFindingsHumanShort)) d["SecurityFindingsHuman"] = SecurityFindingsHumanShort;
        if (!string.IsNullOrEmpty(SecurityFindingsHumanLong))  d["SecurityFindingsHumanLong"] = SecurityFindingsHumanLong;
        if (InnerFindings != null && InnerFindings.Count > 0) d["InnerFindings"] = InnerFindings;
        if (!string.IsNullOrEmpty(InnerFindingsHumanShort)) d["InnerFindingsHuman"] = InnerFindingsHumanShort;
        if (!string.IsNullOrEmpty(InnerFindingsHumanLong))  d["InnerFindingsHumanLong"] = InnerFindingsHumanLong;
        if (InnerExecutablesSampled.HasValue) d["InnerExecutablesSampled"] = InnerExecutablesSampled.Value;
        if (InnerSignedExecutables.HasValue) d["InnerSignedExecutables"] = InnerSignedExecutables.Value;
        if (InnerValidSignedExecutables.HasValue) d["InnerValidSignedExecutables"] = InnerValidSignedExecutables.Value;
        if (!string.IsNullOrEmpty(InnerPublishersHuman)) d["InnerPublishersHuman"] = InnerPublishersHuman;
        if (ArchivePreview != null && ArchivePreview.Count > 0) d["ArchivePreview"] = ArchivePreview;
        d["Kind"] = Kind.ToString();
        // Security/MOTW export (if available)
        if (MotwZoneId.HasValue) d["MotwZoneId"] = MotwZoneId.Value;
        if (!string.IsNullOrEmpty(MotwReferrerUrl)) d["MotwReferrerUrl"] = MotwReferrerUrl;
        if (!string.IsNullOrEmpty(MotwHostUrl)) d["MotwHostUrl"] = MotwHostUrl;
        if (AlternateStreamCount.HasValue) d["AlternateStreamCount"] = AlternateStreamCount.Value;
        // Secrets
        if (SecretsPrivateKeyCount.HasValue) d["SecretsPrivateKeyCount"] = SecretsPrivateKeyCount.Value;
        if (SecretsJwtLikeCount.HasValue) d["SecretsJwtLikeCount"] = SecretsJwtLikeCount.Value;
        if (SecretsKeyPatternCount.HasValue) d["SecretsKeyPatternCount"] = SecretsKeyPatternCount.Value;
        if (Advice != null)
        {
            d["Advice"] = new Dictionary<string, object?>
            {
                ["ShowTypeAnalysis"] = Advice.ShowTypeAnalysis,
                ["ShowProperties"] = Advice.ShowProperties,
                ["ShowSignature"] = Advice.ShowSignature,
                ["ShowScript"] = Advice.ShowScript,
                ["ShowAssessment"] = Advice.ShowAssessment,
                ["ShowHeuristics"] = Advice.ShowHeuristics,
                ["ShowArchiveDetails"] = Advice.ShowArchiveDetails,
                ["ShowScan"] = Advice.ShowScan
            };
        }
        if (CompactFields != null && CompactFields.Count > 0) d["Compact"] = CompactFields;
        return d;
    }
}

/// <summary>
/// Guidance for hosts on which sections to include in UI/emails.
/// </summary>
public sealed class PresentationAdvice
{
    /// <summary>Include type analysis section (detected MIME/type, detection, flags).</summary>
    public bool ShowTypeAnalysis { get; set; }
    /// <summary>Include file properties section (Company, Product, Versions, OriginalFilename).</summary>
    public bool ShowProperties { get; set; }
    /// <summary>Include signature section (publisher, thumbprint, EKUs, TSA CN).</summary>
    public bool ShowSignature { get; set; }
    /// <summary>Include script section when a script language is detected.</summary>
    public bool ShowScript { get; set; }
    /// <summary>Include risk assessment section (score, decision, findings).</summary>
    public bool ShowAssessment { get; set; }
    /// <summary>Include heuristics section (security findings, inner findings).</summary>
    public bool ShowHeuristics { get; set; }
    /// <summary>Include archive details when available (e.g., encrypted entry count).</summary>
    public bool ShowArchiveDetails { get; set; }
    /// <summary>Host-controlled: show scan results (VT/Defender) when enabled.</summary>
    public bool ShowScan { get; set; }
}
