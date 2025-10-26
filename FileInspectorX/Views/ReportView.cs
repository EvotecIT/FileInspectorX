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
    /// <summary>True when a managed assembly has a strong-name signature (CLR header flag).</summary>
    public bool? DotNetStrongNameSigned { get; set; }
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
    /// <summary>Issuer Common Name (CN) of the Authenticode signer certificate.</summary>
    public string? SignerIssuerCN { get; set; }
    /// <summary>Issuer Organization (O) of the Authenticode signer certificate.</summary>
    public string? SignerIssuerO { get; set; }

    // Standalone certificate (DER/CRT/CER/PEM) typed fields
    /// <summary>Certificate subject (for standalone cert files).</summary>
    public string? CertSubject { get; set; }
    /// <summary>Certificate issuer (for standalone cert files).</summary>
    public string? CertIssuer { get; set; }
    /// <summary>Certificate NotBefore (UTC).</summary>
    public DateTime? CertNotBefore { get; set; }
    /// <summary>Certificate NotAfter (UTC).</summary>
    public DateTime? CertNotAfter { get; set; }
    /// <summary>Certificate thumbprint.</summary>
    public string? CertThumbprint { get; set; }
    /// <summary>Public key algorithm of the certificate.</summary>
    public string? CertKeyAlgorithm { get; set; }
    /// <summary>True if the certificate appears self-signed.</summary>
    public bool? CertSelfSigned { get; set; }
    /// <summary>True if a local chain build succeeds.</summary>
    public bool? CertChainTrusted { get; set; }
    /// <summary>Subject of the root element in the chain, when available.</summary>
    public string? CertRootSubject { get; set; }
    /// <summary>True if SAN extension is present.</summary>
    public bool? CertSanPresent { get; set; }

    // Certificate bundle (.p7b/.spc)
    /// <summary>
    /// Number of certificates found in a PKCS#7 bundle (e.g., .p7b/.spc), when the analyzed file is a certificate bundle.
    /// </summary>
    public int? CertBundleCount { get; set; }
    /// <summary>
    /// Distinct subject names extracted from a PKCS#7 certificate bundle, in display order.
    /// </summary>
    public IReadOnlyList<string>? CertBundleSubjects { get; set; }

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
    /// <summary>Compact one-line summary of inner binaries (sampled/signed/valid, top publisher).</summary>
    public string? InnerBinariesSummary { get; set; }

    // Reference samples for HTML and Scripts
    /// <summary>Comma-separated sample of external URLs found in HTML content.</summary>
    public string? HtmlExternalLinksSample { get; set; }
    /// <summary>Comma-separated sample of UNC share roots found in HTML content.</summary>
    public string? HtmlUncSample { get; set; }
    /// <summary>Comma-separated sample of URLs found in scripts.</summary>
    public string? ScriptUrlsSample { get; set; }
    /// <summary>Comma-separated sample of UNC share roots found in scripts.</summary>
    public string? ScriptUncSample { get; set; }
    /// <summary>Full list of external URLs found in HTML (newline-separated), truncated by settings.</summary>
    public string? HtmlExternalLinksFull { get; set; }
    /// <summary>Full list of UNC roots found in HTML (newline-separated), truncated by settings.</summary>
    public string? HtmlUncFull { get; set; }
    /// <summary>Full list of URLs found in scripts (newline-separated), truncated by settings.</summary>
    public string? ScriptUrlsFull { get; set; }
    /// <summary>Full list of UNC roots found in scripts (newline-separated), truncated by settings.</summary>
    public string? ScriptUncFull { get; set; }
    /// <summary>Comma-separated list of notable script cmdlets/verbs encountered.</summary>
    public string? ScriptCmdlets { get; set; }
    /// <summary>Publisher counts among signed inner executables.</summary>
    public IReadOnlyDictionary<string,int>? InnerPublisherCounts { get; set; }
    /// <summary>Publisher counts among validly signed inner executables.</summary>
    public IReadOnlyDictionary<string,int>? InnerPublisherValidCounts { get; set; }
    /// <summary>Publisher counts among self-signed inner executables.</summary>
    public IReadOnlyDictionary<string,int>? InnerPublisherSelfSignedCounts { get; set; }
    /// <summary>Human lines for archive preview entries ("name (ext)").</summary>
    public IReadOnlyList<string>? ArchivePreview { get; set; }

    // Installer summary (subset for presentation)
    /// <summary>Installer kind when recognized (e.g., MSI, MSIX).</summary>
    public string? InstallerKind { get; set; }
    /// <summary>Installer product/package name.</summary>
    public string? InstallerName { get; set; }
    /// <summary>Installer manufacturer/publisher.</summary>
    public string? InstallerManufacturer { get; set; }
    /// <summary>Installer version string.</summary>
    public string? InstallerVersion { get; set; }
    /// <summary>MSI ProductCode (GUID) when applicable.</summary>
    public string? InstallerProductCode { get; set; }
    /// <summary>MSI UpgradeCode (GUID) when applicable.</summary>
    public string? InstallerUpgradeCode { get; set; }
    /// <summary>Installer scope (PerUser/PerMachine) when applicable.</summary>
    public string? InstallerScope { get; set; }
    /// <summary>Installer URLs (About/Update/Help/Support) when available.</summary>
    public string? InstallerUrlInfoAbout { get; set; }
    /// <summary>Installer update information URL when available.</summary>
    public string? InstallerUrlUpdateInfo { get; set; }
    /// <summary>Installer help link when available.</summary>
    public string? InstallerHelpLink { get; set; }
    /// <summary>Installer support URL when available.</summary>
    public string? InstallerSupportUrl { get; set; }
    /// <summary>Installer contact string when available.</summary>
    public string? InstallerContact { get; set; }
    // Flattened MSI Custom Action counters for templating
    internal int? _MsiCAExe { get; set; }
    internal int? _MsiCADll { get; set; }
    internal int? _MsiCAScript { get; set; }
    internal string? _MsiCASamples { get; set; }
    

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
            r.SignerIssuerCN = a.Authenticode.IssuerCN;
            r.SignerIssuerO  = a.Authenticode.IssuerO;
        }
        // .NET strong name (when available)
        if (a.DotNetStrongNameSigned.HasValue)
            r.DotNetStrongNameSigned = a.DotNetStrongNameSigned;
        // Standalone certificate info (if parsed)
        if (a.Certificate != null)
        {
            r.CertSubject = a.Certificate.Subject;
            r.CertIssuer = a.Certificate.Issuer;
            r.CertNotBefore = a.Certificate.NotBeforeUtc;
            r.CertNotAfter = a.Certificate.NotAfterUtc;
            r.CertThumbprint = a.Certificate.Thumbprint;
            r.CertKeyAlgorithm = a.Certificate.KeyAlgorithm;
            r.CertSelfSigned = a.Certificate.SelfSigned;
            r.CertChainTrusted = a.Certificate.ChainTrusted;
            r.CertRootSubject = a.Certificate.RootSubject;
            r.CertSanPresent = a.Certificate.SanPresent;
        }
        // Certificate bundle info
        if (a.CertificateBundleCount.HasValue)
        {
            r.CertBundleCount = a.CertificateBundleCount;
            r.CertBundleSubjects = a.CertificateBundleSubjects;
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
        // Installer summary
        if (a.Installer != null)
        {
            r.InstallerKind = a.Installer.Kind.ToString();
            r.InstallerName = a.Installer.Name;
            r.InstallerManufacturer = a.Installer.Manufacturer ?? a.Installer.Publisher ?? a.Installer.PublisherDisplayName;
            r.InstallerVersion = a.Installer.Version;
            r.InstallerProductCode = a.Installer.ProductCode;
            r.InstallerUpgradeCode = a.Installer.UpgradeCode;
            r.InstallerScope = a.Installer.Scope;
            r.InstallerUrlInfoAbout = a.Installer.UrlInfoAbout;
            r.InstallerUrlUpdateInfo = a.Installer.UrlUpdateInfo;
            r.InstallerHelpLink = a.Installer.HelpLink;
            r.InstallerSupportUrl = a.Installer.SupportUrl;
            r.InstallerContact = a.Installer.Contact;
            // MSI Custom Action counts (flatten)
            if (a.Installer.MsiCustomActions != null)
            {
                r._MsiCAExe = a.Installer.MsiCustomActions.CountExe;
                r._MsiCADll = a.Installer.MsiCustomActions.CountDll;
                r._MsiCAScript = a.Installer.MsiCustomActions.CountScript;
                r._MsiCASamples = a.Installer.MsiCustomActions.Samples != null && a.Installer.MsiCustomActions.Samples.Count > 0
                    ? string.Join(", ", a.Installer.MsiCustomActions.Samples)
                    : null;
            }
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
        if ((f & ContentFlags.HasOoxmlMacros) != 0 || (f & ContentFlags.OleHasVbaMacros) != 0) codes.Add("Macros");
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
        if ((f & ContentFlags.HtmlHasExternalLinks) != 0) codes.Add("HtmlLinks");
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
            var top = a.InnerPublisherCounts
                .OrderByDescending(kv => kv.Value)
                .ThenBy(kv => kv.Key)
                .Take(5)
                .Select(kv =>
                {
                    var name = kv.Key;
                    var total = kv.Value;
                    int valid = 0, self = 0;
                    if (a.InnerPublisherValidCounts != null) a.InnerPublisherValidCounts.TryGetValue(name, out valid);
                    if (a.InnerPublisherSelfSignedCounts != null) a.InnerPublisherSelfSignedCounts.TryGetValue(name, out self);
                    string files = total == 1 ? "1 file" : $"{total} files";
                    string qual;
                    if (self > 0) qual = "self-signed";
                    else if (valid >= total && total > 0) qual = "valid";
                    else qual = "signed";
                    return $"{name} ({files}, {qual})";
                });
            r.InnerPublishersHuman = string.Join(", ", top);
            r.InnerPublisherCounts = a.InnerPublisherCounts;
            if (a.InnerPublisherValidCounts != null && a.InnerPublisherValidCounts.Count > 0) r.InnerPublisherValidCounts = a.InnerPublisherValidCounts;
            if (a.InnerPublisherSelfSignedCounts != null && a.InnerPublisherSelfSignedCounts.Count > 0) r.InnerPublisherSelfSignedCounts = a.InnerPublisherSelfSignedCounts;
        }
        // Inner binaries compact summary (single line) when counts present
        if (a.InnerExecutablesSampled.HasValue)
        {
            var parts = new List<string> { $"Binaries: {a.InnerExecutablesSampled.Value}" };
            if (a.InnerSignedExecutables.HasValue) parts.Add($"Signed {a.InnerSignedExecutables.Value}");
            if (a.InnerValidSignedExecutables.HasValue) parts.Add($"Valid {a.InnerValidSignedExecutables.Value}");
            if (!string.IsNullOrWhiteSpace(r.InnerPublishersHuman))
            {
                var firstSeg = (r.InnerPublishersHuman ?? string.Empty).Split(',');
                var head = firstSeg.Length > 0 ? firstSeg[0].Trim() : string.Empty;
                if (!string.IsNullOrWhiteSpace(head)) parts.Add($"Top: {head}");
            }
            r.InnerBinariesSummary = string.Join(" • ", parts);
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

        // Reference samples (HTML and scripts)
        try
        {
            var refs = a.References;
            if (refs != null && refs.Count > 0)
            {
                string JoinTop(IEnumerable<string> items, int n)
                {
                    var head = items.Where(s => !string.IsNullOrWhiteSpace(s)).Take(n).Select(s => s.Length > 120 ? s.Substring(0, 117) + "…" : s);
                    return string.Join(", ", head);
                }
                var htmlUrls = refs.Where(rf => rf.Kind == ReferenceKind.Url && (rf.SourceTag?.StartsWith("html:", StringComparison.OrdinalIgnoreCase) ?? false)).Select(rf => rf.Value);
                var htmlUnc  = refs.Where(rf => rf.Kind == ReferenceKind.FilePath && (rf.SourceTag?.StartsWith("html:", StringComparison.OrdinalIgnoreCase) ?? false) && (rf.Issues & ReferenceIssue.UncPath) != 0).Select(rf => rf.Value);
                var scrUrls  = refs.Where(rf => rf.Kind == ReferenceKind.Url && (rf.SourceTag?.StartsWith("script:", StringComparison.OrdinalIgnoreCase) ?? false)).Select(rf => rf.Value);
                var scrUnc   = refs.Where(rf => rf.Kind == ReferenceKind.FilePath && (rf.SourceTag?.StartsWith("script:", StringComparison.OrdinalIgnoreCase) ?? false) && (rf.Issues & ReferenceIssue.UncPath) != 0).Select(rf => rf.Value);

                var hUrls = JoinTop(htmlUrls, 5); if (!string.IsNullOrWhiteSpace(hUrls)) r.HtmlExternalLinksSample = hUrls;
                var hUnc  = JoinTop(htmlUnc, 3);  if (!string.IsNullOrWhiteSpace(hUnc))  r.HtmlUncSample = hUnc;
                var sUrls = JoinTop(scrUrls, 5);  if (!string.IsNullOrWhiteSpace(sUrls)) r.ScriptUrlsSample = sUrls;
                var sUnc  = JoinTop(scrUnc, 3);   if (!string.IsNullOrWhiteSpace(sUnc))  r.ScriptUncSample = sUnc;

                // Full lists (optional)
                if (Settings.ReferenceFullListsEnabled)
                {
                    string JoinAll(IEnumerable<string> items)
                    {
                        var uniq = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        var arr = new List<string>();
                        foreach (var it in items) { if (string.IsNullOrWhiteSpace(it)) continue; if (uniq.Add(it)) arr.Add(it); }
                        var joined = string.Join("\n", arr);
                        if (joined.Length > Settings.ReferenceFullListsMaxChars) joined = joined.Substring(0, Settings.ReferenceFullListsMaxChars) + "…";
                        return joined;
                    }
                    var htmlAll = JoinAll(htmlUrls);
                    if (!string.IsNullOrWhiteSpace(htmlAll)) r.HtmlExternalLinksFull = htmlAll;
                    var htmlUncAll = JoinAll(htmlUnc);
                    if (!string.IsNullOrWhiteSpace(htmlUncAll)) r.HtmlUncFull = htmlUncAll;
                    var scrAll = JoinAll(scrUrls);
                    if (!string.IsNullOrWhiteSpace(scrAll)) r.ScriptUrlsFull = scrAll;
                    var scrUncAll = JoinAll(scrUnc);
                    if (!string.IsNullOrWhiteSpace(scrUncAll)) r.ScriptUncFull = scrUncAll;
                }
            }
        } catch { }

        // Cmdlets (scripts)
        try
        {
            if (a.ScriptCmdlets != null && a.ScriptCmdlets.Count > 0)
            {
                string Titleize(string s)
                {
                    if (string.IsNullOrWhiteSpace(s)) return s;
                    var parts = s.Split('-', StringSplitOptions.RemoveEmptyEntries);
                    for (int i = 0; i < parts.Length; i++)
                    {
                        var p = parts[i]; if (p.Length == 0) continue;
                        parts[i] = char.ToUpperInvariant(p[0]) + (p.Length > 1 ? p.Substring(1) : string.Empty);
                    }
                    return string.Join('-', parts);
                }
                r.ScriptCmdlets = string.Join(", ", a.ScriptCmdlets.Take(6).Select(Titleize));
            }
        } catch { }

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
        AddField("Signature", "CertSubject", r.CertSubject);
        AddField("Signature", "CertIssuer", r.CertIssuer);
        AddField("Signature", "CertThumbprint", r.CertThumbprint);
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
            ShowSignature = (!string.IsNullOrEmpty(r.CertificateBlobSha256)) || r.WinTrustStatusCode.HasValue || (r.EnhancedKeyUsages != null && r.EnhancedKeyUsages.Count > 0) || !string.IsNullOrEmpty(r.CertSubject),
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
        if (!string.IsNullOrEmpty(SignerIssuerCN)) d["SignerIssuerCN"] = SignerIssuerCN;
        if (!string.IsNullOrEmpty(SignerIssuerO)) d["SignerIssuerO"] = SignerIssuerO;
        if (CertBundleCount.HasValue) d["CertBundleCount"] = CertBundleCount.Value;
        if (CertBundleSubjects != null && CertBundleSubjects.Count > 0) d["CertBundleSubjects"] = CertBundleSubjects;
        // Certificate (standalone) fields
        if (!string.IsNullOrEmpty(CertSubject)) d["CertSubject"] = CertSubject;
        if (!string.IsNullOrEmpty(CertIssuer)) d["CertIssuer"] = CertIssuer;
        if (CertNotBefore.HasValue) d["CertNotBefore"] = CertNotBefore.Value;
        if (CertNotAfter.HasValue) d["CertNotAfter"] = CertNotAfter.Value;
        if (!string.IsNullOrEmpty(CertThumbprint)) d["CertThumbprint"] = CertThumbprint;
        if (!string.IsNullOrEmpty(CertKeyAlgorithm)) d["CertKeyAlgorithm"] = CertKeyAlgorithm;
        if (CertSelfSigned.HasValue) d["CertSelfSigned"] = CertSelfSigned.Value;
        if (CertChainTrusted.HasValue) d["CertChainTrusted"] = CertChainTrusted.Value;
        if (!string.IsNullOrEmpty(CertRootSubject)) d["CertRootSubject"] = CertRootSubject;
        if (CertSanPresent.HasValue) d["CertSanPresent"] = CertSanPresent.Value;
        // Installer (subset)
        if (!string.IsNullOrEmpty(InstallerKind)) d["InstallerKind"] = InstallerKind;
        if (!string.IsNullOrEmpty(InstallerName)) d["InstallerName"] = InstallerName;
        if (!string.IsNullOrEmpty(InstallerManufacturer)) d["InstallerManufacturer"] = InstallerManufacturer;
        if (!string.IsNullOrEmpty(InstallerVersion)) d["InstallerVersion"] = InstallerVersion;
        if (!string.IsNullOrEmpty(InstallerProductCode)) d["InstallerProductCode"] = InstallerProductCode;
        if (!string.IsNullOrEmpty(InstallerUpgradeCode)) d["InstallerUpgradeCode"] = InstallerUpgradeCode;
        if (!string.IsNullOrEmpty(InstallerScope)) d["InstallerScope"] = InstallerScope;
        if (!string.IsNullOrEmpty(InstallerUrlInfoAbout)) d["InstallerUrlInfoAbout"] = InstallerUrlInfoAbout;
        if (!string.IsNullOrEmpty(InstallerUrlUpdateInfo)) d["InstallerUrlUpdateInfo"] = InstallerUrlUpdateInfo;
        if (!string.IsNullOrEmpty(InstallerHelpLink)) d["InstallerHelpLink"] = InstallerHelpLink;
        if (!string.IsNullOrEmpty(InstallerSupportUrl)) d["InstallerSupportUrl"] = InstallerSupportUrl;
        if (!string.IsNullOrEmpty(InstallerContact)) d["InstallerContact"] = InstallerContact;
        if (_MsiCAExe.HasValue) d["MsiCAExe"] = _MsiCAExe.Value;
        if (_MsiCADll.HasValue) d["MsiCADll"] = _MsiCADll.Value;
        if (_MsiCAScript.HasValue) d["MsiCAScript"] = _MsiCAScript.Value;
        if (!string.IsNullOrEmpty(_MsiCASamples)) d["MsiCASamples"] = _MsiCASamples;
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
        if (InnerPublisherCounts != null && InnerPublisherCounts.Count > 0) d["InnerPublisherCounts"] = InnerPublisherCounts;
        if (InnerPublisherValidCounts != null && InnerPublisherValidCounts.Count > 0) d["InnerPublisherValidCounts"] = InnerPublisherValidCounts;
        if (InnerPublisherSelfSignedCounts != null && InnerPublisherSelfSignedCounts.Count > 0) d["InnerPublisherSelfSignedCounts"] = InnerPublisherSelfSignedCounts;
        if (!string.IsNullOrEmpty(InnerBinariesSummary)) d["InnerBinariesSummary"] = InnerBinariesSummary;
        // Reference samples
        if (!string.IsNullOrEmpty(HtmlExternalLinksSample)) d["HtmlExternalLinksSample"] = HtmlExternalLinksSample;
        if (!string.IsNullOrEmpty(HtmlUncSample)) d["HtmlUncSample"] = HtmlUncSample;
        if (!string.IsNullOrEmpty(ScriptUrlsSample)) d["ScriptUrlsSample"] = ScriptUrlsSample;
        if (!string.IsNullOrEmpty(ScriptUncSample)) d["ScriptUncSample"] = ScriptUncSample;
        if (!string.IsNullOrEmpty(ScriptCmdlets)) d["ScriptCmdlets"] = ScriptCmdlets;
        if (!string.IsNullOrEmpty(HtmlExternalLinksFull)) d["HtmlExternalLinksFull"] = HtmlExternalLinksFull;
        if (!string.IsNullOrEmpty(HtmlUncFull)) d["HtmlUncFull"] = HtmlUncFull;
        if (!string.IsNullOrEmpty(ScriptUrlsFull)) d["ScriptUrlsFull"] = ScriptUrlsFull;
        if (!string.IsNullOrEmpty(ScriptUncFull)) d["ScriptUncFull"] = ScriptUncFull;
        if (ArchivePreview != null && ArchivePreview.Count > 0) d["ArchivePreview"] = ArchivePreview;
        d["Kind"] = Kind.ToString();
        if (DotNetStrongNameSigned.HasValue) d["DotNetStrongNameSigned"] = DotNetStrongNameSigned.Value;
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
