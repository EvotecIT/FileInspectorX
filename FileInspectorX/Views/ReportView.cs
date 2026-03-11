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
    /// <summary>Optional detailed cue description for the detection (e.g., js:cues-6).</summary>
    public string? DetectionReasonDetails { get; set; }
    /// <summary>Structured validation status when applicable (passed/failed/timeout/skipped).</summary>
    public string? DetectionValidationStatus { get; set; }
    /// <summary>Detection score (0-100) used to rank candidates.</summary>
    public int? DetectionScore { get; set; }
    /// <summary>True when the detected type is commonly considered risky/dangerous.</summary>
    public bool? DetectionIsDangerous { get; set; }
    /// <summary>Best-guess extension when ambiguous.</summary>
    public string? GuessedExtension { get; set; }
    /// <summary>Detected container subtype when known (e.g., apk, jar, msix).</summary>
    public string? ContainerSubtype { get; set; }
    /// <summary>Subtype for text-like content when known (e.g., json, log, powershell).</summary>
    public string? TextSubtype { get; set; }
    /// <summary>Estimated line count for text-like content.</summary>
    public int? EstimatedLineCount { get; set; }
    /// <summary>PE machine architecture when applicable.</summary>
    public string? PeMachine { get; set; }
    /// <summary>PE subsystem when applicable.</summary>
    public string? PeSubsystem { get; set; }
    /// <summary>PE kind when applicable (exe/dll/sys).</summary>
    public string? PeKind { get; set; }
    /// <summary>Alternative detection candidates when multiple formats are plausible.</summary>
    public IReadOnlyList<ContentTypeDetectionCandidate>? DetectionAlternatives { get; set; }
    /// <summary>Ranked detection candidates including the primary, when available.</summary>
    public IReadOnlyList<ContentTypeDetectionCandidate>? DetectionCandidates { get; set; }

    // Encoded payload summary (base64/hex) with inner detection
    /// <summary>When the content appears encoded, indicates the encoding kind (e.g., "base64" or "hex").</summary>
    public string? EncodedKind { get; set; }
    /// <summary>Inner detected extension from decoded payload (e.g., exe), when discovered.</summary>
    public string? EncodedInnerDetectedExtension { get; set; }
    /// <summary>Inner detected MIME from decoded payload, when discovered.</summary>
    public string? EncodedInnerDetectedName { get; set; }
    /// <summary>User-friendly label for inner detected type from decoded payload.</summary>
    public string? EncodedInnerDetectedFriendly { get; set; }

    /// <summary>WinVerifyTrust final policy verdict (Windows only).</summary>
    public bool? IsTrustedWindowsPolicy { get; set; }
    /// <summary>Raw WinVerifyTrust status code (0 = success).</summary>
    public int? WinTrustStatusCode { get; set; }
    /// <summary>True when an Authenticode signature is present.</summary>
    public bool? AuthenticodePresent { get; set; }
    /// <summary>True when the Authenticode certificate chain validated.</summary>
    public bool? AuthenticodeChainValid { get; set; }
    /// <summary>True when an Authenticode timestamp countersignature is present.</summary>
    public bool? AuthenticodeTimestampPresent { get; set; }

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
    /// <summary>True when a signature blob is present in the file.</summary>
    public bool? SignatureIsSigned { get; set; }
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
    /// <summary>Decision label under strict profile thresholds.</summary>
    public string? AssessmentDecisionStrict { get; set; }
    /// <summary>Decision label under balanced profile thresholds.</summary>
    public string? AssessmentDecisionBalanced { get; set; }
    /// <summary>Decision label under lenient profile thresholds.</summary>
    public string? AssessmentDecisionLenient { get; set; }
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
    /// <summary>Top tokens extracted from script/log content when enabled.</summary>
    public IReadOnlyList<string>? TopTokens { get; set; }
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
    /// <summary>Number of external link definitions detected in Office documents, when applicable.</summary>
    public int? OfficeExternalLinksCount { get; set; }
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
    /// <summary>Counts of inner executable entries by extension (exe/dll/msi/etc.).</summary>
    public IReadOnlyDictionary<string,int>? InnerExecutableExtCounts { get; set; }
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
    /// <summary>Installer creation time (UTC) when available.</summary>
    public string? InstallerCreated { get; set; }
    /// <summary>Installer last saved time (UTC) when available.</summary>
    public string? InstallerLastSaved { get; set; }
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
    /// <summary>Stable CSV of suspicious name/path issues detected for the file.</summary>
    public string? NameIssuesCsv { get; set; }
    /// <summary>True when the file is a symlink.</summary>
    public bool? IsSymlink { get; set; }
    /// <summary>True when the file is hidden.</summary>
    public bool? IsHidden { get; set; }
    /// <summary>True when the file is read-only.</summary>
    public bool? IsReadOnly { get; set; }
    /// <summary>Owner name when available.</summary>
    public string? Owner { get; set; }
    /// <summary>Unix mode in octal form when available.</summary>
    public string? ModeOctal { get; set; }
    /// <summary>Unix mode in symbolic form when available.</summary>
    public string? ModeSymbolic { get; set; }
    /// <summary>True when the file is executable.</summary>
    public bool? IsExecutable { get; set; }
    /// <summary>True when the file is world-writable.</summary>
    public bool? IsWorldWritable { get; set; }
    /// <summary>True when Everyone has write access on Windows.</summary>
    public bool? EveryoneWriteAllowed { get; set; }
    /// <summary>True when explicit deny ACEs are present on Windows.</summary>
    public bool? HasDenyEntries { get; set; }

    // Secrets (category counts)
    /// <summary>Number of private key indicators found.</summary>
    public int? SecretsPrivateKeyCount { get; set; }
    /// <summary>Number of JWT-like tokens found.</summary>
    public int? SecretsJwtLikeCount { get; set; }
    /// <summary>Number of long key=/secret= value patterns found.</summary>
    public int? SecretsKeyPatternCount { get; set; }
    /// <summary>Number of known token-family patterns found (e.g., GitHub/AWS/Slack-like formats).</summary>
    public int? SecretsTokenFamilyCount { get; set; }
    /// <summary>Number of GitHub token-family matches.</summary>
    public int? SecretsGitHubTokenCount { get; set; }
    /// <summary>Number of GitLab token-family matches.</summary>
    public int? SecretsGitLabTokenCount { get; set; }
    /// <summary>Number of AWS access key id token-family matches.</summary>
    public int? SecretsAwsAccessKeyIdCount { get; set; }
    /// <summary>Number of Slack token-family matches.</summary>
    public int? SecretsSlackTokenCount { get; set; }
    /// <summary>Number of Stripe live/rk token-family matches.</summary>
    public int? SecretsStripeLiveKeyCount { get; set; }
    /// <summary>Number of GCP API key token-family matches.</summary>
    public int? SecretsGcpApiKeyCount { get; set; }
    /// <summary>Number of npm token-family matches.</summary>
    public int? SecretsNpmTokenCount { get; set; }
    /// <summary>Number of Azure SAS token-family matches.</summary>
    public int? SecretsAzureSasTokenCount { get; set; }
    /// <summary>Privacy-safe secret finding details with confidence and redacted evidence.</summary>
    public IReadOnlyList<SecretFindingDetail>? SecretsFindings { get; set; }

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
            r.DetectionReasonDetails = a.Detection.ReasonDetails;
            r.DetectionValidationStatus = a.Detection.ValidationStatus;
            if (a.Detection.Score.HasValue) r.DetectionScore = a.Detection.Score;
            r.DetectionIsDangerous = a.Detection.IsDangerous;
            if (a.Detection.Alternatives != null && a.Detection.Alternatives.Count > 0) r.DetectionAlternatives = a.Detection.Alternatives;
            if (a.Detection.Candidates != null && a.Detection.Candidates.Count > 0) r.DetectionCandidates = a.Detection.Candidates;
            // Additional friendliness for PE is handled in detection; nothing to do here
            if (!string.IsNullOrEmpty(a.Detection.GuessedExtension)) r.GuessedExtension = a.Detection.GuessedExtension;
        }
        r.ContainerSubtype = a.ContainerSubtype;
        r.TextSubtype = a.TextSubtype;
        r.EstimatedLineCount = a.EstimatedLineCount;
        r.PeMachine = a.PeMachine;
        r.PeSubsystem = a.PeSubsystem;
        r.PeKind = a.PeKind;
        // Encoded payload presentation
        if (!string.IsNullOrWhiteSpace(a.EncodedKind))
        {
            r.EncodedKind = a.EncodedKind;
            var inner = a.EncodedInnerDetection;
            if (inner != null)
            {
                r.EncodedInnerDetectedExtension = inner.Extension;
                r.EncodedInnerDetectedName = inner.MimeType;
                r.EncodedInnerDetectedFriendly = FriendlyNames.GetTypeLabel(inner, a);
            }
        }
        if (a.Authenticode != null)
        {
            r.AuthenticodePresent = a.Authenticode.Present;
            r.AuthenticodeChainValid = a.Authenticode.ChainValid;
            r.AuthenticodeTimestampPresent = a.Authenticode.TimestampPresent;
            r.IsTrustedWindowsPolicy = a.Authenticode.IsTrustedWindowsPolicy;
            r.WinTrustStatusCode = a.Authenticode.WinTrustStatusCode;
            r.EnhancedKeyUsages = a.Authenticode.EnhancedKeyUsages;
            r.TimestampAuthorityCN = a.Authenticode.TimestampAuthorityCN;
            r.SignerIssuerCN = a.Authenticode.IssuerCN;
            r.SignerIssuerO  = a.Authenticode.IssuerO;
        }
        if (a.Signature != null)
        {
            r.SignatureIsSigned = a.Signature.IsSigned;
            r.CertificateTableSize = a.Signature.CertificateTableSize;
            if (!string.IsNullOrEmpty(a.Signature.CertificateBlobSha256))
                r.CertificateBlobSha256 = a.Signature.CertificateBlobSha256;
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
            if (a.Installer.CreatedUtc.HasValue) r.InstallerCreated = a.Installer.CreatedUtc.Value.ToString("u");
            if (a.Installer.LastSavedUtc.HasValue) r.InstallerLastSaved = a.Installer.LastSavedUtc.Value.ToString("u");
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
        if (a.OfficeExternalLinksCount.HasValue)
            r.OfficeExternalLinksCount = a.OfficeExternalLinksCount;
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
        if ((f & ContentFlags.EncodedBase64) != 0) codes.Add("EncB64");
        if ((f & ContentFlags.EncodedHex) != 0) codes.Add("EncHex");
        if ((f & ContentFlags.EncodedBase85) != 0) codes.Add("EncB85");
        if ((f & ContentFlags.EncodedUu) != 0) codes.Add("EncUu");
        if ((f & ContentFlags.PeHasAuthenticodeDirectory) != 0) codes.Add("SigPresent");
        if (codes.Count > 0)
        {
            r.FlagsCsv = string.Join(",", codes);
            r.FlagsHumanShort = Legend.HumanizeFlagsCsv(r.FlagsCsv, HumanizeStyle.Short);
            r.FlagsHumanLong  = Legend.HumanizeFlagsCsv(r.FlagsCsv, HumanizeStyle.Long);
        }
        try
        {
            var multi = FileInspector.AssessMulti(a);
            var assess = multi.Balanced;
            r.AssessmentScore = assess.Score;
            r.AssessmentDecision = assess.Decision.ToString();
            r.AssessmentDecisionStrict = multi.Strict.Decision.ToString();
            r.AssessmentDecisionBalanced = multi.Balanced.Decision.ToString();
            r.AssessmentDecisionLenient = multi.Lenient.Decision.ToString();
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
        r.TopTokens = a.TopTokens;
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
        if (a.InnerExecutableExtCounts != null && a.InnerExecutableExtCounts.Count > 0) r.InnerExecutableExtCounts = a.InnerExecutableExtCounts;
        if (a.Security != null)
        {
            r.IsSymlink = a.Security.IsSymlink;
            r.IsHidden = a.Security.IsHidden;
            r.IsReadOnly = a.Security.IsReadOnly;
            r.Owner = a.Security.Owner;
            r.ModeOctal = a.Security.ModeOctal;
            r.ModeSymbolic = a.Security.ModeSymbolic;
            r.IsExecutable = a.Security.IsExecutable;
            r.IsWorldWritable = a.Security.IsWorldWritable;
            r.EveryoneWriteAllowed = a.Security.EveryoneWriteAllowed;
            r.HasDenyEntries = a.Security.HasDenyEntries;
            r.MotwZoneId = a.Security.MotwZoneId;
            r.MotwReferrerUrl = a.Security.MotwReferrerUrl;
            r.MotwHostUrl = a.Security.MotwHostUrl;
            r.AlternateStreamCount = a.Security.AlternateStreamCount;
        }
        if (a.NameIssues != NameIssues.None)
            r.NameIssuesCsv = FormatNameIssuesCsv(a.NameIssues);
        // Secrets summary
        if (a.Secrets != null)
        {
            r.SecretsPrivateKeyCount = a.Secrets.PrivateKeyCount;
            r.SecretsJwtLikeCount = a.Secrets.JwtLikeCount;
            r.SecretsKeyPatternCount = a.Secrets.KeyPatternCount;
            r.SecretsTokenFamilyCount = a.Secrets.TokenFamilyCount;
            r.SecretsGitHubTokenCount = a.Secrets.GitHubTokenCount;
            r.SecretsGitLabTokenCount = a.Secrets.GitLabTokenCount;
            r.SecretsAwsAccessKeyIdCount = a.Secrets.AwsAccessKeyIdCount;
            r.SecretsSlackTokenCount = a.Secrets.SlackTokenCount;
            r.SecretsStripeLiveKeyCount = a.Secrets.StripeLiveKeyCount;
            r.SecretsGcpApiKeyCount = a.Secrets.GcpApiKeyCount;
            r.SecretsNpmTokenCount = a.Secrets.NpmTokenCount;
            r.SecretsAzureSasTokenCount = a.Secrets.AzureSasTokenCount;
            r.SecretsFindings = a.Secrets.Findings;
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
                    var parts = s.Split(new[]{'-'}, StringSplitOptions.RemoveEmptyEntries);
                    for (int i = 0; i < parts.Length; i++)
                    {
                        var p = parts[i]; if (p.Length == 0) continue;
                        parts[i] = char.ToUpperInvariant(p[0]) + (p.Length > 1 ? p.Substring(1) : string.Empty);
                    }
                    return string.Join("-", parts);
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
        if (r.VersionInfo != null && r.VersionInfo.Count > 0) AddField("Properties", "VersionInfo", "1");
        AddField("Properties", "CompanyName", r.CompanyName);
        AddField("Properties", "ProductName", r.ProductName);
        AddField("Properties", "FileDescription", r.FileDescription);
        AddField("Properties", "FileVersion", r.FileVersion);
        AddField("Properties", "ProductVersion", r.ProductVersion);
        AddField("Properties", "OriginalFilename", r.OriginalFilename);
        AddField("TypeAnalysis", "DetectedTypeName", r.DetectedTypeName);
        AddField("TypeAnalysis", "DetectedTypeExtension", r.DetectedTypeExtension);
        AddField("TypeAnalysis", "DetectedTypeFriendly", r.DetectedTypeFriendly);
        AddField("TypeAnalysis", "DetectionConfidence", r.DetectionConfidence);
        AddField("TypeAnalysis", "DetectionReason", r.DetectionReason);
        AddField("TypeAnalysis", "DetectionReasonDetails", r.DetectionReasonDetails);
        AddField("TypeAnalysis", "DetectionValidationStatus", r.DetectionValidationStatus);
        if (r.DetectionScore.HasValue) AddField("TypeAnalysis", "DetectionScore", r.DetectionScore.Value.ToString());
        if (r.DetectionIsDangerous.HasValue) AddField("TypeAnalysis", "DetectionIsDangerous", r.DetectionIsDangerous.Value ? "true" : "false");
        AddField("TypeAnalysis", "GuessedExtension", r.GuessedExtension);
        AddField("TypeAnalysis", "ContainerSubtype", r.ContainerSubtype);
        AddField("TypeAnalysis", "TextSubtype", r.TextSubtype);
        if (r.EstimatedLineCount.HasValue) AddField("TypeAnalysis", "EstimatedLineCount", r.EstimatedLineCount.Value.ToString());
        AddField("TypeAnalysis", "PeMachine", r.PeMachine);
        AddField("TypeAnalysis", "PeSubsystem", r.PeSubsystem);
        AddField("TypeAnalysis", "PeKind", r.PeKind);
        AddField("TypeAnalysis", "EncodedKind", r.EncodedKind);
        AddField("TypeAnalysis", "EncodedInnerDetectedExtension", r.EncodedInnerDetectedExtension);
        AddField("TypeAnalysis", "EncodedInnerDetectedName", r.EncodedInnerDetectedName);
        AddField("TypeAnalysis", "EncodedInnerDetectedFriendly", r.EncodedInnerDetectedFriendly);
        if (r.DetectionCandidates != null && r.DetectionCandidates.Count > 0) AddField("TypeAnalysis", "DetectionCandidates", "1");
        if (r.DetectionAlternatives != null && r.DetectionAlternatives.Count > 0) AddField("TypeAnalysis", "DetectionAlternatives", "1");
        if (r.CertificateTableSize.HasValue) AddField("Signature", "CertificateTableSize", r.CertificateTableSize.Value.ToString());
        AddField("Signature", "CertificateBlobSha256", r.CertificateBlobSha256);
        if (r.SignatureIsSigned.HasValue) AddField("Signature", "SignatureIsSigned", r.SignatureIsSigned.Value ? "true" : "false");
        if (r.DotNetStrongNameSigned.HasValue) AddField("Signature", "DotNetStrongNameSigned", r.DotNetStrongNameSigned.Value ? "true" : "false");
        if (r.AuthenticodePresent.HasValue) AddField("Signature", "AuthenticodePresent", r.AuthenticodePresent.Value ? "true" : "false");
        if (r.AuthenticodeChainValid.HasValue) AddField("Signature", "AuthenticodeChainValid", r.AuthenticodeChainValid.Value ? "true" : "false");
        if (r.AuthenticodeTimestampPresent.HasValue) AddField("Signature", "AuthenticodeTimestampPresent", r.AuthenticodeTimestampPresent.Value ? "true" : "false");
        if (r.IsTrustedWindowsPolicy.HasValue) AddField("Signature", "IsTrustedWindowsPolicy", r.IsTrustedWindowsPolicy.Value ? "true" : "false");
        AddField("Signature", "WinTrustStatusCode", r.WinTrustStatusCode?.ToString());
        AddField("Signature", "EnhancedKeyUsages", (r.EnhancedKeyUsages != null && r.EnhancedKeyUsages.Count > 0) ? string.Join(", ", r.EnhancedKeyUsages) : null);
        AddField("Signature", "TimestampAuthorityCN", r.TimestampAuthorityCN);
        AddField("Signature", "SignerIssuerCN", r.SignerIssuerCN);
        AddField("Signature", "SignerIssuerO", r.SignerIssuerO);
        AddField("Signature", "CertSubject", r.CertSubject);
        AddField("Signature", "CertIssuer", r.CertIssuer);
        if (r.CertNotBefore.HasValue) AddField("Signature", "CertNotBefore", r.CertNotBefore.Value.ToString("u"));
        if (r.CertNotAfter.HasValue) AddField("Signature", "CertNotAfter", r.CertNotAfter.Value.ToString("u"));
        AddField("Signature", "CertThumbprint", r.CertThumbprint);
        AddField("Signature", "CertKeyAlgorithm", r.CertKeyAlgorithm);
        if (r.CertSelfSigned.HasValue) AddField("Signature", "CertSelfSigned", r.CertSelfSigned.Value ? "true" : "false");
        if (r.CertChainTrusted.HasValue) AddField("Signature", "CertChainTrusted", r.CertChainTrusted.Value ? "true" : "false");
        AddField("Signature", "CertRootSubject", r.CertRootSubject);
        if (r.CertSanPresent.HasValue) AddField("Signature", "CertSanPresent", r.CertSanPresent.Value ? "true" : "false");
        if (r.CertBundleCount.HasValue) AddField("Signature", "CertBundleCount", r.CertBundleCount.Value.ToString());
        if (r.CertBundleSubjects != null && r.CertBundleSubjects.Count > 0) AddField("Signature", "CertBundleSubjects", string.Join(", ", r.CertBundleSubjects));
        if (r.MotwZoneId.HasValue) AddField("Security", "MotwZoneId", r.MotwZoneId.Value.ToString());
        AddField("Security", "MotwReferrerUrl", r.MotwReferrerUrl);
        AddField("Security", "MotwHostUrl", r.MotwHostUrl);
        if (r.AlternateStreamCount.HasValue) AddField("Security", "AlternateStreamCount", r.AlternateStreamCount.Value.ToString());
        AddField("Security", "NameIssues", r.NameIssuesCsv);
        if (r.IsSymlink.HasValue) AddField("Security", "IsSymlink", r.IsSymlink.Value ? "true" : "false");
        if (r.IsHidden.HasValue) AddField("Security", "IsHidden", r.IsHidden.Value ? "true" : "false");
        if (r.IsReadOnly.HasValue) AddField("Security", "IsReadOnly", r.IsReadOnly.Value ? "true" : "false");
        AddField("Security", "Owner", r.Owner);
        AddField("Security", "ModeOctal", r.ModeOctal);
        AddField("Security", "ModeSymbolic", r.ModeSymbolic);
        if (r.IsExecutable.HasValue) AddField("Security", "IsExecutable", r.IsExecutable.Value ? "true" : "false");
        if (r.IsWorldWritable.HasValue) AddField("Security", "IsWorldWritable", r.IsWorldWritable.Value ? "true" : "false");
        if (r.EveryoneWriteAllowed.HasValue) AddField("Security", "EveryoneWriteAllowed", r.EveryoneWriteAllowed.Value ? "true" : "false");
        if (r.HasDenyEntries.HasValue) AddField("Security", "HasDenyEntries", r.HasDenyEntries.Value ? "true" : "false");
        AddField("Script", "ScriptLanguage", r.ScriptLanguage);
        AddField("Script", "ScriptLanguageHuman", r.ScriptLanguageHuman);
        AddField("Script", "ScriptCmdlets", r.ScriptCmdlets);
        AddField("References", "HtmlExternalLinksSample", r.HtmlExternalLinksSample);
        AddField("References", "HtmlUncSample", r.HtmlUncSample);
        AddField("References", "ScriptUrlsSample", r.ScriptUrlsSample);
        AddField("References", "ScriptUncSample", r.ScriptUncSample);
        if (r.OfficeExternalLinksCount.HasValue) AddField("References", "OfficeExternalLinksCount", r.OfficeExternalLinksCount.Value.ToString());
        AddField("References", "HtmlExternalLinksFull", r.HtmlExternalLinksFull);
        AddField("References", "HtmlUncFull", r.HtmlUncFull);
        AddField("References", "ScriptUrlsFull", r.ScriptUrlsFull);
        AddField("References", "ScriptUncFull", r.ScriptUncFull);
        AddField("Installer", "InstallerKind", r.InstallerKind);
        AddField("Installer", "InstallerName", r.InstallerName);
        AddField("Installer", "InstallerManufacturer", r.InstallerManufacturer);
        AddField("Installer", "InstallerVersion", r.InstallerVersion);
        AddField("Installer", "InstallerProductCode", r.InstallerProductCode);
        AddField("Installer", "InstallerUpgradeCode", r.InstallerUpgradeCode);
        AddField("Installer", "InstallerScope", r.InstallerScope);
        AddField("Installer", "InstallerUrlInfoAbout", r.InstallerUrlInfoAbout);
        AddField("Installer", "InstallerUrlUpdateInfo", r.InstallerUrlUpdateInfo);
        AddField("Installer", "InstallerHelpLink", r.InstallerHelpLink);
        AddField("Installer", "InstallerSupportUrl", r.InstallerSupportUrl);
        AddField("Installer", "InstallerContact", r.InstallerContact);
        AddField("Installer", "InstallerCreated", r.InstallerCreated);
        AddField("Installer", "InstallerLastSaved", r.InstallerLastSaved);
        if (r._MsiCAExe.HasValue) AddField("Installer", "MsiCAExe", r._MsiCAExe.Value.ToString());
        if (r._MsiCADll.HasValue) AddField("Installer", "MsiCADll", r._MsiCADll.Value.ToString());
        if (r._MsiCAScript.HasValue) AddField("Installer", "MsiCAScript", r._MsiCAScript.Value.ToString());
        AddField("Installer", "MsiCASamples", r._MsiCASamples);
        if (r.AssessmentScore.HasValue) AddField("Assessment", "AssessmentScore", r.AssessmentScore.Value.ToString());
        AddField("Assessment", "AssessmentDecision", r.AssessmentDecision);
        AddField("Assessment", "AssessmentDecisionStrict", r.AssessmentDecisionStrict);
        AddField("Assessment", "AssessmentDecisionBalanced", r.AssessmentDecisionBalanced);
        AddField("Assessment", "AssessmentDecisionLenient", r.AssessmentDecisionLenient);
        if (r.AssessmentCodes != null && r.AssessmentCodes.Count > 0) AddField("Assessment", "AssessmentCodes", "1");
        if (r.AssessmentFactors != null && r.AssessmentFactors.Count > 0) AddField("Assessment", "AssessmentFactors", "1");
        AddField("Assessment", "AssessmentCodesHuman", r.AssessmentCodesHuman);
        AddField("Assessment", "AssessmentCodesHumanLong", r.AssessmentCodesHumanLong);
        if (r.EncryptedEntryCount.HasValue) AddField("Archive", "EncryptedEntryCount", r.EncryptedEntryCount.Value.ToString());
        if (a.ContainerEntryCount.HasValue) AddField("Archive", "EntryCount", a.ContainerEntryCount.Value.ToString());
        if (a.ContainerTopExtensions != null && a.ContainerTopExtensions.Count > 0) AddField("Archive", "TopExtensions", string.Join(", ", a.ContainerTopExtensions));
        if (r.InnerExecutablesSampled.HasValue) AddField("Archive", "InnerExecutablesSampled", r.InnerExecutablesSampled.Value.ToString());
        if (r.InnerSignedExecutables.HasValue) AddField("Archive", "InnerSignedExecutables", r.InnerSignedExecutables.Value.ToString());
        if (r.InnerValidSignedExecutables.HasValue) AddField("Archive", "InnerValidSignedExecutables", r.InnerValidSignedExecutables.Value.ToString());
        AddField("Archive", "InnerPublishersHuman", r.InnerPublishersHuman);
        if (r.InnerPublisherCounts != null && r.InnerPublisherCounts.Count > 0) AddField("Archive", "InnerPublisherCounts", "1");
        if (r.InnerPublisherValidCounts != null && r.InnerPublisherValidCounts.Count > 0) AddField("Archive", "InnerPublisherValidCounts", "1");
        if (r.InnerPublisherSelfSignedCounts != null && r.InnerPublisherSelfSignedCounts.Count > 0) AddField("Archive", "InnerPublisherSelfSignedCounts", "1");
        if (r.InnerExecutableExtCounts != null && r.InnerExecutableExtCounts.Count > 0) AddField("Archive", "InnerExecutableExtCounts", "1");
        if (!string.IsNullOrWhiteSpace(r.InnerBinariesSummary)) AddField("Archive", "InnerBinariesSummary", r.InnerBinariesSummary);
        if (r.ArchivePreview != null && r.ArchivePreview.Count > 0) AddField("Archive", "Preview", "1");
        if (r.SecurityFindings is { Count: > 0 } || r.InnerFindings is { Count: > 0 } || r.TopTokens is { Count: > 0 } || HasAnySecretSignals(r))
            AddField("Heuristics", "Findings", "1");
        if (r.TopTokens is { Count: > 0 }) AddField("Heuristics", "TopTokens", "1");
        r.CompactFields = groups.ToDictionary(k => k.Key, k => (IReadOnlyList<string>)k.Value);
        r.Advice = new PresentationAdvice
        {
            ShowTypeAnalysis = HasAnyTypeSignals(r),
            ShowProperties = HasAnyPropertySignals(r),
            ShowSignature = HasAnySignatureSignals(r),
            ShowSecurity = HasAnySecuritySignals(r),
            ShowScript = HasAnyScriptSignals(r),
            ShowReferences = HasAnyReferenceSignals(r),
            ShowInstaller = HasAnyInstallerSignals(r),
            ShowAssessment = HasAnyAssessmentSignals(r),
            ShowHeuristics = (r.SecurityFindings != null && r.SecurityFindings.Count > 0) ||
                             (r.InnerFindings != null && r.InnerFindings.Count > 0) ||
                             (r.TopTokens != null && r.TopTokens.Count > 0) ||
                             HasAnySecretSignals(r),
            ShowArchiveDetails = HasAnyArchiveSignals(r)
        };

        return r;
    }

    private static bool HasAnySecretSignals(ReportView r)
        => (r.SecretsPrivateKeyCount ?? 0) > 0 ||
           (r.SecretsJwtLikeCount ?? 0) > 0 ||
           (r.SecretsKeyPatternCount ?? 0) > 0 ||
           (r.SecretsTokenFamilyCount ?? 0) > 0 ||
           (r.SecretsGitHubTokenCount ?? 0) > 0 ||
           (r.SecretsGitLabTokenCount ?? 0) > 0 ||
           (r.SecretsAwsAccessKeyIdCount ?? 0) > 0 ||
           (r.SecretsSlackTokenCount ?? 0) > 0 ||
           (r.SecretsStripeLiveKeyCount ?? 0) > 0 ||
           (r.SecretsGcpApiKeyCount ?? 0) > 0 ||
           (r.SecretsNpmTokenCount ?? 0) > 0 ||
           (r.SecretsAzureSasTokenCount ?? 0) > 0 ||
           (r.SecretsFindings != null && r.SecretsFindings.Count > 0);

    private static bool HasAnySignatureSignals(ReportView r)
        => r.SignatureIsSigned.HasValue ||
           r.CertificateTableSize.HasValue ||
           !string.IsNullOrEmpty(r.CertificateBlobSha256) ||
           r.DotNetStrongNameSigned.HasValue ||
           r.AuthenticodePresent.HasValue ||
           r.AuthenticodeChainValid.HasValue ||
           r.AuthenticodeTimestampPresent.HasValue ||
           r.IsTrustedWindowsPolicy.HasValue ||
           r.WinTrustStatusCode.HasValue ||
           (r.EnhancedKeyUsages != null && r.EnhancedKeyUsages.Count > 0) ||
           !string.IsNullOrEmpty(r.TimestampAuthorityCN) ||
           !string.IsNullOrEmpty(r.SignerIssuerCN) ||
           !string.IsNullOrEmpty(r.SignerIssuerO) ||
           !string.IsNullOrEmpty(r.CertSubject) ||
           !string.IsNullOrEmpty(r.CertIssuer) ||
           r.CertNotBefore.HasValue ||
           r.CertNotAfter.HasValue ||
           !string.IsNullOrEmpty(r.CertThumbprint) ||
           !string.IsNullOrEmpty(r.CertKeyAlgorithm) ||
           r.CertSelfSigned.HasValue ||
           r.CertChainTrusted.HasValue ||
           !string.IsNullOrEmpty(r.CertRootSubject) ||
           r.CertSanPresent.HasValue ||
           r.CertBundleCount.HasValue ||
           (r.CertBundleSubjects != null && r.CertBundleSubjects.Count > 0);

    private static bool HasAnyTypeSignals(ReportView r)
        => !string.IsNullOrEmpty(r.DetectedTypeName) ||
           !string.IsNullOrEmpty(r.DetectedTypeExtension) ||
           !string.IsNullOrEmpty(r.DetectedTypeFriendly) ||
           !string.IsNullOrEmpty(r.DetectionConfidence) ||
           !string.IsNullOrEmpty(r.DetectionReason) ||
           !string.IsNullOrEmpty(r.DetectionReasonDetails) ||
           !string.IsNullOrEmpty(r.DetectionValidationStatus) ||
           r.DetectionScore.HasValue ||
           r.DetectionIsDangerous.HasValue ||
           !string.IsNullOrEmpty(r.GuessedExtension) ||
           !string.IsNullOrEmpty(r.ContainerSubtype) ||
           !string.IsNullOrEmpty(r.TextSubtype) ||
           r.EstimatedLineCount.HasValue ||
           !string.IsNullOrEmpty(r.PeMachine) ||
           !string.IsNullOrEmpty(r.PeSubsystem) ||
           !string.IsNullOrEmpty(r.PeKind) ||
           (r.DetectionAlternatives != null && r.DetectionAlternatives.Count > 0) ||
           (r.DetectionCandidates != null && r.DetectionCandidates.Count > 0) ||
           !string.IsNullOrEmpty(r.EncodedKind) ||
           !string.IsNullOrEmpty(r.EncodedInnerDetectedExtension) ||
           !string.IsNullOrEmpty(r.EncodedInnerDetectedName) ||
           !string.IsNullOrEmpty(r.EncodedInnerDetectedFriendly);

    private static bool HasAnyInstallerSignals(ReportView r)
        => !string.IsNullOrEmpty(r.InstallerKind) ||
           !string.IsNullOrEmpty(r.InstallerName) ||
           !string.IsNullOrEmpty(r.InstallerManufacturer) ||
           !string.IsNullOrEmpty(r.InstallerVersion) ||
           !string.IsNullOrEmpty(r.InstallerProductCode) ||
           !string.IsNullOrEmpty(r.InstallerUpgradeCode) ||
           !string.IsNullOrEmpty(r.InstallerScope) ||
           !string.IsNullOrEmpty(r.InstallerUrlInfoAbout) ||
           !string.IsNullOrEmpty(r.InstallerUrlUpdateInfo) ||
           !string.IsNullOrEmpty(r.InstallerHelpLink) ||
           !string.IsNullOrEmpty(r.InstallerSupportUrl) ||
           !string.IsNullOrEmpty(r.InstallerContact) ||
           !string.IsNullOrEmpty(r.InstallerCreated) ||
           !string.IsNullOrEmpty(r.InstallerLastSaved) ||
           r._MsiCAExe.HasValue ||
           r._MsiCADll.HasValue ||
           r._MsiCAScript.HasValue ||
           !string.IsNullOrEmpty(r._MsiCASamples);

    private static bool HasAnyScriptSignals(ReportView r)
        => !string.IsNullOrEmpty(r.ScriptLanguage) ||
           !string.IsNullOrEmpty(r.ScriptLanguageHuman) ||
           !string.IsNullOrEmpty(r.ScriptCmdlets);

    private static bool HasAnyReferenceSignals(ReportView r)
        => !string.IsNullOrEmpty(r.HtmlExternalLinksSample) ||
           !string.IsNullOrEmpty(r.HtmlUncSample) ||
           !string.IsNullOrEmpty(r.ScriptUrlsSample) ||
           !string.IsNullOrEmpty(r.ScriptUncSample) ||
           r.OfficeExternalLinksCount.HasValue ||
           !string.IsNullOrEmpty(r.HtmlExternalLinksFull) ||
           !string.IsNullOrEmpty(r.HtmlUncFull) ||
           !string.IsNullOrEmpty(r.ScriptUrlsFull) ||
           !string.IsNullOrEmpty(r.ScriptUncFull);

    private static bool HasAnySecuritySignals(ReportView r)
        => r.MotwZoneId.HasValue ||
           !string.IsNullOrEmpty(r.MotwReferrerUrl) ||
           !string.IsNullOrEmpty(r.MotwHostUrl) ||
           r.AlternateStreamCount.HasValue ||
           !string.IsNullOrEmpty(r.NameIssuesCsv) ||
           r.IsSymlink.HasValue ||
           r.IsHidden.HasValue ||
           r.IsReadOnly.HasValue ||
           !string.IsNullOrEmpty(r.Owner) ||
           !string.IsNullOrEmpty(r.ModeOctal) ||
           !string.IsNullOrEmpty(r.ModeSymbolic) ||
           r.IsExecutable.HasValue ||
           r.IsWorldWritable.HasValue ||
           r.EveryoneWriteAllowed.HasValue ||
           r.HasDenyEntries.HasValue;

    private static bool HasAnyPropertySignals(ReportView r)
        => (r.VersionInfo != null && r.VersionInfo.Count > 0) ||
           !string.IsNullOrEmpty(r.CompanyName) ||
           !string.IsNullOrEmpty(r.ProductName) ||
           !string.IsNullOrEmpty(r.FileDescription) ||
           !string.IsNullOrEmpty(r.FileVersion) ||
           !string.IsNullOrEmpty(r.ProductVersion) ||
           !string.IsNullOrEmpty(r.OriginalFilename);

    private static bool HasAnyAssessmentSignals(ReportView r)
        => r.AssessmentScore.HasValue ||
           !string.IsNullOrEmpty(r.AssessmentDecision) ||
           !string.IsNullOrEmpty(r.AssessmentDecisionStrict) ||
           !string.IsNullOrEmpty(r.AssessmentDecisionBalanced) ||
           !string.IsNullOrEmpty(r.AssessmentDecisionLenient) ||
           (r.AssessmentCodes != null && r.AssessmentCodes.Count > 0) ||
           (r.AssessmentFactors != null && r.AssessmentFactors.Count > 0) ||
           !string.IsNullOrEmpty(r.AssessmentCodesHuman) ||
           !string.IsNullOrEmpty(r.AssessmentCodesHumanLong);

    private static bool HasAnyArchiveSignals(ReportView r)
        => r.EncryptedEntryCount.HasValue ||
           r.ArchiveEntryCount.HasValue ||
           (r.ArchiveTopExtensions != null && r.ArchiveTopExtensions.Count > 0) ||
           r.InnerExecutablesSampled.HasValue ||
           r.InnerSignedExecutables.HasValue ||
           r.InnerValidSignedExecutables.HasValue ||
           !string.IsNullOrEmpty(r.InnerPublishersHuman) ||
           (r.InnerPublisherCounts != null && r.InnerPublisherCounts.Count > 0) ||
           (r.InnerPublisherValidCounts != null && r.InnerPublisherValidCounts.Count > 0) ||
           (r.InnerPublisherSelfSignedCounts != null && r.InnerPublisherSelfSignedCounts.Count > 0) ||
           (r.InnerExecutableExtCounts != null && r.InnerExecutableExtCounts.Count > 0) ||
           !string.IsNullOrWhiteSpace(r.InnerBinariesSummary) ||
           (r.ArchivePreview != null && r.ArchivePreview.Count > 0);

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
        if (DetectionReasonDetails != null) d["DetectionReasonDetails"] = DetectionReasonDetails;
        if (!string.IsNullOrEmpty(DetectionValidationStatus)) d["DetectionValidationStatus"] = DetectionValidationStatus;
        if (DetectionScore.HasValue) d["DetectionScore"] = DetectionScore.Value;
        if (DetectionIsDangerous.HasValue) d["DetectionIsDangerous"] = DetectionIsDangerous.Value;
        if (!string.IsNullOrEmpty(GuessedExtension)) d["GuessedExtension"] = GuessedExtension;
        if (!string.IsNullOrEmpty(ContainerSubtype)) d["ContainerSubtype"] = ContainerSubtype;
        if (!string.IsNullOrEmpty(TextSubtype)) d["TextSubtype"] = TextSubtype;
        if (EstimatedLineCount.HasValue) d["EstimatedLineCount"] = EstimatedLineCount.Value;
        if (!string.IsNullOrEmpty(PeMachine)) d["PeMachine"] = PeMachine;
        if (!string.IsNullOrEmpty(PeSubsystem)) d["PeSubsystem"] = PeSubsystem;
        if (!string.IsNullOrEmpty(PeKind)) d["PeKind"] = PeKind;
        if (DetectionAlternatives != null && DetectionAlternatives.Count > 0) d["DetectionAlternatives"] = DetectionAlternatives;
        if (DetectionCandidates != null && DetectionCandidates.Count > 0) d["DetectionCandidates"] = DetectionCandidates;
        if (!string.IsNullOrEmpty(EncodedKind)) d["EncodedKind"] = EncodedKind;
        if (!string.IsNullOrEmpty(EncodedInnerDetectedExtension)) d["EncodedInnerDetectedExtension"] = EncodedInnerDetectedExtension;
        if (!string.IsNullOrEmpty(EncodedInnerDetectedName)) d["EncodedInnerDetectedName"] = EncodedInnerDetectedName;
        if (!string.IsNullOrEmpty(EncodedInnerDetectedFriendly)) d["EncodedInnerDetectedFriendly"] = EncodedInnerDetectedFriendly;
        if (AuthenticodePresent.HasValue) d["AuthenticodePresent"] = AuthenticodePresent.Value;
        if (AuthenticodeChainValid.HasValue) d["AuthenticodeChainValid"] = AuthenticodeChainValid.Value;
        if (AuthenticodeTimestampPresent.HasValue) d["AuthenticodeTimestampPresent"] = AuthenticodeTimestampPresent.Value;
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
        if (SignatureIsSigned.HasValue) d["SignatureIsSigned"] = SignatureIsSigned.Value;
        if (AssessmentScore.HasValue) d["AssessmentScore"] = AssessmentScore.Value;
        if (!string.IsNullOrEmpty(AssessmentDecision)) d["AssessmentDecision"] = AssessmentDecision;
        if (!string.IsNullOrEmpty(AssessmentDecisionStrict)) d["AssessmentDecisionStrict"] = AssessmentDecisionStrict;
        if (!string.IsNullOrEmpty(AssessmentDecisionBalanced)) d["AssessmentDecisionBalanced"] = AssessmentDecisionBalanced;
        if (!string.IsNullOrEmpty(AssessmentDecisionLenient)) d["AssessmentDecisionLenient"] = AssessmentDecisionLenient;
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
        if (!string.IsNullOrEmpty(InstallerCreated)) d["InstallerCreated"] = InstallerCreated;
        if (!string.IsNullOrEmpty(InstallerLastSaved)) d["InstallerLastSaved"] = InstallerLastSaved;
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
        if (TopTokens != null && TopTokens.Count > 0) d["TopTokens"] = TopTokens;
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
        if (InnerExecutableExtCounts != null && InnerExecutableExtCounts.Count > 0) d["InnerExecutableExtCounts"] = InnerExecutableExtCounts;
        // Reference samples
        if (!string.IsNullOrEmpty(HtmlExternalLinksSample)) d["HtmlExternalLinksSample"] = HtmlExternalLinksSample;
        if (!string.IsNullOrEmpty(HtmlUncSample)) d["HtmlUncSample"] = HtmlUncSample;
        if (!string.IsNullOrEmpty(ScriptUrlsSample)) d["ScriptUrlsSample"] = ScriptUrlsSample;
        if (!string.IsNullOrEmpty(ScriptUncSample)) d["ScriptUncSample"] = ScriptUncSample;
        if (OfficeExternalLinksCount.HasValue) d["OfficeExternalLinksCount"] = OfficeExternalLinksCount.Value;
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
        if (!string.IsNullOrEmpty(NameIssuesCsv)) d["NameIssues"] = NameIssuesCsv;
        if (IsSymlink.HasValue) d["IsSymlink"] = IsSymlink.Value;
        if (IsHidden.HasValue) d["IsHidden"] = IsHidden.Value;
        if (IsReadOnly.HasValue) d["IsReadOnly"] = IsReadOnly.Value;
        if (!string.IsNullOrEmpty(Owner)) d["Owner"] = Owner;
        if (!string.IsNullOrEmpty(ModeOctal)) d["ModeOctal"] = ModeOctal;
        if (!string.IsNullOrEmpty(ModeSymbolic)) d["ModeSymbolic"] = ModeSymbolic;
        if (IsExecutable.HasValue) d["IsExecutable"] = IsExecutable.Value;
        if (IsWorldWritable.HasValue) d["IsWorldWritable"] = IsWorldWritable.Value;
        if (EveryoneWriteAllowed.HasValue) d["EveryoneWriteAllowed"] = EveryoneWriteAllowed.Value;
        if (HasDenyEntries.HasValue) d["HasDenyEntries"] = HasDenyEntries.Value;
        // Secrets
        if (SecretsPrivateKeyCount.HasValue) d["SecretsPrivateKeyCount"] = SecretsPrivateKeyCount.Value;
        if (SecretsJwtLikeCount.HasValue) d["SecretsJwtLikeCount"] = SecretsJwtLikeCount.Value;
        if (SecretsKeyPatternCount.HasValue) d["SecretsKeyPatternCount"] = SecretsKeyPatternCount.Value;
        if (SecretsTokenFamilyCount.HasValue) d["SecretsTokenFamilyCount"] = SecretsTokenFamilyCount.Value;
        if (SecretsGitHubTokenCount.HasValue) d["SecretsGitHubTokenCount"] = SecretsGitHubTokenCount.Value;
        if (SecretsGitLabTokenCount.HasValue) d["SecretsGitLabTokenCount"] = SecretsGitLabTokenCount.Value;
        if (SecretsAwsAccessKeyIdCount.HasValue) d["SecretsAwsAccessKeyIdCount"] = SecretsAwsAccessKeyIdCount.Value;
        if (SecretsSlackTokenCount.HasValue) d["SecretsSlackTokenCount"] = SecretsSlackTokenCount.Value;
        if (SecretsStripeLiveKeyCount.HasValue) d["SecretsStripeLiveKeyCount"] = SecretsStripeLiveKeyCount.Value;
        if (SecretsGcpApiKeyCount.HasValue) d["SecretsGcpApiKeyCount"] = SecretsGcpApiKeyCount.Value;
        if (SecretsNpmTokenCount.HasValue) d["SecretsNpmTokenCount"] = SecretsNpmTokenCount.Value;
        if (SecretsAzureSasTokenCount.HasValue) d["SecretsAzureSasTokenCount"] = SecretsAzureSasTokenCount.Value;
        if (SecretsFindings != null && SecretsFindings.Count > 0) d["SecretsFindings"] = SecretsFindings;
        if (Advice != null)
        {
            d["Advice"] = new Dictionary<string, object?>
            {
                ["ShowTypeAnalysis"] = Advice.ShowTypeAnalysis,
                ["ShowProperties"] = Advice.ShowProperties,
                ["ShowSignature"] = Advice.ShowSignature,
                ["ShowSecurity"] = Advice.ShowSecurity,
                ["ShowScript"] = Advice.ShowScript,
                ["ShowReferences"] = Advice.ShowReferences,
                ["ShowInstaller"] = Advice.ShowInstaller,
                ["ShowAssessment"] = Advice.ShowAssessment,
                ["ShowHeuristics"] = Advice.ShowHeuristics,
                ["ShowArchiveDetails"] = Advice.ShowArchiveDetails,
                ["ShowScan"] = Advice.ShowScan
            };
        }
        if (CompactFields != null && CompactFields.Count > 0) d["Compact"] = CompactFields;
        return d;
    }

    private static string FormatNameIssuesCsv(NameIssues issues)
    {
        var parts = new List<string>(5);
        if ((issues & NameIssues.DoubleExtension) != 0) parts.Add("double-extension");
        if ((issues & NameIssues.BiDiOverride) != 0) parts.Add("bidi-override");
        if ((issues & NameIssues.SuspiciousWhitespace) != 0) parts.Add("suspicious-whitespace");
        if ((issues & NameIssues.LeadingDotHidden) != 0) parts.Add("leading-dot-hidden");
        if ((issues & NameIssues.ExtensionMismatch) != 0) parts.Add("extension-mismatch");
        return string.Join(",", parts);
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
    /// <summary>Include file security metadata section (MOTW / alternate streams).</summary>
    public bool ShowSecurity { get; set; }
    /// <summary>Include script section when a script language is detected.</summary>
    public bool ShowScript { get; set; }
    /// <summary>Include references section when HTML or script URLs/UNC paths are present.</summary>
    public bool ShowReferences { get; set; }
    /// <summary>Include installer/package section when installer metadata is available.</summary>
    public bool ShowInstaller { get; set; }
    /// <summary>Include risk assessment section (score, decision, findings).</summary>
    public bool ShowAssessment { get; set; }
    /// <summary>Include heuristics section (security findings, inner findings).</summary>
    public bool ShowHeuristics { get; set; }
    /// <summary>Include archive details when available (e.g., encrypted entry count).</summary>
    public bool ShowArchiveDetails { get; set; }
    /// <summary>Host-controlled: show scan results (VT/Defender) when enabled.</summary>
    public bool ShowScan { get; set; }
}
