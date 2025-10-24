namespace FileInspectorX;

/// <summary>
/// High-level analysis describing file type, risk flags, metadata and container hints.
/// Produced by <see cref="FileInspector.Analyze(string, FileInspector.DetectionOptions?)"/>.
/// </summary>
public class FileAnalysis {
    /// <summary>Result of magic/heuristic content type detection.</summary>
    public ContentTypeDetectionResult? Detection { get; set; }
    /// <summary>Broad content category derived from <see cref="Detection"/>.</summary>
    public ContentKind Kind { get; set; } = ContentKind.Unknown;
    /// <summary>Bitmask of analysis signals collected for this file.</summary>
    public ContentFlags Flags { get; set; } = ContentFlags.None;

    // Optional hints
    /// <summary>Best-guess extension when detection is ambiguous (e.g., container subtype).</summary>
    public string? GuessedExtension { get; set; }
    /// <summary>Subtype hint for containers (e.g., jar/apk/epub inside ZIP).</summary>
    public string? ContainerSubtype { get; set; }
    /// <summary>Script language inferred from shebang or structure (e.g., powershell, bash).</summary>
    public string? ScriptLanguage { get; set; }

    // PE triage hints
    /// <summary>CPU architecture string for PE files (e.g., x86, x64, ARM).</summary>
    public string? PeMachine { get; set; }
    /// <summary>Subsystem string for PE files (e.g., Windows GUI, CUI).</summary>
    public string? PeSubsystem { get; set; }

    // Container summary (ZIP/TAR)
    /// <summary>Number of entries sampled inside the container.</summary>
    public int? ContainerEntryCount { get; set; }
    /// <summary>Top N extensions encountered inside the container (ordered by frequency).</summary>
    public IReadOnlyList<string>? ContainerTopExtensions { get; set; }

    /// <summary>Version or metadata key/value pairs, when available (e.g., PE/FVI, package manifests).</summary>
    public IReadOnlyDictionary<string, string>? VersionInfo { get; set; }

    /// <summary>Quick summary of signing data availability and certificate table size (lightweight).</summary>
    public SignatureSummary? Signature { get; set; }

    // Text-specific hints
    /// <summary>Estimated number of lines for delimited text (CSV/TSV) based on sample.</summary>
    public int? EstimatedLineCount { get; set; }
    /// <summary>Text subtype such as json, yaml, markdown, log.</summary>
    public string? TextSubtype { get; set; }

    /// <summary>
    /// Security-relevant findings detected by lightweight script/content heuristics.
    /// Elements are short codes like "ps:iex", "ps:encoded", "py:exec-b64", "sig:mkatz".
    /// No raw malware names or signatures are emitted to avoid AV heuristics.
    /// </summary>
    public IReadOnlyList<string>? SecurityFindings { get; set; }

    /// <summary>
    /// Normalized file permission/ownership snapshot (best-effort cross-platform).
    /// </summary>
    public FileSecurity? Security { get; set; }

    /// <summary>
    /// Windows PE Authenticode signature summary (when present). Cross-platform, best-effort parsing.
    /// </summary>
    public AuthenticodeInfo? Authenticode { get; set; }

    /// <summary>
    /// Structured references extracted from the file's content (e.g., command targets from Task Scheduler XML,
    /// GPO scripts lists, URLs). Kept generic to support diverse configuration formats.
    /// </summary>
    public IReadOnlyList<Reference>? References { get; set; }

    /// <summary>
    /// Suspicious traits of the file name/path (generic; library-agnostic; see <see cref="NameIssues"/>).
    /// </summary>
    public NameIssues NameIssues { get; set; } = NameIssues.None;

    /// <summary>
    /// When the file is or contains a recognizable installer/package, basic metadata is exposed here.
    /// </summary>
    public InstallerInfo? Installer { get; set; }

    /// <summary>
    /// Optional computed assessment (score/decision/codes) when requested.
    /// </summary>
    public AssessmentResult? Assessment { get; set; }
    /// <summary>
    /// Counts of generic secret indicators discovered in text/script content, when enabled.
    /// </summary>
    public SecretsSummary? Secrets { get; set; }

    /// <summary>
    /// Number of external link definitions detected in OOXML Excel documents (xl/externalLinks/* or workbook rels). Null when not applicable.
    /// </summary>
    public int? OfficeExternalLinksCount { get; set; }

    /// <summary>
    /// Number of encrypted entries detected inside a ZIP container (central directory flags or AES extra field). Null when not applicable.
    /// </summary>
    public int? EncryptedEntryCount { get; set; }
    /// <summary>
    /// Per-entry indicators collected during deep container scan (bounded).
    /// </summary>
    public IReadOnlyList<string>? InnerFindings { get; set; }

    // Inner archive signer summary (from sampled executables inside ZIP/TAR when deep scan is enabled)
    /// <summary>
    /// Preview of notable inner entries found inside an archive (e.g., top executables). Bounded and sampling-based.
    /// </summary>
    public IReadOnlyList<InnerEntryPreview>? ArchivePreviewEntries { get; set; }

    /// <summary>Total inner executables sampled during deep scan.</summary>
    public int? InnerExecutablesSampled { get; set; }
    /// <summary>Number of sampled inner executables that were Authenticode signed.</summary>
    public int? InnerSignedExecutables { get; set; }
    /// <summary>Number of sampled inner executables with a valid chain or trusted WinVerifyTrust policy.</summary>
    public int? InnerValidSignedExecutables { get; set; }
    /// <summary>Counts by publisher (SignerSubjectCN when available) among signed inner executables.</summary>
    public IReadOnlyDictionary<string,int>? InnerPublisherCounts { get; set; }
}

/// <summary>
/// Lightweight description of an inner archive entry for preview purposes.
/// </summary>
public sealed class InnerEntryPreview {
    /// <summary>Entry name or path within the container.</summary>
    public string Name { get; set; } = string.Empty;
    /// <summary>Detected type extension when sampled (e.g., exe, dll), if available.</summary>
    public string? DetectedExtension { get; set; }
}
