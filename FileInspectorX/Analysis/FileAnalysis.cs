namespace FileInspectorX;

/// <summary>
/// High-level analysis describing file type, risk flags, metadata and container hints.
/// Produced by <see cref="FileInspector.Analyze(string, FileInspector.DetectionOptions?)"/>.
/// </summary>
public class FileAnalysis {
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

    // Container summary (ZIP/TAR)
    public int? ContainerEntryCount { get; set; }
    public IReadOnlyList<string>? ContainerTopExtensions { get; set; }

    public IReadOnlyDictionary<string, string>? VersionInfo { get; set; }

    public SignatureSummary? Signature { get; set; }

    // Text-specific hints
    public int? EstimatedLineCount { get; set; }
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
}
