namespace FileInspectorX;

/// <summary>
/// High-level analysis describing file type, risk flags, metadata and container hints.
/// Produced by <see cref="FileInspector.Analyze(string, FileInspector.DetectionOptions?)"/>.
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

    // Container summary (ZIP/TAR)
    public int? ContainerEntryCount { get; set; }
    public IReadOnlyList<string>? ContainerTopExtensions { get; set; }

    public IReadOnlyDictionary<string, string>? VersionInfo { get; set; }

    public SignatureSummary? Signature { get; set; }
}

