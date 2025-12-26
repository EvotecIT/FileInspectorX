namespace FileInspectorX;

/// <summary>
/// Flattened analysis summary tailored for tabular display.
/// </summary>
public sealed class AnalysisView
{
    /// <summary>File path.</summary>
    public string Path { get; set; } = string.Empty;
    /// <summary>Detected extension.</summary>
    public string Extension { get; set; } = string.Empty;
    /// <summary>Detected MIME type.</summary>
    public string MimeType { get; set; } = string.Empty;
    /// <summary>High-level kind classification.</summary>
    public ContentKind Kind { get; set; } = ContentKind.Unknown;
    /// <summary>Bit flags with analysis signals.</summary>
    public ContentFlags Flags { get; set; } = ContentFlags.None;
    /// <summary>Best-guess extension when ambiguous.</summary>
    public string? GuessedExtension { get; set; }

    // Container
    /// <summary>Detected container subtype (e.g., jar/apk/epub).</summary>
    public string? ContainerSubtype { get; set; }
    /// <summary>Number of entries in container (when sampled).</summary>
    public int? ContainerEntryCount { get; set; }
    /// <summary>Top extensions found within the container.</summary>
    public IReadOnlyList<string>? ContainerTopExtensions { get; set; }

    // Text
    /// <summary>Subtype for text-like files (e.g., json,yaml,markdown).</summary>
    public string? TextSubtype { get; set; }
    /// <summary>Estimated line count for text-like files.</summary>
    public int? EstimatedLineCount { get; set; }
    /// <summary>Script language from shebang.</summary>
    public string? ScriptLanguage { get; set; }
    /// <summary>Neutral security finding codes for scripts.</summary>
    public IReadOnlyList<string>? SecurityFindings { get; set; }
    /// <summary>Top tokens extracted from script/log content when enabled.</summary>
    public IReadOnlyList<string>? TopTokens { get; set; }

    // PE quick
    /// <summary>PE machine (x86/x64/etc.).</summary>
    public string? PeMachine { get; set; }
    /// <summary>PE subsystem (GUI/CUI/etc.).</summary>
    public string? PeSubsystem { get; set; }

    // Signature quick
    /// <summary>True when Authenticode is present.</summary>
    public bool? Authenticode { get; set; }
    /// <summary>True when chain built to a trusted root.</summary>
    public bool? AuthChainValid { get; set; }
    /// <summary>True when a timestamp countersignature is present.</summary>
    public bool? AuthTimestamp { get; set; }
    /// <summary>The full analysis object for deep inspection.</summary>
    public FileAnalysis? Raw { get; set; }

    /// <summary>
    /// Creates an <see cref="AnalysisView"/> from a <see cref="FileAnalysis"/>.
    /// </summary>
    public static AnalysisView From(string path, FileAnalysis a) => new AnalysisView {
        Path = path,
        Extension = a.Detection?.Extension ?? string.Empty,
        MimeType = a.Detection?.MimeType ?? string.Empty,
        Kind = a.Kind,
        Flags = a.Flags,
        GuessedExtension = a.GuessedExtension,
        ContainerSubtype = a.ContainerSubtype,
        ContainerEntryCount = a.ContainerEntryCount,
        ContainerTopExtensions = a.ContainerTopExtensions,
        TextSubtype = a.TextSubtype,
        EstimatedLineCount = a.EstimatedLineCount,
        ScriptLanguage = a.ScriptLanguage,
        SecurityFindings = a.SecurityFindings,
        TopTokens = a.TopTokens,
        PeMachine = a.PeMachine,
        PeSubsystem = a.PeSubsystem,
        Authenticode = a.Authenticode?.Present,
        AuthChainValid = a.Authenticode?.ChainValid,
        AuthTimestamp = a.Authenticode?.TimestampPresent,
        Raw = a
    };
}
