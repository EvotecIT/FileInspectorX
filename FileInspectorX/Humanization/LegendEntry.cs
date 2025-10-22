namespace FileInspectorX;

/// <summary>
/// Describes a single legend entry used to humanize analysis signals or heuristic codes.
/// </summary>
public sealed class LegendEntry
{
    /// <summary>Stable code (e.g., "Macros", "ZipEnc", "ps:encoded").</summary>
    public string Code { get; }
    /// <summary>Short label, compact for inline displays.</summary>
    public string Short { get; }
    /// <summary>Long description, suitable for legends and tooltips.</summary>
    public string Long { get; }
    /// <summary>Optional category grouping (e.g., "PDF", "OOXML", "Archive", "Script").</summary>
    public string? Category { get; }
    /// <summary>Optional rough severity (0–100) for ordering; neutral when null.</summary>
    public int? Severity { get; }

    /// <summary>Create a new legend entry.</summary>
    public LegendEntry(string code, string @short, string @long, string? category = null, int? severity = null)
    {
        Code = code; Short = @short; Long = @long; Category = category; Severity = severity;
    }
}

/// <summary>
/// Presentation style for humanizing lists.
/// </summary>
/// <summary>
/// Output verbosity for humanized text.
/// </summary>
public enum HumanizeStyle {
    /// <summary>Concise labels for inline displays (e.g., lists, tables).</summary>
    Short,
    /// <summary>Descriptive labels for legends/tooltips (full sentences).</summary>
    Long
}
