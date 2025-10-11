namespace FileInspectorX;

/// <summary>
/// Very compact, tabular-friendly view with the most important columns.
/// </summary>
public sealed class SummaryView
{
    /// <summary>File path.</summary>
    public string Path { get; set; } = string.Empty;
    /// <summary>High-level kind classification.</summary>
    public ContentKind Kind { get; set; } = ContentKind.Unknown;
    /// <summary>Detected extension.</summary>
    public string Extension { get; set; } = string.Empty;
    /// <summary>Detected MIME type.</summary>
    public string MimeType { get; set; } = string.Empty;
    /// <summary>Confidence level.</summary>
    public string Confidence { get; set; } = string.Empty;
    /// <summary>Short reason for detection.</summary>
    public string Reason { get; set; } = string.Empty;
    /// <summary>Bit flags with analysis signals.</summary>
    public ContentFlags Flags { get; set; } = ContentFlags.None;

    public static SummaryView From(string path, FileAnalysis a)
    {
        var d = a.Detection;
        return new SummaryView {
            Path = path,
            Kind = a.Kind,
            Extension = d?.Extension ?? string.Empty,
            MimeType = d?.MimeType ?? string.Empty,
            Confidence = d?.Confidence ?? string.Empty,
            Reason = d?.Reason ?? string.Empty,
            Flags = a.Flags
        };
    }
}
