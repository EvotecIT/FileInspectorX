namespace FileInspectorX;

/// <summary>
/// Bundled analysis plus file metadata and a flattened metadata dictionary.
/// </summary>
public sealed class FileInspectionSummary
{
    /// <summary>Full analysis result.</summary>
    public FileAnalysis Analysis { get; set; } = new FileAnalysis();
    /// <summary>Report view derived from the analysis.</summary>
    public ReportView Report { get; set; } = new ReportView();
    /// <summary>File system metadata captured for the file.</summary>
    public FileSystemMetadata? FileMetadata { get; set; }
    /// <summary>Flattened metadata dictionary (file info + report fields).</summary>
    public IReadOnlyDictionary<string, object?> Metadata { get; set; } =
        new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
}
