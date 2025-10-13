namespace FileInspectorX;

/// <summary>
/// Flattened projection of <see cref="Reference"/> entries for display/logging.
/// </summary>
public sealed class ReferencesView
{
    /// <summary>File path.</summary>
    public string Path { get; set; } = string.Empty;
    /// <summary>Kind/category of the extracted reference.</summary>
    public ReferenceKind Kind { get; set; }
    /// <summary>Raw value of the reference as found in the file.</summary>
    public string Value { get; set; } = string.Empty;
    /// <summary>Expanded/normalized form of the reference (e.g., environment expansion).</summary>
    public string? ExpandedValue { get; set; }
    /// <summary>Whether the referenced path/URL appears to exist.</summary>
    public bool? Exists { get; set; }
    /// <summary>Issues found with this reference (e.g., absolute path).</summary>
    public ReferenceIssue Issues { get; set; }
    /// <summary>Source tag indicating where it was found (e.g., Task XML element).</summary>
    public string? Source { get; set; }
    /// <summary>The full analysis object for deep inspection.</summary>
    public FileAnalysis? Raw { get; set; }

    internal static IEnumerable<ReferencesView> From(string path, IReadOnlyList<Reference>? refs)
    {
        if (refs is null || refs.Count == 0) yield break;
        foreach (var r in refs)
        {
            yield return new ReferencesView
            {
                Path = path,
                Kind = r.Kind,
                Value = r.Value,
                ExpandedValue = r.ExpandedValue,
                Exists = r.Exists,
                Issues = r.Issues,
                Source = r.SourceTag,
                Raw = null
            };
        }
    }
}
