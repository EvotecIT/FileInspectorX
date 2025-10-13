namespace FileInspectorX;

/// <summary>
/// Flattened projection of <see cref="Reference"/> entries for display/logging.
/// </summary>
public sealed class ReferencesView
{
    public string Path { get; set; } = string.Empty;
    public ReferenceKind Kind { get; set; }
    public string Value { get; set; } = string.Empty;
    public string? ExpandedValue { get; set; }
    public bool? Exists { get; set; }
    public ReferenceIssue Issues { get; set; }
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
