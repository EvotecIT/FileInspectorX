namespace FileInspectorX;

/// <summary>
/// Flattened Windows shell properties (Explorer Details) for tabular display.
/// </summary>
public sealed class ShellPropertiesView
{
    /// <summary>File path.</summary>
    public string Path { get; set; } = string.Empty;
    /// <summary>Display property name (localized).</summary>
    public string Property { get; set; } = string.Empty;
    /// <summary>Property value (formatted).</summary>
    public string? Value { get; set; }
    /// <summary>Canonical property name (e.g., System.Music.InitialKey).</summary>
    public string? CanonicalName { get; set; }
    /// <summary>Variant type name (e.g., VT_LPWSTR, VT_VECTOR|VT_LPWSTR).</summary>
    public string? ValueType { get; set; }
    /// <summary>Raw property key in fmtid:pid format.</summary>
    public string? Key { get; set; }
    /// <summary>The full analysis object for deep inspection.</summary>
    public FileAnalysis? Raw { get; set; }

    internal static IEnumerable<ShellPropertiesView> From(string path, IReadOnlyList<ShellProperty>? props)
    {
        if (props == null || props.Count == 0) yield break;
        foreach (var p in props)
        {
            yield return new ShellPropertiesView
            {
                Path = path,
                Property = p.DisplayName ?? p.CanonicalName ?? p.Key ?? string.Empty,
                Value = p.Value,
                CanonicalName = p.CanonicalName,
                ValueType = p.ValueType,
                Key = p.Key
            };
        }
    }
}
