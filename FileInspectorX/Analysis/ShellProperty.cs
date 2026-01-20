namespace FileInspectorX;

/// <summary>
/// Single Windows shell property (Explorer Details) entry.
/// </summary>
public sealed class ShellProperty
{
    /// <summary>Localized display name (e.g., "Initial key").</summary>
    public string? DisplayName { get; set; }
    /// <summary>Canonical property name (e.g., "System.Music.InitialKey").</summary>
    public string? CanonicalName { get; set; }
    /// <summary>Property value formatted for display.</summary>
    public string? Value { get; set; }
    /// <summary>Variant type name (e.g., VT_LPWSTR, VT_VECTOR|VT_LPWSTR).</summary>
    public string? ValueType { get; set; }
    /// <summary>Raw property key in fmtid:pid format.</summary>
    public string? Key { get; set; }
}

/// <summary>
/// Options controlling how Windows shell properties are read.
/// </summary>
public sealed class ShellPropertiesOptions
{
    /// <summary>Include entries with empty/whitespace values. Default false.</summary>
    public bool IncludeEmpty { get; set; } = false;
}
