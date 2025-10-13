namespace FileInspectorX;

/// <summary>
/// Describes a reference found inside a file's content, such as a command target in a Task Scheduler XML,
/// a script path in a GPO scripts INI, a URL, or a registry path. Library-agnostic to remain broadly useful.
/// </summary>
public sealed class Reference
{
    /// <summary>Kind of the reference (file path, URL, command text, environment variable, registry path, CLSID).</summary>
    public ReferenceKind Kind { get; set; }

    /// <summary>Raw value as found in the source (e.g., Command attribute or INI value).</summary>
    public string Value { get; set; } = string.Empty;

    /// <summary>Expanded value when applicable (e.g., %SystemRoot% expanded), or null if not expanded.</summary>
    public string? ExpandedValue { get; set; }

    /// <summary>True if the expanded value points to an existing file on the current machine.</summary>
    public bool? Exists { get; set; }

    /// <summary>Issues detected for this reference (unquoted path with spaces, UNC path, relative path, etc.).</summary>
    public ReferenceIssue Issues { get; set; } = ReferenceIssue.None;

    /// <summary>Optional short tag indicating the source feature (e.g., "task:exec", "gpo:scripts.ini").</summary>
    public string? SourceTag { get; set; }
}

/// <summary>
/// Classifies the type of a reference extracted from content.
/// </summary>
public enum ReferenceKind
{
    /// <summary>File system path (may be relative, absolute or UNC).</summary>
    FilePath = 0,
    /// <summary>HTTP/HTTPS URL.</summary>
    Url = 1,
    /// <summary>Opaque command-line text (tokenization attempted when applicable).</summary>
    Command = 2,
    /// <summary>Environment variable reference (e.g., %SystemRoot%).</summary>
    EnvVar = 3,
    /// <summary>Windows registry path.</summary>
    RegistryPath = 4,
    /// <summary>COM class or handler CLSID.</summary>
    Clsid = 5
}

/// <summary>
/// Flags describing potential problems in a reference value.
/// </summary>
[System.Flags]
public enum ReferenceIssue
{
    /// <summary>No issues detected.</summary>
    None = 0,
    /// <summary>Path contains spaces and is unquoted in a command line.</summary>
    UnquotedPathWithSpaces = 1 << 0,
    /// <summary>Reference uses a UNC path.</summary>
    UncPath = 1 << 1,
    /// <summary>Reference is an absolute path to a different drive or root.</summary>
    AbsolutePath = 1 << 2,
    /// <summary>Reference is a relative path (may resolve unexpectedly depending on working directory).</summary>
    RelativePath = 1 << 3,
    /// <summary>Reference points to a directory considered insecure (e.g., world-writable temp).</summary>
    InsecureDirectory = 1 << 4,
    /// <summary>Environment variables present and unresolved (no expansion performed).</summary>
    ContainsEnvVars = 1 << 5
}
