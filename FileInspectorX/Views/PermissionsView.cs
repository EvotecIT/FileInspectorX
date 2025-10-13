namespace FileInspectorX;

/// <summary>
/// Flattened permissions/ownership view for display.
/// </summary>
/// <summary>Flattened permissions/ownership view for display.</summary>
public sealed class PermissionsView
{
    /// <summary>File path.</summary>
    public string Path { get; set; } = string.Empty;

    // Generic
    /// <summary>True if file is a symbolic link.</summary>
    public bool? IsSymlink { get; set; }
    /// <summary>True if file has hidden attribute (Windows) or leading dot (Unix; best-effort).</summary>
    public bool? IsHidden { get; set; }
    /// <summary>True if file is read-only.</summary>
    public bool? IsReadOnly { get; set; }

    // Ownership
    /// <summary>Owner name (friendly).</summary>
    public string? Owner { get; set; }
    /// <summary>Owner ID (SID on Windows; uid on Unix).</summary>
    public string? OwnerId { get; set; }
    /// <summary>Group name (friendly; Unix or Windows primary group).</summary>
    public string? Group { get; set; }
    /// <summary>Group ID (gid on Unix; SID on Windows).</summary>
    public string? GroupId { get; set; }

    // Permissions
    /// <summary>Unix mode in octal (e.g., 0755).</summary>
    public string? ModeOctal { get; set; }
    /// <summary>Unix mode in symbolic form (e.g., rwxr-xr-x).</summary>
    public string? ModeSymbolic { get; set; }
    /// <summary>True if any execute bit set (Unix) or inferred.</summary>
    public bool? IsExecutable { get; set; }
    /// <summary>True if world-writable (Unix).</summary>
    public bool? IsWorldWritable { get; set; }
    /// <summary>Windows: Everyone has write permissions.</summary>
    public bool? EveryoneWriteAllowed { get; set; }
    /// <summary>Windows: Authenticated Users have write permissions.</summary>
    public bool? AuthenticatedUsersWriteAllowed { get; set; }
    /// <summary>Windows: Everyone has read permissions.</summary>
    public bool? EveryoneReadAllowed { get; set; }
    /// <summary>Windows: BUILTIN\\Users have write permissions.</summary>
    public bool? BuiltinUsersWriteAllowed { get; set; }
    /// <summary>Windows: BUILTIN\\Users have read permissions.</summary>
    public bool? BuiltinUsersReadAllowed { get; set; }
    /// <summary>Windows: BUILTIN\\Administrators have write permissions.</summary>
    public bool? AdministratorsWriteAllowed { get; set; }
    /// <summary>Windows: BUILTIN\\Administrators have read permissions.</summary>
    public bool? AdministratorsReadAllowed { get; set; }
    /// <summary>Windows: True when explicit deny ACE(s) are present.</summary>
    public bool? HasDenyEntries { get; set; }
    /// <summary>Windows: Total allow ACEs.</summary>
    public int? TotalAllowCount { get; set; }
    /// <summary>Windows: Total deny ACEs.</summary>
    public int? TotalDenyCount { get; set; }
    /// <summary>Windows: Explicit (non-inherited) allow ACEs.</summary>
    public int? ExplicitAllowCount { get; set; }
    /// <summary>Windows: Explicit (non-inherited) deny ACEs.</summary>
    public int? ExplicitDenyCount { get; set; }
    /// <summary>The full analysis object for deep inspection.</summary>
    public FileAnalysis? Raw { get; set; }

    public static PermissionsView From(string path, FileSecurity? s) => new PermissionsView {
        Path = path,
        IsSymlink = s?.IsSymlink,
        IsHidden = s?.IsHidden,
        IsReadOnly = s?.IsReadOnly,
        Owner = s?.Owner,
        OwnerId = s?.OwnerId,
        Group = s?.Group,
        GroupId = s?.GroupId,
        ModeOctal = s?.ModeOctal,
        ModeSymbolic = s?.ModeSymbolic,
        IsExecutable = s?.IsExecutable,
        IsWorldWritable = s?.IsWorldWritable,
        EveryoneWriteAllowed = s?.EveryoneWriteAllowed,
        AuthenticatedUsersWriteAllowed = s?.AuthenticatedUsersWriteAllowed,
        EveryoneReadAllowed = s?.EveryoneReadAllowed,
        BuiltinUsersWriteAllowed = s?.BuiltinUsersWriteAllowed,
        BuiltinUsersReadAllowed = s?.BuiltinUsersReadAllowed,
        AdministratorsWriteAllowed = s?.AdministratorsWriteAllowed,
        AdministratorsReadAllowed = s?.AdministratorsReadAllowed,
        HasDenyEntries = s?.HasDenyEntries,
        TotalAllowCount = s?.TotalAllowCount,
        TotalDenyCount = s?.TotalDenyCount,
        ExplicitAllowCount = s?.ExplicitAllowCount,
        ExplicitDenyCount = s?.ExplicitDenyCount,
        Raw = null
    };
}
