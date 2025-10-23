namespace FileInspectorX;

/// <summary>
/// Cross-platform file security/permission snapshot with a normalized shape.
/// Values may be null when not available on the current platform/TFM.
/// </summary>
public sealed class FileSecurity
{
    // Generic
    /// <summary>True if file is a symbolic link (best-effort across platforms).</summary>
    public bool? IsSymlink { get; set; }
    /// <summary>True if file is hidden (Windows attribute or path conventions).</summary>
    public bool? IsHidden { get; set; }
    /// <summary>True if file is read-only.</summary>
    public bool? IsReadOnly { get; set; }

    // Ownership (best-effort)
    /// <summary>Owner display name (Windows: DOMAIN\User; Unix: user name).</summary>
    public string? Owner { get; set; }
    /// <summary>Owner ID (Windows: SID; Unix: uid).</summary>
    public string? OwnerId { get; set; }
    /// <summary>Group display name (Unix group or Windows primary group).</summary>
    public string? Group { get; set; }
    /// <summary>Group ID (gid on Unix; SID on Windows).</summary>
    public string? GroupId { get; set; }

    // Permissions summary
    /// <summary>Unix mode in octal (e.g., 0755).</summary>
    public string? ModeOctal { get; set; }
    /// <summary>Unix mode in symbolic form (e.g., rwxr-xr-x).</summary>
    public string? ModeSymbolic { get; set; }
    /// <summary>True if any execute bit set (Unix) or inferred.</summary>
    public bool? IsExecutable { get; set; }
    /// <summary>True if world-writable (Unix others write bit).</summary>
    public bool? IsWorldWritable { get; set; }

    // Windows ACL quick checks (best-effort summaries)
    /// <summary>Windows: Everyone has write permissions (allow rules).</summary>
    public bool? EveryoneWriteAllowed { get; set; }
    /// <summary>Windows: Authenticated Users have write permissions (allow rules).</summary>
    public bool? AuthenticatedUsersWriteAllowed { get; set; }

    /// <summary>Windows: Everyone has read permissions (allow rules).</summary>
    public bool? EveryoneReadAllowed { get; set; }
    /// <summary>Windows: BUILTIN\\Users have write permissions (allow rules).</summary>
    public bool? BuiltinUsersWriteAllowed { get; set; }
    /// <summary>Windows: BUILTIN\\Users have read permissions (allow rules).</summary>
    public bool? BuiltinUsersReadAllowed { get; set; }
    /// <summary>Windows: BUILTIN\\Administrators have write permissions (allow rules).</summary>
    public bool? AdministratorsWriteAllowed { get; set; }
    /// <summary>Windows: BUILTIN\\Administrators have read permissions (allow rules).</summary>
    public bool? AdministratorsReadAllowed { get; set; }
    /// <summary>Windows: True when any explicit deny ACE is present.</summary>
    public bool? HasDenyEntries { get; set; }

    /// <summary>Windows: Total allow ACEs.</summary>
    public int? TotalAllowCount { get; set; }
    /// <summary>Windows: Total deny ACEs.</summary>
    public int? TotalDenyCount { get; set; }
    /// <summary>Windows: Explicit (non-inherited) allow ACEs.</summary>
    public int? ExplicitAllowCount { get; set; }
    /// <summary>Windows: Explicit (non-inherited) deny ACEs.</summary>
    public int? ExplicitDenyCount { get; set; }

    /// <summary>Windows: Flattened ACE entries for display and inspection.</summary>
    public IReadOnlyList<FileAce>? AclEntries { get; set; }

    // Windows Mark-of-the-Web (MOTW) and ADS summary
    /// <summary>Windows: Number of alternate data streams on the file (best-effort enumeration).</summary>
    public int? AlternateStreamCount { get; set; }
    /// <summary>Windows: MOTW ZoneId value from Zone.Identifier (e.g., 3=Internet). Null when absent.</summary>
    public int? MotwZoneId { get; set; }
    /// <summary>Windows: MOTW ReferrerUrl value, when present.</summary>
    public string? MotwReferrerUrl { get; set; }
    /// <summary>Windows: MOTW HostUrl value, when present.</summary>
    public string? MotwHostUrl { get; set; }
}
