namespace FileInspectorX;

/// <summary>
/// Windows ACL entry (ACE) summary for display and quick analysis.
/// Cross-platform: populated on Windows; null elsewhere.
/// </summary>
public sealed class FileAce
{
    /// <summary>Allow or Deny.</summary>
    public string AccessControlType { get; set; } = string.Empty;
    /// <summary>Principal display name (e.g., BUILTIN\Users).</summary>
    public string Principal { get; set; } = string.Empty;
    /// <summary>Principal SID string.</summary>
    public string PrincipalSid { get; set; } = string.Empty;
    /// <summary>Rights set as a compact string (e.g., Read, Write, Modify, Execute, FullControl).</summary>
    public string Rights { get; set; } = string.Empty;
    /// <summary>True when this ACE is inherited.</summary>
    public bool IsInherited { get; set; }
    /// <summary>Raw rights bitmask string (FileSystemRights) for reference.</summary>
    public string RawRights { get; set; } = string.Empty;
}

