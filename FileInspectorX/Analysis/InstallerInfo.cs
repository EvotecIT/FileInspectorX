namespace FileInspectorX;

/// <summary>
/// Minimal, generic metadata for installers/packages detected in files or containers.
/// </summary>
public sealed class InstallerInfo
{
    public InstallerKind Kind { get; set; } = InstallerKind.Unknown;
    public string? Name { get; set; }
    public string? Publisher { get; set; }
    public string? PublisherDisplayName { get; set; }
    public string? IdentityName { get; set; }
    public string? Version { get; set; }
    public string? ProductCode { get; set; }
    public string? Manufacturer { get; set; }
    public string? Author { get; set; }
    public string? Comments { get; set; }
}

public enum InstallerKind
{
    Unknown = 0,
    Msi = 1,
    Msix = 2,
    Appx = 3,
    Vsix = 4
}
