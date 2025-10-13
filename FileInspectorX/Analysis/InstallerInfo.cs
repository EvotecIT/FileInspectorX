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
    /// <summary>Declared capabilities (MSIX/APPX); element/local names as found.</summary>
    public IReadOnlyList<string>? Capabilities { get; set; }
    /// <summary>Declared extensions (e.g., windows.protocol:edge or protocol names); compact string tokens.</summary>
    public IReadOnlyList<string>? Extensions { get; set; }
    /// <summary>MSI CustomAction summary (Windows-only).</summary>
    public MsiCustomActionSummary? MsiCustomActions { get; set; }
}

/// <summary>
/// Summary of MSI custom actions discovered in the package (Windows-only, no external dependencies).
/// </summary>
public sealed class MsiCustomActionSummary
{
    public int CountExe { get; set; }
    public int CountDll { get; set; }
    public int CountScript { get; set; }
    public int CountOther { get; set; }
    /// <summary>First few action descriptors for diagnostics (e.g., type:source/target). Length is bounded.</summary>
    public IReadOnlyList<string>? Samples { get; set; }
}

/// <summary>
/// Known installer/package kinds recognized by the library.
/// </summary>
public enum InstallerKind
{
    /// <summary>Not recognized as a known installer kind.</summary>
    Unknown = 0,
    /// <summary>Windows Installer package (.msi).</summary>
    Msi = 1,
    /// <summary>Modern Windows package (.msix).</summary>
    Msix = 2,
    /// <summary>Windows AppX package (.appx).</summary>
    Appx = 3,
    /// <summary>Visual Studio extension package (.vsix).</summary>
    Vsix = 4
}
