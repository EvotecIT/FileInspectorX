namespace FileInspectorX;

/// <summary>
/// Minimal installer/package metadata extracted from MSIX/APPX/VSIX manifests and MSI databases (Windows-only).
/// </summary>
public sealed class InstallerInfo
{
    /// <summary>Kind of installer/package (MSI/MSIX/APPX/VSIX).</summary>
    public InstallerKind Kind { get; set; } = InstallerKind.Unknown;
    /// <summary>Display name of the package/product.</summary>
    public string? Name { get; set; }
    /// <summary>Publisher name (subject DN or friendly display name).</summary>
    public string? Publisher { get; set; }
    /// <summary>Publisher display name (MSIX/APPX identity metadata).</summary>
    public string? PublisherDisplayName { get; set; }
    /// <summary>Identity name (Package Family Name element for MSIX/APPX; VSIX Id).</summary>
    public string? IdentityName { get; set; }
    /// <summary>Package version string.</summary>
    public string? Version { get; set; }
    /// <summary>MSI product code (GUID), when applicable.</summary>
    public string? ProductCode { get; set; }
    /// <summary>MSI manufacturer, when applicable.</summary>
    public string? Manufacturer { get; set; }
    /// <summary>Author metadata (when present).</summary>
    public string? Author { get; set; }
    /// <summary>Free‑form comments or description.</summary>
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
    /// <summary>Number of EXE custom actions.</summary>
    public int CountExe { get; set; }
    /// <summary>Number of DLL custom actions.</summary>
    public int CountDll { get; set; }
    /// <summary>Number of script custom actions (JScript/VBScript).</summary>
    public int CountScript { get; set; }
    /// <summary>Number of custom actions of other kinds.</summary>
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
