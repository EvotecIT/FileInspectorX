namespace FileInspectorX;

/// <summary>
/// Flattened view for installer/package metadata.
/// </summary>
public sealed class InstallerView
{
    /// <summary>File path.</summary>
    public string Path { get; set; } = string.Empty;
    /// <summary>Installer kind.</summary>
    public InstallerKind Kind { get; set; }
    /// <summary>Package/product display name.</summary>
    public string? Name { get; set; }
    /// <summary>Publisher name.</summary>
    public string? Publisher { get; set; }
    /// <summary>Publisher display name (MSIX/APPX).</summary>
    public string? PublisherDisplayName { get; set; }
    /// <summary>Identity/name (MSIX/APPX family name; VSIX Id).</summary>
    public string? IdentityName { get; set; }
    /// <summary>Version string.</summary>
    public string? Version { get; set; }
    /// <summary>MSI product code (GUID).</summary>
    public string? ProductCode { get; set; }
    /// <summary>MSI upgrade code (GUID).</summary>
    public string? UpgradeCode { get; set; }
    /// <summary>MSI manufacturer.</summary>
    public string? Manufacturer { get; set; }
    /// <summary>Installer scope (PerUser/PerMachine), when detectable.</summary>
    public string? Scope { get; set; }
    /// <summary>Author metadata, when present.</summary>
    public string? Author { get; set; }
    /// <summary>Comments/description, when present.</summary>
    public string? Comments { get; set; }
    /// <summary>Package code (GUID) from SummaryInformation.</summary>
    public string? PackageCode { get; set; }
    /// <summary>About/Info URL.</summary>
    public string? UrlInfoAbout { get; set; }
    /// <summary>Update URL.</summary>
    public string? UrlUpdateInfo { get; set; }
    /// <summary>Help link.</summary>
    public string? HelpLink { get; set; }
    /// <summary>Support URL.</summary>
    public string? SupportUrl { get; set; }
    /// <summary>Contact string.</summary>
    public string? Contact { get; set; }
    /// <summary>The full analysis object for deep inspection.</summary>
    public FileAnalysis? Raw { get; set; }

    /// <summary>
    /// Creates an <see cref="InstallerView"/> from <see cref="InstallerInfo"/>.
    /// </summary>
    internal static InstallerView From(string path, InstallerInfo? i)
    {
        if (i == null) return new InstallerView { Path = path, Kind = InstallerKind.Unknown };
        return new InstallerView
        {
            Path = path,
            Kind = i.Kind,
            Name = i.Name,
            Publisher = i.Publisher,
            PublisherDisplayName = i.PublisherDisplayName,
            IdentityName = i.IdentityName,
            Version = i.Version,
            ProductCode = i.ProductCode,
            UpgradeCode = i.UpgradeCode,
            Scope = i.Scope,
            Manufacturer = i.Manufacturer,
            Author = i.Author,
            Comments = i.Comments,
            PackageCode = i.PackageCode,
            UrlInfoAbout = i.UrlInfoAbout,
            UrlUpdateInfo = i.UrlUpdateInfo,
            HelpLink = i.HelpLink,
            SupportUrl = i.SupportUrl,
            Contact = i.Contact,
            Raw = null
        };
    }
}
