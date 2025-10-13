namespace FileInspectorX;

/// <summary>
/// Flattened view for installer/package metadata.
/// </summary>
public sealed class InstallerView
{
    public string Path { get; set; } = string.Empty;
    public InstallerKind Kind { get; set; }
    public string? Name { get; set; }
    public string? Publisher { get; set; }
    public string? PublisherDisplayName { get; set; }
    public string? IdentityName { get; set; }
    public string? Version { get; set; }
    public string? ProductCode { get; set; }
    public string? Manufacturer { get; set; }
    public string? Author { get; set; }
    public string? Comments { get; set; }
    /// <summary>The full analysis object for deep inspection.</summary>
    public FileAnalysis? Raw { get; set; }

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
            Manufacturer = i.Manufacturer,
            Author = i.Author,
            Comments = i.Comments,
            Raw = null
        };
    }
}
