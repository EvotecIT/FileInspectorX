namespace FileInspectorX;

/// <summary>
/// Very compact, tabular-friendly view with the most important columns.
/// </summary>
public sealed class SummaryView
{
    /// <summary>File path.</summary>
    public string Path { get; set; } = string.Empty;
    /// <summary>High-level kind classification.</summary>
    public ContentKind Kind { get; set; } = ContentKind.Unknown;
    /// <summary>Detected extension.</summary>
    public string Extension { get; set; } = string.Empty;
    /// <summary>Detected MIME type.</summary>
    public string MimeType { get; set; } = string.Empty;
    /// <summary>Confidence level.</summary>
    public string Confidence { get; set; } = string.Empty;
    /// <summary>Short reason for detection.</summary>
    public string Reason { get; set; } = string.Empty;
    /// <summary>Structured validation status when applicable.</summary>
    public string ValidationStatus { get; set; } = string.Empty;
    /// <summary>Bit flags with analysis signals.</summary>
    public ContentFlags Flags { get; set; } = ContentFlags.None;
    /// <summary>Compact installer/package summary when applicable (e.g., "MSIX: Name v1.0 by Publisher"). Empty when not applicable.</summary>
    public string InstallerSummary { get; set; } = string.Empty;
    /// <summary>The full analysis object for deep inspection (useful in PowerShell).</summary>
    public FileAnalysis? Raw { get; set; }

    /// <summary>
    /// Creates a compact <see cref="SummaryView"/> from a <see cref="FileAnalysis"/>.
    /// </summary>
    public static SummaryView From(string path, FileAnalysis a)
    {
        var d = a.Detection;
        return new SummaryView {
            Path = path,
            Kind = a.Kind,
            Extension = d?.Extension ?? string.Empty,
            MimeType = d?.MimeType ?? string.Empty,
            Confidence = d?.Confidence ?? string.Empty,
            Reason = d?.Reason ?? string.Empty,
            ValidationStatus = d?.ValidationStatus ?? string.Empty,
            Flags = a.Flags,
            InstallerSummary = BuildInstallerSummary(a.Installer),
            Raw = a
        };
    }

    private static string BuildInstallerSummary(InstallerInfo? i)
    {
        if (i == null || i.Kind == InstallerKind.Unknown) return string.Empty;
        string kind = i.Kind.ToString().ToUpperInvariant();
        switch (i.Kind)
        {
            case InstallerKind.Msix:
            case InstallerKind.Appx:
            {
                var name = i.Name ?? i.IdentityName ?? string.Empty;
                var pub = i.PublisherDisplayName ?? i.Publisher ?? string.Empty;
                var ver = i.Version ?? string.Empty;
                return TrimSpaces($"{kind}: {name} v{ver} by {pub}");
            }
            case InstallerKind.Msi:
            {
                var name = i.Name ?? string.Empty;
                var mfr = i.Manufacturer ?? string.Empty;
                var pc = i.ProductCode ?? string.Empty;
                return TrimSpaces($"MSI: {name} by {mfr} {(string.IsNullOrEmpty(pc) ? string.Empty : "(" + pc + ")")}");
            }
            case InstallerKind.Vsix:
            {
                var name = i.Name ?? i.IdentityName ?? string.Empty;
                var pub = i.Publisher ?? string.Empty;
                var ver = i.Version ?? string.Empty;
                return TrimSpaces($"VSIX: {name} v{ver} by {pub}");
            }
            default:
                return string.Empty;
        }

        static string TrimSpaces(string s) => s.Replace("  ", " ").Trim().TrimEnd(' ', ')');
    }
}
