namespace FileInspectorX;

/// <summary>
/// Selects which flattened view to project from analysis/detection.
/// </summary>
public enum InsightView
{
    /// <summary>Return the full underlying <see cref="FileAnalysis"/> object.</summary>
    Raw = 0,
    /// <summary>Flattened analysis view (container/text/PE/signature hints).</summary>
    Analysis = 1,
    /// <summary>Flattened detection view (extension/MIME/reason).</summary>
    Detection = 2,
    /// <summary>Flattened permissions/ownership view.</summary>
    Permissions = 3,
    /// <summary>Flattened Authenticode signature view.</summary>
    Signature = 4,
    /// <summary>Compact summary view (few key columns).</summary>
    Summary = 5,
    /// <summary>Flattened references extracted from content.</summary>
    References = 6,
    /// <summary>Flattened risk assessment view (score/decision/codes).</summary>
    Assessment = 7,
    /// <summary>Flattened installer/package metadata view.</summary>
    Installer = 8,
    /// <summary>Windows shell properties view (Explorer Details).</summary>
    ShellProperties = 9
}
