namespace FileInspectorX;

/// <summary>
/// Selects which flattened view to project from analysis/detection.
/// </summary>
public enum InsightView
{
    Raw = 0,
    Analysis = 1,
    Detection = 2,
    Permissions = 3,
    Signature = 4,
    Summary = 5,
    References = 6,
    Assessment = 7,
    Installer = 8
}
