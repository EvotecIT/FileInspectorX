namespace FileInspectorX;

/// <summary>
/// Extension helpers to project core results into flattened views for display/logging.
/// </summary>
public static class ViewExtensions
{
    public static SummaryView ToSummaryView(this FileAnalysis a, string path) => SummaryView.From(path, a);
    public static AnalysisView ToAnalysisView(this FileAnalysis a, string path) => AnalysisView.From(path, a);
    public static PermissionsView ToPermissionsView(this FileAnalysis a, string path) => PermissionsView.From(path, a.Security);
    public static SignatureView ToSignatureView(this FileAnalysis a, string path) => SignatureView.From(path, a.Authenticode);
    public static DetectionView ToDetectionView(this ContentTypeDetectionResult d, string path) => DetectionView.From(path, d);
    public static DetectionView ToDetectionView(this FileAnalysis a, string path)
    {
        var d = a.Detection ?? new ContentTypeDetectionResult();
        return DetectionView.From(path, d);
    }
}

