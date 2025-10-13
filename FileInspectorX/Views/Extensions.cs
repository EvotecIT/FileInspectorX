namespace FileInspectorX;

/// <summary>
/// Extension helpers to project core results into flattened views for display/logging.
/// </summary>
public static class ViewExtensions
{
    public static SummaryView ToSummaryView(this FileAnalysis a, string path) => SummaryView.From(path, a);
    public static AnalysisView ToAnalysisView(this FileAnalysis a, string path) { var v = AnalysisView.From(path, a); v.Raw = a; return v; }
    public static PermissionsView ToPermissionsView(this FileAnalysis a, string path) { var v = PermissionsView.From(path, a.Security); v.Raw = a; return v; }
    public static SignatureView ToSignatureView(this FileAnalysis a, string path) { var v = SignatureView.From(path, a.Authenticode); v.Raw = a; return v; }
    public static DetectionView ToDetectionView(this ContentTypeDetectionResult d, string path) => DetectionView.From(path, d);
    public static DetectionView ToDetectionView(this FileAnalysis a, string path)
    {
        var d = a.Detection ?? new ContentTypeDetectionResult();
        var v = DetectionView.From(path, d);
        v.Raw = a;
        return v;
    }
    public static IEnumerable<ReferencesView> ToReferencesView(this FileAnalysis a, string path)
    {
        foreach (var rv in ReferencesView.From(path, a.References)) { rv.Raw = a; yield return rv; }
    }
    public static AssessmentView ToAssessmentView(this FileAnalysis a, string path) { var v = AssessmentView.From(path, FileInspector.Assess(a)); v.Raw = a; return v; }
    public static InstallerView ToInstallerView(this FileAnalysis a, string path) { var v = InstallerView.From(path, a.Installer); v.Raw = a; return v; }
}
