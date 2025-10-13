namespace FileInspectorX;

/// <summary>
/// Extension helpers to project core results into flattened views for display/logging.
/// </summary>
public static class ViewExtensions
{
    /// <summary>Projects a full <see cref="FileAnalysis"/> into a compact <see cref="SummaryView"/>.</summary>
    public static SummaryView ToSummaryView(this FileAnalysis a, string path) => SummaryView.From(path, a);
    /// <summary>Projects a full <see cref="FileAnalysis"/> into an <see cref="AnalysisView"/>; attaches the original object to <c>Raw</c>.</summary>
    public static AnalysisView ToAnalysisView(this FileAnalysis a, string path) { var v = AnalysisView.From(path, a); v.Raw = a; return v; }
    /// <summary>Projects the permissions snapshot into a <see cref="PermissionsView"/>; attaches the original object to <c>Raw</c>.</summary>
    public static PermissionsView ToPermissionsView(this FileAnalysis a, string path) { var v = PermissionsView.From(path, a.Security); v.Raw = a; return v; }
    /// <summary>Projects the signature summary into a <see cref="SignatureView"/>; attaches the original object to <c>Raw</c>.</summary>
    public static SignatureView ToSignatureView(this FileAnalysis a, string path) { var v = SignatureView.From(path, a.Authenticode); v.Raw = a; return v; }
    /// <summary>Projects a detection result into a <see cref="DetectionView"/>.</summary>
    public static DetectionView ToDetectionView(this ContentTypeDetectionResult d, string path) => DetectionView.From(path, d);
    public static DetectionView ToDetectionView(this FileAnalysis a, string path)
    {
        var d = a.Detection ?? new ContentTypeDetectionResult();
        var v = DetectionView.From(path, d);
        v.Raw = a;
        return v;
    }
    /// <summary>Projects extracted references into <see cref="ReferencesView"/> rows; attaches the original object to <c>Raw</c>.</summary>
    public static IEnumerable<ReferencesView> ToReferencesView(this FileAnalysis a, string path)
    {
        foreach (var rv in ReferencesView.From(path, a.References)) { rv.Raw = a; yield return rv; }
    }
    /// <summary>Projects assessment into an <see cref="AssessmentView"/>; attaches the original object to <c>Raw</c>.</summary>
    public static AssessmentView ToAssessmentView(this FileAnalysis a, string path) { var v = AssessmentView.From(path, FileInspector.Assess(a)); v.Raw = a; return v; }
    /// <summary>Projects installer metadata into an <see cref="InstallerView"/>; attaches the original object to <c>Raw</c>.</summary>
    public static InstallerView ToInstallerView(this FileAnalysis a, string path) { var v = InstallerView.From(path, a.Installer); v.Raw = a; return v; }
}
