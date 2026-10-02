namespace FileInspectorX;

public static partial class FileInspector
{
    private static FileAnalysis InputFailureAnalysis(DetectionOptions options)
    {
        var failed = new FileAnalysis { AnalysisComplete = false, AnalysisIssues = new[] { "input:read-failed" } };
        if (options.IncludeAssessment)
        {
            failed.Assessment = Assess(failed);
            failed.AssessmentProfiles = AssessMulti(failed.Assessment);
        }
        return failed;
    }
}
