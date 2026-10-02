namespace FileInspectorX;

public static partial class FileInspector
{
    private static FileAnalysis InputFailureAnalysis(DetectionOptions options, bool detectionOnly = false, bool hasFileSystemSource = true)
    {
        var failed = new FileAnalysis { SettingsSnapshot = options.Settings, HasFileSystemSource = hasFileSystemSource,
            AnalysisComplete = false, AnalysisIssues = new[] { "input:read-failed" } };
        if (options.IncludeAssessment)
        {
            using var timing = InspectionOperation.Current?.Measure(InspectionStage.Assessment);
            failed.Assessment = Assess(failed);
            failed.AssessmentProfiles = AssessMulti(failed.Assessment);
        }
        return CompleteAnalysis(failed, options, detectionOnly);
    }
}
