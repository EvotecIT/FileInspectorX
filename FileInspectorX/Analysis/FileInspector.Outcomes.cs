namespace FileInspectorX;

public static partial class FileInspector
{
    private static FileAnalysis CompleteAnalysis(FileAnalysis result, DetectionOptions options, bool detectionOnly = false, bool quick = false)
    {
        bool unreadable = result.InputStatus == InspectionInputStatus.Unreadable;
        var stages = new List<InspectionStageResult>
        {
            new(InspectionStage.Detection, unreadable ? InspectionStageStatus.Failed : InspectionStageStatus.Completed,
                unreadable ? new[] { "input:read-failed" } : Array.Empty<string>())
        };
        var validation = result.Detection?.StructuredValidation ?? StructuredValidationOutcome.NotAttempted;
        stages.Add(new InspectionStageResult(InspectionStage.StructuredValidation, validation switch
        {
            StructuredValidationOutcome.NotAttempted => InspectionStageStatus.NotApplicable,
            StructuredValidationOutcome.Skipped or StructuredValidationOutcome.TimedOut => InspectionStageStatus.Partial,
            StructuredValidationOutcome.Unavailable => InspectionStageStatus.Unavailable,
            _ => InspectionStageStatus.Completed
        }, validation == StructuredValidationOutcome.NotAttempted ? Array.Empty<string>() : new[] { "validation:" + result.Detection!.ValidationStatus }));
        stages.Add(new InspectionStageResult(InspectionStage.Sha256,
            !options.ComputeSha256 ? InspectionStageStatus.NotRequested :
            result.Detection?.Sha256Hex != null ? InspectionStageStatus.Completed : InspectionStageStatus.Unavailable,
            options.ComputeSha256 && result.Detection?.Sha256Hex == null ? new[] { "hash:unavailable" } : Array.Empty<string>()));
        var learned = result.Detection?.LearnedClassification;
        stages.Add(new InspectionStageResult(InspectionStage.LearnedClassification,
            options.LearnedClassificationMode == LearnedClassificationMode.Off ? InspectionStageStatus.NotRequested :
            learned == null ? InspectionStageStatus.Unavailable :
            learned.Disposition == LearnedClassificationDisposition.Failed ? InspectionStageStatus.Failed : InspectionStageStatus.Completed,
            options.LearnedClassificationMode == LearnedClassificationMode.Off ? Array.Empty<string>() :
            learned == null ? new[] { "classifier:unavailable" } :
            learned.Disposition == LearnedClassificationDisposition.Failed ? new[] { "classifier:failed" } : Array.Empty<string>()));
        var archiveIssues = result.AnalysisIssues?.Where(issue => issue.StartsWith("archive:", StringComparison.Ordinal) ||
            issue.StartsWith("tar:", StringComparison.Ordinal)).ToArray() ?? Array.Empty<string>();
        bool supportedContainer = result.ContainerEntryCount.HasValue || archiveIssues.Length > 0 || result.Detection?.Extension is "zip" or "docx" or "xlsx" or "pptx" or "tar";
        stages.Add(new InspectionStageResult(InspectionStage.Container,
            detectionOnly || !options.IncludeContainer ? InspectionStageStatus.NotRequested :
            unreadable ? InspectionStageStatus.Unavailable : !supportedContainer ? InspectionStageStatus.NotApplicable :
            archiveIssues.Length > 0 ? InspectionStageStatus.Partial :
            result.ContainerEntryCount.HasValue ? InspectionStageStatus.Completed : InspectionStageStatus.Unavailable,
            archiveIssues));
        stages.Add(new InspectionStageResult(InspectionStage.Assessment,
            result.Assessment != null ? InspectionStageStatus.Completed :
            detectionOnly || !options.IncludeAssessment ? InspectionStageStatus.NotRequested : InspectionStageStatus.Unavailable,
            !detectionOnly && options.IncludeAssessment && result.Assessment == null
                ? new[] { quick ? "assessment:quick-scan" : "assessment:unavailable" } : Array.Empty<string>()));
        if (!result.HasFileSystemSource) AddPortablePathStageOutcomes(stages, result, options, detectionOnly);
        result.StageOutcomes = Array.AsReadOnly(stages.ToArray());
        result.Metrics = InspectionOperation.Current?.SnapshotMetrics();
        return result;
    }

    private static ContentTypeDetectionResult? CompleteDetection(ContentTypeDetectionResult? result)
    {
        if (result != null) result.Metrics = InspectionOperation.Current?.SnapshotMetrics();
        return result;
    }
}
