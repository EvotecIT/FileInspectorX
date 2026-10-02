using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class InspectionOutcomesTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ReadableUnknownAndMissingInputHaveDifferentTypedOutcomes(bool detectOnly)
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".bin");
        try
        {
            File.WriteAllBytes(path, Array.Empty<byte>());
            var options = new FileInspector.DetectionOptions { DetectOnly = detectOnly, CollectMetrics = true };
            var unknown = FileInspector.Inspect(path, options);
            Assert.Equal(InspectionInputStatus.Unrecognized, unknown.InputStatus);
            Assert.Equal(InspectionOutcome.Complete, unknown.Outcome);
            Assert.Equal(InspectionStageStatus.Completed, Stage(unknown, InspectionStage.Detection).Status);
            Assert.NotNull(unknown.Metrics);
            File.Delete(path);
            var missing = FileInspector.Inspect(path, options);
            Assert.Equal(InspectionInputStatus.Unreadable, missing.InputStatus);
            Assert.Equal(InspectionOutcome.InputUnavailable, missing.Outcome);
            Assert.Equal(InspectionStageStatus.Failed, Stage(missing, InspectionStage.Detection).Status);
            Assert.Equal(0, missing.Metrics!.StreamBytesRead);
            Assert.Equal("Defer", missing.Assessment!.Decision.ToString());
        }
        finally { File.Delete(path); }
    }

    [Theory]
    [InlineData("passed", StructuredValidationOutcome.Passed)]
    [InlineData("failed", StructuredValidationOutcome.Failed)]
    [InlineData("skipped", StructuredValidationOutcome.Skipped)]
    [InlineData("timeout", StructuredValidationOutcome.TimedOut)]
    [InlineData(null, StructuredValidationOutcome.NotAttempted)]
    public void TypedValidationKeepsTheCompatibilityStatus(string? status, StructuredValidationOutcome expected)
    {
        var detection = new ContentTypeDetectionResult { ValidationStatus = status };
        Assert.Equal(expected, detection.StructuredValidation);
        Assert.Equal(expected, DetectionView.From("input", detection).StructuredValidation);
    }

    [Fact]
    public void BudgetedArchiveReportsPartialAndDefaultMetricsAreAbsent()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".zip");
        try
        {
            File.WriteAllBytes(path, ZipTestArchive.Create(("one.txt", "one"), ("two.txt", "two")));
            var settings = InspectionSettings.CaptureDefaults() with { ArchiveMaxEntries = 1 };
            var partial = FileInspector.Analyze(path, new() { Settings = settings, CollectMetrics = true });
            Assert.Equal(InspectionInputStatus.Recognized, partial.InputStatus);
            Assert.Equal(InspectionOutcome.Partial, partial.Outcome);
            Assert.Contains("archive:entry-count-limit", Stage(partial, InspectionStage.Container).Issues);
            Assert.Equal(InspectionStageStatus.Partial, Stage(partial, InspectionStage.Container).Status);
            Assert.True(partial.Metrics!.ArchiveLimitHits >= 1);
            Assert.Equal(0, partial.Metrics.ArchiveEntriesVisited);
            Assert.Null(FileInspector.Analyze(path, new() { IncludeContainer = false }).Metrics);
        }
        finally { File.Delete(path); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void OptionalProviderFailureIsTypedWithoutChangingTheCompatibilityFlag(bool missingProvider)
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".json");
        try
        {
            File.WriteAllText(path, "{\"value\":1}");
            var result = FileInspector.Inspect(path, new() {
                DetectOnly = true, CollectMetrics = true, LearnedClassificationMode = LearnedClassificationMode.Assist,
                LearnedClassifier = missingProvider ? null : new FailingClassifier()
            });
            Assert.True(result.AnalysisComplete);
            Assert.Equal(InspectionOutcome.Partial, result.Outcome);
            Assert.Equal(InspectionStageStatus.Failed, Stage(result, InspectionStage.LearnedClassification).Status);
            Assert.Equal(missingProvider ? 0 : 1, result.Metrics!.ClassifierAttempts);
            Assert.Equal(missingProvider ? 0 : 1, result.Metrics.ClassifierFailures);
            Assert.DoesNotContain(Stage(result, InspectionStage.LearnedClassification).Issues, code => code.Contains(path));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void StageAndMetricProjectionsKeepImmutableEvidence()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".json");
        try
        {
            File.WriteAllText(path, "{\"value\":1}");
            var result = FileInspector.Inspect(path, new() { DetectOnly = true, ComputeSha256 = true, CollectMetrics = true });
            Assert.Equal(InspectionStageStatus.Completed, Stage(result, InspectionStage.Sha256).Status);
            Assert.Equal(InspectionStageStatus.NotRequested, Stage(result, InspectionStage.Container).Status);
            var view = ReportView.From(result);
            Assert.Same(result.Metrics, view.Metrics);
            Assert.Same(result.StageOutcomes, view.StageOutcomes);
            Assert.Equal(result.Outcome, view.ToDictionary()["Outcome"]);
            Assert.Throws<NotSupportedException>(() => ((IList<InspectionStageResult>)result.StageOutcomes).Clear());
            Assert.Throws<NotSupportedException>(() => ((IList<string>)Stage(result, InspectionStage.Detection).Issues).Add("changed"));
            Assert.Throws<NotSupportedException>(() => ((IList<InspectionStageMetric>)result.Metrics!.Stages).Clear());
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void InvalidValidationCompletedButBudgetLimitedValidationIsPartial()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".json");
        try
        {
            File.WriteAllText(path, "{\"a\": [ } ]");
            var invalid = FileInspector.Inspect(path, new() { DetectOnly = true, CollectMetrics = true });
            Assert.Equal(StructuredValidationOutcome.Failed, invalid.Detection!.StructuredValidation);
            Assert.Equal(InspectionStageStatus.Completed, Stage(invalid, InspectionStage.StructuredValidation).Status);
            Assert.Equal(InspectionOutcome.Complete, invalid.Outcome);
            Assert.True(Assert.Single(invalid.Metrics!.Stages, stage => stage.Stage == InspectionStage.StructuredValidation).Invocations >= 1);
            File.WriteAllText(path, "{\"ok\":true}".PadRight(64) + "trailing bytes");
            var settings = InspectionSettings.CaptureDefaults() with { DetectionReadBudgetBytes = 64 };
            var limited = FileInspector.Inspect(path, new() { DetectOnly = true, Settings = settings });
            Assert.Equal(StructuredValidationOutcome.Skipped, limited.Detection!.StructuredValidation);
            Assert.Equal(InspectionStageStatus.Partial, Stage(limited, InspectionStage.StructuredValidation).Status);
            Assert.Equal(InspectionOutcome.Partial, limited.Outcome);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void QuickEtlScanReportsRequestedHashAndAssessmentAsUnavailable()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".etl");
        try
        {
            File.WriteAllBytes(path, new byte[] { 0x45, 0x6c, 0x66, 0x46, 0, 1 });
            var settings = InspectionSettings.CaptureDefaults() with { EtlLargeFileQuickScanBytes = 1, EtlValidation = Settings.EtlValidationMode.MagicOnly };
            var quick = FileInspector.Inspect(path, new() { Settings = settings, ComputeSha256 = true, CollectMetrics = true });
            Assert.Equal(InspectionOutcome.Partial, quick.Outcome);
            Assert.Equal(InspectionStageStatus.Unavailable, Stage(quick, InspectionStage.Sha256).Status);
            Assert.Contains("assessment:quick-scan", Stage(quick, InspectionStage.Assessment).Issues);
            Assert.Equal(0, quick.Metrics!.HashBytes);
            Assert.Equal(1, Assert.Single(quick.Metrics.Stages, stage => stage.Stage == InspectionStage.Detection).Invocations);
        }
        finally { File.Delete(path); }
    }

    internal static InspectionStageResult Stage(FileAnalysis result, InspectionStage stage)
        => Assert.Single(result.StageOutcomes, item => item.Stage == stage);

    private sealed class FailingClassifier : ILearnedContentClassifier
    {
        public LearnedContentPrediction Predict(ReadOnlyMemory<byte> content) => throw new InvalidOperationException("private provider detail");
        public LearnedContentPrediction Predict(Stream content) => throw new InvalidOperationException("private provider detail");
    }
}
