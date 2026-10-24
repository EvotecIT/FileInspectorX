using Xunit;

namespace FileInspectorX.Tests;

public partial class DetectorTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PlainHeaderSevenZipRemainsIncompleteRegardlessOfDeepScanSelection(bool deep)
    {
        var bytes = CreateMinimal7zArchiveWithNames("message.txt");
        var analysis = FileInspector.Inspect(bytes, new FileInspector.DetectionOptions
        {
            IncludeContainer = true, IncludePermissions = false, IncludeAuthenticode = false,
            Settings = InspectionSettings.CaptureDefaults() with { DeepContainerScanEnabled = deep }
        }, "upload.7z");
        Assert.Equal("7z", analysis.Detection!.Extension);
        Assert.Equal(1, analysis.ContainerEntryCount);
        Assert.Contains("archive:inner-content-unavailable", analysis.AnalysisIssues!);
        Assert.Equal(InspectionStageStatus.Partial, analysis.StageOutcomes.Single(stage => stage.Stage == InspectionStage.Container).Status);
        Assert.Equal(FileAcceptanceDecision.Incomplete, FileInspector.EvaluateAcceptance(analysis, "upload.7z").Decision);
    }
}
