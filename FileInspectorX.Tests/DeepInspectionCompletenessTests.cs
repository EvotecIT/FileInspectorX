using System.IO.Compression;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class DeepInspectionCompletenessTests
{
    [Theory]
    [InlineData("zip", 1, false)]
    [InlineData("zip", 2, true)]
    [InlineData("zip", 3, true)]
    [InlineData("tar", 1, false)]
    [InlineData("tar", 2, true)]
    [InlineData("tar", 3, true)]
    public void ArchiveDeepEntryLimitReportsOmittedContent(string format, int limit, bool complete)
    {
        using var input = CreateArchive(format, "ordinary documentation", "param([string]$Name); Get-Process | Select-Object Name");
        var options = Options(limit, 4096);

        var analysis = FileInspector.Analyze(input, options, "bundle." + format);

        Assert.Equal(2, analysis.ContainerEntryCount);
        Assert.Equal(complete, analysis.AnalysisComplete);
        Assert.Equal(complete ? InspectionOutcome.Complete : InspectionOutcome.Partial, analysis.Outcome);
        if (complete)
            Assert.Contains("archive:inner-disguised-script", analysis.InnerFindings ?? Array.Empty<string>());
        else
        {
            Assert.Contains("archive:deep-entry-count-limit", analysis.AnalysisIssues!);
            Assert.Equal("Defer", analysis.Assessment!.Decision.ToString());
        }
    }

    [Theory]
    [InlineData("rar")]
    [InlineData("7z")]
    public void OpaqueArchiveContentDefersRequestedDeepInspection(string format)
    {
        byte[] bytes;
        if (format == "rar")
        {
            bytes = new byte[] { 0x52, 0x61, 0x72, 0x21, 0x1a, 7, 1, 0, 0, 0, 0, 0, 5, 1, 4, 0 };
        }
        else
        {
            bytes = new byte[48];
            new byte[] { 0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c }.CopyTo(bytes, 0);
            bytes[20] = 16;
            bytes[32] = 0x17;
        }

        var analysis = FileInspector.Analyze(bytes, Options(2, 4096), "bundle." + format);

        Assert.Equal(format, analysis.Detection!.Extension);
        Assert.False(analysis.AnalysisComplete);
        Assert.Equal(InspectionOutcome.Partial, analysis.Outcome);
        Assert.Equal("Defer", analysis.Assessment!.Decision.ToString());
        Assert.Contains("archive:encrypted-content-unavailable", analysis.AnalysisIssues!);
    }

    [Theory]
    [InlineData("zip")]
    [InlineData("tar")]
    public void ArchiveDeepByteLimitReportsUnexaminedRemainder(string format)
    {
        using var input = CreateArchive(format, new string('a', 8192), "ordinary text");

        var analysis = FileInspector.Analyze(input, Options(2, 4096), "bundle." + format);

        Assert.False(analysis.AnalysisComplete);
        Assert.Contains("archive:deep-entry-byte-limit", analysis.AnalysisIssues!);
        Assert.Equal(InspectionStageStatus.Partial,
            Assert.Single(analysis.StageOutcomes, stage => stage.Stage == InspectionStage.Container).Status);
    }

    private static FileInspector.DetectionOptions Options(int entries, int bytes) => new()
    {
        Settings = InspectionSettings.CaptureDefaults() with
        {
            DeepContainerScanEnabled = true,
            DeepContainerMaxEntries = entries,
            DeepContainerMaxEntryBytes = bytes,
            ArchiveMaxCompressionRatio = 10000
        },
        IncludeAuthenticode = false,
        IncludePermissions = false,
        IncludeInstaller = false
    };

    private static MemoryStream CreateArchive(string format, string first, string second)
    {
        var input = new MemoryStream();
        if (format == "tar")
        {
            foreach (var item in new[] { ("first.txt", first), ("second.txt", second) })
            {
                var bytes = System.Text.Encoding.UTF8.GetBytes(item.Item2);
                InspectionIntegrityTests.WriteTarHeader(input, item.Item1, size: bytes.Length);
                input.Write(bytes, 0, bytes.Length);
                var padding = new byte[(512 - bytes.Length % 512) % 512];
                input.Write(padding, 0, padding.Length);
            }
            input.Write(new byte[1024], 0, 1024);
            input.Position = 0;
            return input;
        }
        using (var zip = new ZipArchive(input, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var item in new[] { ("first.txt", first), ("second.txt", second) })
            {
                using var writer = new StreamWriter(zip.CreateEntry(item.Item1).Open());
                writer.Write(item.Item2);
            }
        }
        input.Position = 0;
        return input;
    }
}
