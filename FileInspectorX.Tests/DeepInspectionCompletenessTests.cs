using System.IO.Compression;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class DeepInspectionCompletenessTests
{
    [Fact]
    public void TarExhaustedPrefixBudgetPreservesLaterMemberNamesAndSafetyFlags()
    {
        using var tar = new MemoryStream();
        InspectionIntegrityTests.WriteTarHeader(tar, "first.txt", size: 1024);
        tar.Write(new byte[1024], 0, 1024);
        InspectionIntegrityTests.WriteTarHeader(tar, "../later.ps1", size: 1);
        tar.Write(new byte[512], 0, 512);
        tar.Write(new byte[1024], 0, 1024);
        tar.Position = 0;
        var options = Options(2, 4096);
        options.Settings = options.Settings! with { ArchiveMaxTotalReadBytes = 512 };

        var analysis = FileInspector.Analyze(tar, options, "bundle.tar");

        Assert.Equal(2, analysis.ContainerEntryCount);
        Assert.Contains("ps1", analysis.ContainerTopExtensions!);
        Assert.True(analysis.Flags.HasFlag(ContentFlags.ContainerContainsScripts));
        Assert.True(analysis.Flags.HasFlag(ContentFlags.ArchiveHasPathTraversal));
        Assert.False(analysis.AnalysisComplete);
        Assert.Contains("archive:total-read-limit", analysis.AnalysisIssues!);
    }

    [Theory]
    [InlineData(false, false, 4096)]
    [InlineData(true, false, 4096)]
    [InlineData(false, true, 4096)]
    [InlineData(false, false, 7)]
    public void KnownEmptyRarDoesNotClaimUnexaminedPayload(bool truncated, bool corrupt, int metadataBudget)
    {
        // RAR4 marker, 13-byte main header, and 7-byte end header, with header CRCs.
        var bytes = new byte[] { 0x52, 0x61, 0x72, 0x21, 0x1a, 7, 0,
            0xcf, 0x90, 0x73, 0, 0, 13, 0, 0, 0, 0, 0, 0, 0,
            4, 0xb0, 0x7b, 0, 0, 7, 0 };
        if (truncated) Array.Resize(ref bytes, 20);
        if (corrupt) bytes[7] ^= 1;
        var options = Options(2, 4096);
        options.Settings = options.Settings! with { DetectionReadBudgetBytes = metadataBudget };

        var analysis = FileInspector.Analyze(bytes, options, "empty.rar");

        Assert.Equal("rar", analysis.Detection!.Extension);
        Assert.Equal(0, analysis.ContainerEntryCount);
        bool complete = !truncated && !corrupt && metadataBudget > 7;
        Assert.Equal(complete, analysis.AnalysisComplete);
        if (!complete)
            Assert.Contains("archive:inner-content-unavailable", analysis.AnalysisIssues!);
        else
            Assert.DoesNotContain("archive:inner-content-unavailable", analysis.AnalysisIssues ?? Array.Empty<string>());
    }

    [Fact]
    public void OneNestedMemberUsesNestedAllowanceInsteadOfDirectAggregate()
    {
        using var nested = new MemoryStream();
        using (var zip = new ZipArchive(nested, ZipArchiveMode.Create, leaveOpen: true))
        using (var writer = new StreamWriter(zip.CreateEntry("payload.ps1", CompressionLevel.NoCompression).Open()))
            writer.Write("param([string]$Name); Get-Process | Select-Object Name\n" + new string(' ', 400));
        Assert.InRange(nested.Length, 513, 32768);
        using var outer = new MemoryStream();
        using (var zip = new ZipArchive(outer, ZipArchiveMode.Create, leaveOpen: true))
        using (var entry = zip.CreateEntry("nested.zip", CompressionLevel.NoCompression).Open())
            entry.Write(nested.ToArray(), 0, (int)nested.Length);
        outer.Position = 0;
        var options = Options(1, 512);
        options.Settings = options.Settings! with { DeepContainerMaxNestedArchiveBytes = 32768 };

        var analysis = FileInspector.Analyze(outer, options, "outer.zip");

        Assert.True(analysis.Flags.HasFlag(ContentFlags.ContainerContainsScripts));
        Assert.True(analysis.AnalysisComplete, string.Join(",", analysis.AnalysisIssues ?? Array.Empty<string>()));
    }

    [Theory]
    [InlineData(1024, 0)]
    [InlineData(8192, 1)]
    public void TarSignerSampleCountExcludesPrefixOnlyExecutables(int limit, int expectedSamples)
    {
        var bytes = new byte[8192];
        TestHelpers.CreateMinimalPe().CopyTo(bytes, 0);
        using var tar = new MemoryStream();
        InspectionIntegrityTests.WriteTarHeader(tar, "payload.exe", size: bytes.Length);
        tar.Write(bytes, 0, bytes.Length);
        tar.Write(new byte[1024], 0, 1024);
        tar.Position = 0;

        var analysis = FileInspector.Analyze(tar, Options(2, limit), "bundle.tar");

        Assert.True(analysis.Flags.HasFlag(ContentFlags.ContainerContainsExecutables));
        Assert.Equal(expectedSamples, analysis.InnerExecutablesSampled ?? 0);
        Assert.Equal(expectedSamples == 1, analysis.AnalysisComplete);
    }

    [Theory]
    [InlineData("notes.txt", 4096)]
    [InlineData("nested.zip", 512)]
    public void NestedArchiveUsesContentAndItsOwnByteAllowance(string name, int directBytes)
    {
        using var nested = new MemoryStream();
        using (var zip = new ZipArchive(nested, ZipArchiveMode.Create, leaveOpen: true))
        {
            using (var writer = new StreamWriter(zip.CreateEntry("payload.ps1", CompressionLevel.NoCompression).Open()))
                writer.Write("param([string]$Name); Get-Process | Select-Object Name");
            for (var i = 0; i < 8; i++)
            {
                using var writer = new StreamWriter(zip.CreateEntry("part" + i + ".txt", CompressionLevel.NoCompression).Open());
                writer.Write(new string('a', 128));
            }
        }
        using var outer = new MemoryStream();
        using (var zip = new ZipArchive(outer, ZipArchiveMode.Create, leaveOpen: true))
        using (var entry = zip.CreateEntry(name, CompressionLevel.NoCompression).Open())
            entry.Write(nested.ToArray(), 0, (int)nested.Length);
        outer.Position = 0;
        var options = Options(20, directBytes);
        options.Settings = options.Settings! with { DeepContainerMaxNestedArchiveBytes = 32768 };

        var analysis = FileInspector.Analyze(outer, options, "outer.zip");

        Assert.True(analysis.Flags.HasFlag(ContentFlags.ContainerContainsScripts));
        Assert.True(analysis.AnalysisComplete, string.Join(",", analysis.AnalysisIssues ?? Array.Empty<string>()));
        Assert.Equal(InspectionOutcome.Complete, analysis.Outcome);
    }

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
