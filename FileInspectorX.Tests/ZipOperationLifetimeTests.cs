using Xunit;

namespace FileInspectorX.Tests;

public sealed class ZipOperationLifetimeTests
{
    private static readonly byte[] Jar = ZipTestArchive.Create(
        ("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n"), ("Demo.class", "class bytes"), ("readme.txt", "hello"));

    private static FileInspector.DetectionOptions Options(int entries = 3) => new()
    {
        Settings = InspectionSettings.CaptureDefaults() with { ArchiveMaxEntries = entries, ZipSubtypeMaxEntries = 3 },
        IncludeAuthenticode = false, IncludePermissions = false, IncludeReferences = false,
        IncludeInstaller = false, IncludeAssessment = false
    };

    [Fact]
    public void ZipSubtypeAndContainerRetainIndependentEntryBudgetsAndBorrowedPosition()
    {
        using var stream = new MemoryStream(Jar, writable: false) { Position = 19 };
        var result = FileInspector.Analyze(stream, Options(), "sample.jar");
        Assert.Equal("jar", result.Detection!.GuessedExtension);
        Assert.Equal(3, result.ContainerEntryCount);
        Assert.True(result.AnalysisComplete, string.Join(",", result.AnalysisIssues ?? Array.Empty<string>()));
        Assert.Equal(19, stream.Position);
        Assert.True(stream.CanRead);

        // The next operation applies its own settings rather than reusing the
        // prior call's directory acceptance or mutable counters.
        var limited = FileInspector.Analyze(stream, Options(entries: 2), "sample.jar");
        Assert.False(limited.AnalysisComplete);
        Assert.Contains("archive:entry-count-limit", limited.AnalysisIssues!);
        Assert.Equal(19, stream.Position);
    }

    [Fact]
    public void SharedZipReaderReleasesThePathHandleBeforeReturning()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".jar");
        try
        {
            File.WriteAllBytes(path, Jar);
            var result = FileInspector.Analyze(path, Options());
            Assert.Equal(3, result.ContainerEntryCount);
            using var exclusive = File.Open(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            Assert.Equal(Jar.Length, exclusive.Length);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void UnavailableBorrowedPositionRetainsTypedInputFailure()
    {
        using var stream = new UnavailablePositionStream(Jar);
        var result = FileInspector.Analyze(stream, Options());
        Assert.Equal(InspectionInputStatus.Unreadable, result.InputStatus);
        Assert.Equal(InspectionOutcome.InputUnavailable, result.Outcome);
        Assert.True(stream.CanRead);
    }

    private sealed class UnavailablePositionStream : MemoryStream
    {
        internal UnavailablePositionStream(byte[] bytes) : base(bytes, writable: false) { }
        public override long Position { get => throw new IOException("Position unavailable."); set => base.Position = value; }
    }
}
