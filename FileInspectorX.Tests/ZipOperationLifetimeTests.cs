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

    [Theory]
    [InlineData(0, LearnedClassificationMode.Off)]
    [InlineData(1, LearnedClassificationMode.Off)]
    [InlineData(2, LearnedClassificationMode.Off)]
    [InlineData(0, LearnedClassificationMode.Assist)]
    [InlineData(1, LearnedClassificationMode.Assist)]
    [InlineData(2, LearnedClassificationMode.Assist)]
    public void UnavailableBorrowedPositionRetainsTypedInputFailure(int facade, LearnedClassificationMode mode)
    {
        using var stream = new UnavailablePositionStream(Jar);
        var options = Options();
        options.LearnedClassificationMode = mode;
        options.LearnedClassifier = new UnreachableClassifier();
        var result = InspectUnavailable(stream, options, facade);
        Assert.Equal(InspectionInputStatus.Unreadable, result.InputStatus);
        Assert.Equal(InspectionOutcome.InputUnavailable, result.Outcome);
        Assert.True(stream.CanRead);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public void RequiredClassifierTranslatesUnavailableBorrowedPosition(int facade)
    {
        using var stream = new UnavailablePositionStream(Jar);
        var options = Options();
        options.LearnedClassificationMode = LearnedClassificationMode.Required;
        options.LearnedClassifier = new UnreachableClassifier();
        var exception = Assert.Throws<LearnedClassificationException>(() => InspectUnavailable(stream, options, facade));
        Assert.IsType<IOException>(exception.InnerException);
        Assert.True(stream.CanRead);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void PathZipDetectionRetainsCompatibleWriterSharing(bool docx, bool includeContainer)
    {
        // File sharing is enforced by Windows; Unix permits these handles regardless of FileShare.
        if (Environment.OSVersion.Platform != PlatformID.Win32NT) return;
        var bytes = docx ? ZipTestArchive.Create(
            ("[Content_Types].xml", "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"/>"),
            ("word/document.xml", "<document/>")) : Jar;
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".zip");
        try
        {
            File.WriteAllBytes(path, bytes);
            using var writer = File.Open(path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete);
            var detected = FileInspector.Detect(path)!;
            Assert.Equal(docx ? "docx" : "jar", docx ? detected.Extension : detected.GuessedExtension);
            var options = Options();
            options.IncludeContainer = includeContainer;
            foreach (var result in new[] { FileInspector.Analyze(path, options), FileInspector.Inspect(path, options) })
            {
                Assert.Equal(detected.Extension, result.Detection!.Extension);
                Assert.Equal(detected.GuessedExtension, result.Detection.GuessedExtension);
                if (includeContainer) Assert.Equal(docx ? 2 : 3, result.ContainerEntryCount);
            }
        }
        finally { File.Delete(path); }
    }

    private static FileAnalysis InspectUnavailable(Stream stream, FileInspector.DetectionOptions options, int facade)
    {
        options.DetectOnly = facade == 2;
        return facade == 0 ? FileInspector.Analyze(stream, options) : FileInspector.Inspect(stream, options);
    }

    private sealed class UnreachableClassifier : ILearnedContentClassifier
    {
        public LearnedContentPrediction Predict(ReadOnlyMemory<byte> content) => throw new InvalidOperationException("Unreadable input cannot reach the provider.");
        public LearnedContentPrediction Predict(Stream content) => throw new InvalidOperationException("Unreadable input cannot reach the provider.");
    }

    private sealed class UnavailablePositionStream : MemoryStream
    {
        internal UnavailablePositionStream(byte[] bytes) : base(bytes, writable: false) { }
        public override long Position { get => throw new IOException("Position unavailable."); set => base.Position = value; }
    }
}
