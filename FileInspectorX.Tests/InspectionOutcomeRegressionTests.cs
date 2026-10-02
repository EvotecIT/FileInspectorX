using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class InspectionOutcomeRegressionTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void AnalysisDetectionViewsRetainTheAnalysisStatusAndMetrics(bool detectOnly)
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".json");
        try
        {
            File.WriteAllText(path, "{\"value\":1}");
            var options = new FileInspector.DetectionOptions { DetectOnly = detectOnly, CollectMetrics = true };
            var analysis = FileInspector.Inspect(path, options);
            var view = analysis.ToDetectionView(path);
            Assert.Same(analysis.Metrics, view.Metrics);
            Assert.Equal(analysis.InputStatus, view.InputStatus);
            File.Delete(path);
            var missing = FileInspector.Inspect(path, options).ToDetectionView(path);
            Assert.Equal(InspectionInputStatus.Unreadable, missing.InputStatus);
            Assert.NotNull(missing.Metrics);
            Assert.Equal(0, missing.Metrics!.StreamBytesRead);
        }
        finally { File.Delete(path); }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    public void MetricsAloneRetainReadableUnknownDetectionAcrossInputs(int shape)
    {
        var options = new FileInspector.DetectionOptions { CollectMetrics = true };
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".bin");
        try
        {
            File.WriteAllBytes(path, Array.Empty<byte>());
            using var stream = new MemoryStream();
            ContentTypeDetectionResult? Detect(FileInspector.DetectionOptions? selected) => shape switch {
                0 => FileInspector.Detect(Array.Empty<byte>(), selected),
                1 => FileInspector.Detect(ReadOnlyMemory<byte>.Empty, selected),
                2 => FileInspector.Detect(ReadOnlySpan<byte>.Empty, selected),
                3 => FileInspector.Detect(stream, selected),
                _ => FileInspector.Detect(path, selected)
            };
            Assert.Null(Detect(null));
            var result = Detect(options);
            Assert.NotNull(result);
            Assert.Equal(InspectionInputStatus.Unrecognized, result!.InputStatus);
            Assert.NotNull(result.Metrics);
            Assert.Equal(0, result.Metrics!.HashBytes);
            Assert.Equal(0, result.Metrics.StreamBytesRead);
            File.Delete(path);
            Assert.Null(FileInspector.Detect(path, options)); // unreadable input retains nullable detection behavior
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void PlainXmlTimeoutCannotReportCompletedValidation()
    {
        var xml = "<?xml version=\"1.0\"?><root>" + string.Concat(Enumerable.Repeat("<node/>", 400_000)) + "</root>";
        var settings = InspectionSettings.CaptureDefaults() with { XmlWellFormednessTimeoutMs = 1, DetectionReadBudgetBytes = 4 * 1024 * 1024 };
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".xml");
        try
        {
            File.WriteAllText(path, xml);
            var analysis = FileInspector.Inspect(path, new() { DetectOnly = true, Settings = settings });
            Assert.Equal(StructuredValidationOutcome.TimedOut, analysis.Detection!.StructuredValidation);
            Assert.Equal(InspectionStageStatus.Partial, InspectionOutcomesTests.Stage(analysis, InspectionStage.StructuredValidation).Status);
            Assert.Equal(InspectionOutcome.Partial, analysis.Outcome);
        }
        finally { File.Delete(path); }
    }

    [Theory]
    [InlineData("xml", "root")]
    [InlineData("admx", "policyDefinitions")]
    public void XmlDepthLimitsArePartialRatherThanNegativeValidation(string extension, string root)
    {
        var xml = "<?xml version=\"1.0\"?><" + root + ">" + string.Concat(Enumerable.Repeat("<node>", 258)) +
            string.Concat(Enumerable.Repeat("</node>", 258)) + "</" + root + ">";
        var settings = InspectionSettings.CaptureDefaults() with { XmlWellFormednessTimeoutMs = 0 };
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + "." + extension);
        try
        {
            File.WriteAllText(path, xml);
            var analysis = FileInspector.Inspect(path, new() { DetectOnly = true, Settings = settings });
            Assert.Equal(StructuredValidationOutcome.Skipped, analysis.Detection!.StructuredValidation);
            Assert.Equal(InspectionOutcome.Partial, analysis.Outcome);
        }
        finally { File.Delete(path); }
    }

    [Theory]
    [InlineData("json", "{\"value\":1}")]
    [InlineData("xml", "<?xml version=\"1.0\"?><root/>")]
    public void ValidationReadFailureIsUnavailableRatherThanContentRejection(string extension, string content)
    {
        using var input = new ValidationReadFailure(Encoding.UTF8.GetBytes(content));
        var result = FileInspector.Detect(input, declaredExtension: extension);
        Assert.NotNull(result);
        Assert.Equal(StructuredValidationOutcome.Unavailable, result!.StructuredValidation);
        Assert.Equal(0, input.Position);
        Assert.True(input.CanRead);
    }

    [Fact]
    public void MetricsDoNotChangeTheNullablePrivateDetectionOrAnalysisPolicy()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".bin");
        try
        {
            File.WriteAllBytes(path, Array.Empty<byte>());
            var ordinary = FileInspector.Analyze(path);
            var measured = FileInspector.Analyze(path, new() { CollectMetrics = true });
            Assert.Null(ordinary.Detection);
            Assert.Null(measured.Detection);
            Assert.Equal(ordinary.Flags, measured.Flags);
            Assert.Equal(ordinary.Assessment!.Decision, measured.Assessment!.Decision);
            Assert.Null(measured.Security);
            Assert.NotNull(measured.Metrics);
            // A parent collector must not change a provider's uninstrumented nested detections.
            var classified = FileInspector.Detect(Encoding.UTF8.GetBytes("{\"value\":1}"), new() {
                CollectMetrics = true, LearnedClassificationMode = LearnedClassificationMode.Assist,
                LearnedClassifier = new NullableDetectionClassifier()
            });
            Assert.NotEqual(LearnedClassificationDisposition.Failed, classified!.LearnedClassification!.Disposition);
        }
        finally { File.Delete(path); }
    }

    private sealed class ValidationReadFailure : Stream
    {
        private readonly MemoryStream _inner;
        private bool _readFromStart;
        internal ValidationReadFailure(byte[] bytes) => _inner = new MemoryStream(bytes);
        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => _inner.Length;
        public override long Position { get => _inner.Position; set => _inner.Position = value; }
        public override long Seek(long offset, SeekOrigin origin) => _inner.Seek(offset, origin);
        public override int Read(byte[] buffer, int offset, int count)
        {
            if (_inner.Position == 0)
            {
                if (_readFromStart) throw new IOException("Validation read unavailable");
                _readFromStart = true;
            }
            return _inner.Read(buffer, offset, count);
        }
        public override void Flush() { }
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) { if (disposing) _inner.Dispose(); base.Dispose(disposing); }
    }

    private sealed class NullableDetectionClassifier : ILearnedContentClassifier
    {
        public LearnedContentPrediction Predict(Stream content) => Predict(ReadOnlyMemory<byte>.Empty);
        public LearnedContentPrediction Predict(ReadOnlyMemory<byte> content)
        {
            if (FileInspector.Detect(Array.Empty<byte>()) != null || FileInspector.Detect(ReadOnlyMemory<byte>.Empty, new FileInspector.DetectionOptions()) != null)
                throw new InvalidOperationException("Inherited metrics changed nullable detection");
            return new LearnedContentPrediction { Provider = "test", OutputLabel = "json", Extension = "json", Probability = 1, ThresholdMet = true };
        }
    }
}
