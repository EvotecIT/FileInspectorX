using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class InspectionMetricsTests
{
    private static readonly byte[] Json = Encoding.UTF8.GetBytes("{\"value\":1}");

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void StreamCountersMatchActualReadsAndHashCountsCompleteInput(bool seekable)
    {
        using var input = new CountingInput(Json, seekable);
        if (seekable) input.Position = 3;
        var result = FileInspector.Detect(input, new() { CollectMetrics = true, ComputeSha256 = true });
        var metrics = result!.Metrics!;
        Assert.Equal(input.BytesRead, metrics.StreamBytesRead);
        Assert.Equal(input.ReadCalls, metrics.ReadOperations);
        Assert.Equal(Json.Length, metrics.HashBytes);
        Assert.True(metrics.Elapsed >= TimeSpan.Zero);
        Assert.Equal(1, Assert.Single(metrics.Stages, stage => stage.Stage == InspectionStage.Detection).Invocations);
        Assert.Equal(1, Assert.Single(metrics.Stages, stage => stage.Stage == InspectionStage.Sha256).Invocations);
        Assert.False(input.Disposed);
        if (seekable) Assert.Equal(3, input.Position);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public void ArrayMemoryAndSpanHashCountersDoNotPretendToReadDisk(int shape)
    {
        var options = new FileInspector.DetectionOptions { CollectMetrics = true, ComputeSha256 = true };
        var result = shape switch {
            0 => FileInspector.Detect(Json, options),
            1 => FileInspector.Detect(Json.AsMemory(), options),
            _ => FileInspector.Detect(Json.AsSpan(), options)
        };
        Assert.Equal(Json.Length, result!.Metrics!.HashBytes);
        Assert.Equal(0, result.Metrics.StreamBytesRead);
        Assert.Equal(0, result.Metrics.ReadOperations);
        Assert.Equal(result.Metrics, DetectionView.From("input", result).Metrics);
        Assert.Null(FileInspector.Detect(Json)!.Metrics);
    }

    [Fact]
    public void NestedProviderDetectionCountsReadsOnceAndSnapshotsStayIsolated()
    {
        using var input = new CountingInput(Json, true);
        using var token = new CancellationTokenSource();
        var classifier = new NestedClassifier();
        var result = FileInspector.Detect(input, new() {
            CollectMetrics = true, CancellationToken = token.Token,
            LearnedClassificationMode = LearnedClassificationMode.Assist, LearnedClassifier = classifier
        });
        var metrics = result!.Metrics!;
        Assert.Equal(input.BytesRead, metrics.StreamBytesRead);
        Assert.Equal(input.ReadCalls, metrics.ReadOperations);
        Assert.Equal(Json.Length, metrics.HashBytes);
        Assert.Equal(1, metrics.ClassifierAttempts);
        Assert.Equal(0, metrics.ClassifierFailures);
        Assert.Equal(3, Assert.Single(metrics.Stages, stage => stage.Stage == InspectionStage.Detection).Invocations);
        Assert.Equal(1, Assert.Single(classifier.Nested!.Metrics!.Stages, stage => stage.Stage == InspectionStage.Detection).Invocations);
        Assert.Equal(0, classifier.Nested.Metrics.ClassifierAttempts);
        var retainedBytes = metrics.StreamBytesRead;
        Assert.Null(FileInspector.Detect(Json)!.Metrics);
        FileInspector.Detect(new byte[100], new FileInspector.DetectionOptions { ComputeSha256 = true, CollectMetrics = true });
        Assert.Equal(retainedBytes, metrics.StreamBytesRead);
        Assert.False(input.Disposed);
    }

    [Fact]
    public async Task ParallelOperationsAndDirectoryWorkersKeepSeparateCounters()
    {
        var tasks = Enumerable.Range(1, 8).Select(size => Task.Run(() =>
            FileInspector.Detect(new byte[size * 100], new FileInspector.DetectionOptions { CollectMetrics = true, ComputeSha256 = true })!.Metrics!)).ToArray();
        var metrics = await Task.WhenAll(tasks);
        for (int i = 0; i < metrics.Length; i++)
        {
            Assert.Equal((i + 1) * 100, metrics[i].HashBytes);
            Assert.Equal(0, metrics[i].StreamBytesRead);
        }
        var directory = Path.Combine(Path.GetTempPath(), "FileInspectorX-metrics-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            for (int i = 1; i <= 4; i++) File.WriteAllBytes(Path.Combine(directory, i + ".bin"), new byte[i * 100]);
            var analyses = FileInspector.AnalyzeDirectory(directory, options: new() { DetectOnly = true, CollectMetrics = true, ComputeSha256 = true }).ToList();
            Assert.Equal(4, analyses.Count);
            Assert.Equal(new long[] { 100, 200, 300, 400 }, analyses.Select(item => item.Metrics!.HashBytes).OrderBy(bytes => bytes));
            Assert.All(analyses, item => Assert.Equal(1, Assert.Single(item.Metrics!.Stages, stage => stage.Stage == InspectionStage.Detection).Invocations));
#if NET8_0_OR_GREATER
            var concurrent = new List<FileAnalysis>();
            await foreach (var analysis in FileInspector.AnalyzeDirectoryAsync(directory,
                options: new() { CollectMetrics = true, ComputeSha256 = true }, maxDegreeOfParallelism: 2)) concurrent.Add(analysis);
            Assert.Equal(new long[] { 100, 200, 300, 400 }, concurrent.Select(item => item.Metrics!.HashBytes).OrderBy(bytes => bytes));
#endif
        }
        finally { Directory.Delete(directory, true); }
    }

    [Fact]
    public void CancellationThrowsAndDoesNotLeakMetricsIntoTheNextCall()
    {
        using var token = new CancellationTokenSource();
        using var input = new CountingInput(Json, true, token.Cancel);
        Assert.Throws<OperationCanceledException>(() => FileInspector.Detect(input, new() { CollectMetrics = true, CancellationToken = token.Token }));
        Assert.False(input.Disposed);
        Assert.Equal(0, input.Position);
        var next = FileInspector.Detect(Json, new FileInspector.DetectionOptions { CollectMetrics = true, ComputeSha256 = true });
        Assert.Equal(Json.Length, next!.Metrics!.HashBytes);
        Assert.Equal(0, next.Metrics.StreamBytesRead);
    }

    [Fact]
    public void CollectionOptionIsCapturedBeforeTheFirstRead()
    {
        var options = new FileInspector.DetectionOptions { CollectMetrics = true, ComputeSha256 = true };
        using var input = new CountingInput(Json, true, () => options.CollectMetrics = false);
        Assert.Equal(Json.Length, FileInspector.Detect(input, options)!.Metrics!.HashBytes);
        Assert.Null(FileInspector.Detect(Json, options)!.Metrics);
    }

    [Fact]
    public void ArchiveMetricsCountExpandedReadsAndMalformedMetadataIsNotALimit()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".zip");
        try
        {
            var bytes = ZipTestArchive.Create(("one.txt", "one"), ("two.txt", "two"));
            File.WriteAllBytes(path, bytes);
            var settings = InspectionSettings.CaptureDefaults() with {
                DeepContainerScanEnabled = true, DeepContainerMaxEntries = 2, DeepContainerMaxEntryBytes = 64
            };
            var result = FileInspector.Inspect(path, new() { CollectMetrics = true, Settings = settings });
            // Two visits for subtype detection and two for the container analyzer.
            Assert.Equal(4, result.Metrics!.ArchiveEntriesVisited);
            Assert.True(result.Metrics.ArchivePayloadBytesRead >= 6);
            Assert.Equal(0, result.Metrics.ArchiveLimitHits);
            // Entry probes are nested detection calls and participate in the enclosing operation.
            Assert.True(Assert.Single(result.Metrics.Stages, stage => stage.Stage == InspectionStage.Detection).Invocations > 1);
            Assert.Equal(1, Assert.Single(result.Metrics.Stages, stage => stage.Stage == InspectionStage.Container).Invocations);
            Assert.True(Assert.Single(result.Metrics.Stages, stage => stage.Stage == InspectionStage.Assessment).Invocations > 1);
            ZipTestArchive.Write32(bytes, bytes.Length - 6, 0);
            File.WriteAllBytes(path, bytes);
            var malformed = FileInspector.Analyze(path, new() { CollectMetrics = true });
            Assert.Equal(InspectionOutcome.Partial, malformed.Outcome);
            Assert.Equal(0, malformed.Metrics!.ArchiveLimitHits);
            Assert.Equal(0, malformed.Metrics.ArchivePayloadBytesRead);
        }
        finally { File.Delete(path); }
    }

    private sealed class NestedClassifier : ILearnedContentClassifier
    {
        internal ContentTypeDetectionResult? Nested;
        public LearnedContentPrediction Predict(ReadOnlyMemory<byte> content) => throw new NotSupportedException();
        public LearnedContentPrediction Predict(Stream content)
        {
            // Different tokens create several borrowed cancellation wrappers around the same input.
            using var first = new CancellationTokenSource();
            using var second = new CancellationTokenSource();
            Nested = FileInspector.Detect(content, new() { CancellationToken = first.Token, ComputeSha256 = true });
            FileInspector.Detect(content, new() { CancellationToken = second.Token });
            return new LearnedContentPrediction { Provider = "test", ModelId = "test", OutputLabel = "json", Extension = "json", Probability = 1, ThresholdMet = true };
        }
    }

    private sealed class CountingInput : Stream
    {
        private readonly MemoryStream _inner;
        private readonly bool _seekable;
        private Action? _afterRead;
        internal long BytesRead, ReadCalls;
        internal bool Disposed;
        internal CountingInput(byte[] bytes, bool seekable, Action? afterRead = null)
        { _inner = new MemoryStream(bytes); _seekable = seekable; _afterRead = afterRead; }
        public override bool CanRead => true;
        public override bool CanSeek => _seekable;
        public override bool CanWrite => false;
        public override long Length => _seekable ? _inner.Length : throw new NotSupportedException();
        public override long Position { get => _seekable ? _inner.Position : throw new NotSupportedException(); set { if (!_seekable) throw new NotSupportedException(); _inner.Position = value; } }
        public override int Read(byte[] buffer, int offset, int count) => Record(_inner.Read(buffer, offset, count));
        public override int ReadByte() { int value = _inner.ReadByte(); Record(value < 0 ? 0 : 1); return value; }
#if NET8_0_OR_GREATER
        public override int Read(Span<byte> buffer) => Record(_inner.Read(buffer));
#endif
        private int Record(int count) { ReadCalls++; BytesRead += count; var action = _afterRead; _afterRead = null; action?.Invoke(); return count; }
        public override long Seek(long offset, SeekOrigin origin) => _seekable ? _inner.Seek(offset, origin) : throw new NotSupportedException();
        protected override void Dispose(bool disposing) { Disposed = true; if (disposing) _inner.Dispose(); base.Dispose(disposing); }
        public override void Flush() { }
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
