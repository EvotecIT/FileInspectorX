using System.Text;
using System.Threading;
using Xunit;

namespace FileInspectorX.Tests;

[Collection(nameof(DetectionSettingsCollection))]
public sealed class OperationControlsTests
{
    private static readonly byte[] Json = Encoding.UTF8.GetBytes("{\"name\":\"inspection\",\"nested\":{\"value\":1}}");

    [Fact]
    public void SnapshotsCopyCollectionsAndPreserveTheirComparers()
    {
        var domains = new[] { "example.org" };
        var scores = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase) { ["ext:JSON"] = 8 };
        var dangerous = new HashSet<string>(StringComparer.Ordinal) { "json" };
        var settings = InspectionSettings.CaptureDefaults() with {
            HtmlAllowedDomains = domains, DetectionScoreAdjustments = scores, DangerousExtensionsOverride = dangerous
        };
        domains[0] = "changed.org";
        scores["ext:JSON"] = 999;
        dangerous.Clear();

        Assert.Equal("example.org", settings.HtmlAllowedDomains[0]);
        Assert.Equal(8, settings.DetectionScoreAdjustments["ext:json"]);
        Assert.True(FileInspector.Detect(Json, new() { Settings = settings })!.IsDangerous);
        Assert.Throws<NotSupportedException>(() => ((IList<string>)settings.HtmlAllowedDomains)[0] = "changed");
        Assert.Throws<NotSupportedException>(() => ((IDictionary<string, int>)settings.DetectionScoreAdjustments).Clear());
        Assert.Throws<NotSupportedException>(() => ((ISet<string>)settings.DangerousExtensionsOverride!).Clear());
    }

    [Fact]
    public async Task ConcurrentOperationsKeepIndependentPolicies()
    {
        var defaults = InspectionSettings.CaptureDefaults();
        var dangerous = defaults with { DangerousExtensionsOverride = new[] { "json" } };
        var safe = defaults with { DangerousExtensionsOverride = new[] { "safe" } };
        await Task.WhenAll(Run(dangerous, true), Run(safe, false));

        static Task Run(InspectionSettings settings, bool expected) => Task.Run(() => {
            for (int i = 0; i < 40; i++) Assert.Equal(expected, FileInspector.Detect(Json, new() { Settings = settings })!.IsDangerous);
        });
    }

    [Fact]
    public void SnapshotIgnoresGlobalChangesDuringBorrowedStreamRead()
    {
        var previous = Settings.DangerousExtensionsOverride;
        try
        {
            Settings.DangerousExtensionsOverride = new HashSet<string> { "json" };
            var snapshot = InspectionSettings.CaptureDefaults();
            using var stream = new CallbackStream(Json, () => Settings.DangerousExtensionsOverride = new HashSet<string> { "safe" });
            Assert.True(FileInspector.Detect(stream, new() { Settings = snapshot })!.IsDangerous);
            Assert.Equal(0, stream.Position);
            Assert.False(FileInspector.Detect(Json)!.IsDangerous);
        }
        finally { Settings.DangerousExtensionsOverride = previous; }
    }

    [Fact]
    public void OperationCapturesMutableOptionsBeforeReadingInput()
    {
        var options = new FileInspector.DetectionOptions { ComputeSha256 = true, MagicHeaderBytes = 8 };
        using var stream = new CallbackStream(Json, () => { options.ComputeSha256 = false; options.MagicHeaderBytes = 0; });
        var result = FileInspector.Detect(stream, options);
        using var hash = System.Security.Cryptography.SHA256.Create();
        Assert.Equal(BitConverter.ToString(hash.ComputeHash(Json)).Replace("-", "").ToLowerInvariant(), result!.Sha256Hex);
        Assert.Equal(16, result.MagicHeaderHex!.Length);
    }

    [Fact]
    public void PreCanceledOperationsThrowBeforeReadingOrReportingInputFailure()
    {
        using var cancel = new CancellationTokenSource();
        cancel.Cancel();
        var options = new FileInspector.DetectionOptions { CancellationToken = cancel.Token };
        using var stream = new MemoryStream(Json) { Position = 3 };
        Assert.Throws<OperationCanceledException>(() => FileInspector.Detect(stream, options));
        Assert.Equal(3, stream.Position);
        Assert.Throws<OperationCanceledException>(() => FileInspector.Detect(Json, options));
        Assert.Throws<OperationCanceledException>(() => FileInspector.Detect(Json.AsSpan(), options));
        Assert.Throws<OperationCanceledException>(() => FileInspector.Analyze("missing-canceled-input", options));
        Assert.Throws<OperationCanceledException>(() => FileInspector.Inspect("missing-canceled-input", options));
        Assert.Throws<OperationCanceledException>(() => FileInspector.AnalyzeDirectory("missing-canceled-directory", options: options).ToList());
    }

    [Fact]
    public void MidHashCancellationRestoresCallerPositionAndScope()
    {
        using var cancel = new CancellationTokenSource();
        var bytes = Encoding.UTF8.GetBytes("{\"name\":\"inspection\"}" + new string(' ', 2 * 1024 * 1024));
        using var stream = new CancelDuringHashStream(bytes, cancel) { Position = 7 };
        var settings = InspectionSettings.CaptureDefaults() with { DangerousExtensionsOverride = new[] { "json" } };
        Assert.Throws<OperationCanceledException>(() => FileInspector.Detect(stream, new() { Settings = settings, ComputeSha256 = true, CancellationToken = cancel.Token }));
        Assert.True(stream.HashReadCount > 0);
        Assert.Equal(7, stream.Position);
        Assert.True(stream.CanRead);
        Assert.False(FileInspector.Detect(Json)!.IsDangerous);
    }

    [Theory]
    [InlineData(LearnedClassificationMode.Assist)]
    [InlineData(LearnedClassificationMode.Required)]
    public void ProviderCancellationIsNotConvertedToClassificationFailure(LearnedClassificationMode mode)
    {
        var options = new FileInspector.DetectionOptions { LearnedClassifier = new CancelingProvider(), LearnedClassificationMode = mode };
        Assert.Throws<OperationCanceledException>(() => FileInspector.Detect(Json, options));
        using var stream = new MemoryStream(Json);
        Assert.Throws<OperationCanceledException>(() => FileInspector.Detect(stream, options));
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, Json);
            Assert.Throws<OperationCanceledException>(() => FileInspector.Analyze(path, options));
            Assert.Throws<OperationCanceledException>(() => FileInspector.Inspect(path, options));
            options.DetectOnly = true;
            Assert.Throws<OperationCanceledException>(() => FileInspector.Inspect(path, options));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void CancellableProviderReceivesTheOperationToken()
    {
        using var cancel = new CancellationTokenSource();
        var provider = new CancellableProvider(cancel);
        Assert.Throws<OperationCanceledException>(() => FileInspector.Detect(Json, new() {
            CancellationToken = cancel.Token, LearnedClassifier = provider, LearnedClassificationMode = LearnedClassificationMode.Assist
        }));
        Assert.Equal(cancel.Token, provider.ObservedToken);
    }

    [Fact]
    public async Task CancellationDoesNotWaitForAnotherPredictionHoldingTheProviderLock()
    {
        using var provider = new PausingProvider();
        using var cancel = new CancellationTokenSource();
        var first = Task.Run(() => FileInspector.Detect(Json, new() { LearnedClassifier = provider, LearnedClassificationMode = LearnedClassificationMode.Required }));
        try
        {
            Assert.True(provider.Entered.Wait(TimeSpan.FromSeconds(10)));
            var second = Task.Run(() => FileInspector.Detect(Json, new() {
                LearnedClassifier = provider, LearnedClassificationMode = LearnedClassificationMode.Required, CancellationToken = cancel.Token
            }));
            await Task.Delay(100);
            cancel.Cancel();
            Assert.Same(second, await Task.WhenAny(second, Task.Delay(TimeSpan.FromSeconds(5))));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => { await second; });
            Assert.Equal(1, provider.Calls);
        }
        finally { provider.Release.Set(); await first; }
    }

    [Fact]
    public void ProfilesReturnFreshOptionsAndAssessmentAcceptsFrozenPolicy()
    {
        var snapshot = InspectionSettings.CaptureDefaults() with { AssessmentWarnThreshold = 0, AssessmentBlockThreshold = 100 };
        var quick = InspectionProfile.Quick(snapshot);
        Assert.True(quick.CreateOptions().DetectOnly);
        Assert.NotSame(quick.CreateOptions(), quick.CreateOptions());
        Assert.False(InspectionProfile.Bounded(snapshot).CreateOptions().DetectOnly);
        Assert.True(InspectionProfile.Deep(snapshot).Settings.DeepContainerScanEnabled);
        Assert.Equal(snapshot.ArchiveMaxTotalReadBytes, InspectionProfile.Deep(snapshot).Settings.ArchiveMaxTotalReadBytes);
        Assert.Equal(AssessmentDecision.Warn, FileInspector.Assess(new FileAnalysis(), snapshot).Decision);
    }

    [Fact]
    public void DirectoryEnumerationCapturesOptionsAcrossYieldBoundaries()
    {
        var directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            File.WriteAllBytes(Path.Combine(directory, "a.json"), Json);
            File.WriteAllBytes(Path.Combine(directory, "b.json"), Json);
            var options = new FileInspector.DetectionOptions { ComputeSha256 = true, IncludeAuthenticode = false, IncludePermissions = false };
            using var enumerator = FileInspector.AnalyzeDirectory(directory, options: options).GetEnumerator();
            Assert.True(enumerator.MoveNext());
            Assert.NotNull(enumerator.Current.Detection!.Sha256Hex);
            options.ComputeSha256 = false;
            Assert.True(enumerator.MoveNext());
            Assert.NotNull(enumerator.Current.Detection!.Sha256Hex);
        }
        finally { Directory.Delete(directory, true); }
    }

#if NET8_0_OR_GREATER
    [Fact]
    public async Task AsyncDirectoryDisposalCancelsSupportedInFlightProvider()
    {
        var directory = Directory.CreateTempSubdirectory();
        using var provider = new WaitingCancellableProvider();
        try
        {
            for (int i = 0; i < 5; i++) File.WriteAllBytes(Path.Combine(directory.FullName, i + ".json"), Json);
            var enumerator = FileInspector.AnalyzeDirectoryAsync(directory.FullName, maxDegreeOfParallelism: 1, options: new() {
                LearnedClassifier = provider, LearnedClassificationMode = LearnedClassificationMode.Required,
                IncludePermissions = false, IncludeAuthenticode = false
            }).GetAsyncEnumerator();
            try
            {
                Assert.True(await enumerator.MoveNextAsync());
                Assert.True(provider.SecondEntered.Wait(TimeSpan.FromSeconds(10)));
                await enumerator.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));
                Assert.Equal(2, provider.Calls);
                Assert.True(provider.Canceled);
            }
            finally { await enumerator.DisposeAsync(); }
        }
        finally { directory.Delete(true); }
    }

    private sealed class WaitingCancellableProvider : ICancellableLearnedContentClassifier, IDisposable
    {
        internal readonly ManualResetEventSlim SecondEntered = new(false);
        internal int Calls;
        internal bool Canceled;
        public LearnedContentPrediction Predict(Stream content) => throw new InvalidOperationException("Token required.");
        public LearnedContentPrediction Predict(ReadOnlyMemory<byte> content) => throw new InvalidOperationException("Token required.");
        public LearnedContentPrediction Predict(ReadOnlyMemory<byte> content, CancellationToken token) => Predict(Stream.Null, token);
        public LearnedContentPrediction Predict(Stream content, CancellationToken token)
        {
            if (Interlocked.Increment(ref Calls) == 2)
            {
                SecondEntered.Set();
                if (!token.WaitHandle.WaitOne(TimeSpan.FromSeconds(10))) throw new TimeoutException();
                Canceled = token.IsCancellationRequested;
                token.ThrowIfCancellationRequested();
            }
            return new LearnedContentPrediction { Provider = "test", Extension = "txt", OutputLabel = "txt", Probability = 1, ThresholdMet = true };
        }
        public void Dispose() => SecondEntered.Dispose();
    }
#endif

    private sealed class CallbackStream : MemoryStream
    {
        private readonly Action _callback;
        private bool _called;
        internal CallbackStream(byte[] content, Action callback) : base(content, writable: false) => _callback = callback;
        public override int Read(byte[] buffer, int offset, int count)
        {
            if (!_called) { _called = true; _callback(); }
            return base.Read(buffer, offset, count);
        }
    }

    private sealed class CancelDuringHashStream : MemoryStream
    {
        private readonly CancellationTokenSource _cancel;
        internal int HashReadCount;
        internal CancelDuringHashStream(byte[] content, CancellationTokenSource cancel) : base(content, writable: false) => _cancel = cancel;
        public override int Read(byte[] buffer, int offset, int count)
        {
            int read = base.Read(buffer, offset, count);
            if (count == 8192 && ++HashReadCount == 12) _cancel.Cancel();
            return read;
        }
    }

    private sealed class CancelingProvider : ILearnedContentClassifier
    {
        public LearnedContentPrediction Predict(Stream content) => throw new OperationCanceledException();
        public LearnedContentPrediction Predict(ReadOnlyMemory<byte> content) => throw new OperationCanceledException();
    }

    private sealed class CancellableProvider : ICancellableLearnedContentClassifier
    {
        private readonly CancellationTokenSource _cancel;
        internal CancellationToken ObservedToken;
        internal CancellableProvider(CancellationTokenSource cancel) => _cancel = cancel;
        public LearnedContentPrediction Predict(Stream content) => throw new InvalidOperationException("Token overload required.");
        public LearnedContentPrediction Predict(ReadOnlyMemory<byte> content) => throw new InvalidOperationException("Token overload required.");
        public LearnedContentPrediction Predict(Stream content, CancellationToken token) => Predict(ReadOnlyMemory<byte>.Empty, token);
        public LearnedContentPrediction Predict(ReadOnlyMemory<byte> content, CancellationToken token)
        {
            ObservedToken = token;
            _cancel.Cancel();
            token.ThrowIfCancellationRequested();
            throw new InvalidOperationException();
        }
    }

    private sealed class PausingProvider : ILearnedContentClassifier, IDisposable
    {
        internal readonly ManualResetEventSlim Entered = new(false);
        internal readonly ManualResetEventSlim Release = new(false);
        internal int Calls;
        public LearnedContentPrediction Predict(Stream content) => Predict(ReadOnlyMemory<byte>.Empty);
        public LearnedContentPrediction Predict(ReadOnlyMemory<byte> content)
        {
            Interlocked.Increment(ref Calls);
            Entered.Set();
            if (!Release.Wait(TimeSpan.FromSeconds(10))) throw new TimeoutException();
            return new LearnedContentPrediction { Provider = "test", Extension = "txt", OutputLabel = "txt", Probability = 1, ThresholdMet = true };
        }
        public void Dispose() { Entered.Dispose(); Release.Dispose(); }
    }
}
