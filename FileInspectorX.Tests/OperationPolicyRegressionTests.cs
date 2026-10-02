using System.Collections.ObjectModel;
using System.IO.Compression;
using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

[Collection(nameof(DetectionSettingsCollection))]
public sealed class OperationPolicyRegressionTests
{
    [Fact]
    public void OpaqueScoreDictionariesRequireTheirComparerInsteadOfChangingLookupSemantics()
    {
        var previous = Settings.DetectionScoreAdjustments;
        try
        {
            Settings.DetectionScoreAdjustments = new ReadOnlyDictionary<string, int>(
                new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase) { ["ext:JSON"] = -20 });
            Assert.True(Settings.DetectionScoreAdjustments.ContainsKey("ext:json"));
            Assert.Throws<ArgumentException>(() => InspectionSettings.CaptureDefaults());
            var snapshot = InspectionSettings.CaptureDefaults(scoreComparer: StringComparer.OrdinalIgnoreCase);
            Assert.Equal(-20, snapshot.DetectionScoreAdjustments["ext:json"]);
        }
        finally { Settings.DetectionScoreAdjustments = previous; }
    }

    [Fact]
    public void SortedListScoresKeepTheirOrderingComparer()
    {
        var previous = Settings.DetectionScoreAdjustments;
        try
        {
            Settings.DetectionScoreAdjustments = new SortedList<string, int>(StringComparer.OrdinalIgnoreCase) { ["ext:JSON"] = -20 };
            Assert.Equal(-20, InspectionSettings.CaptureDefaults().DetectionScoreAdjustments["ext:json"]);
        }
        finally { Settings.DetectionScoreAdjustments = previous; }
    }

    [Fact]
    public void ExplicitCollectionCopiesPreserveOpaqueLookupPolicyAndCanChangeFrozenComparers()
    {
        var scores = new ReadOnlyDictionary<string, int>(new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase) { ["ext:JSON"] = -20 });
        var hashes = new ReadOnlyDictionary<string, string>(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["TOOL"] = "abc" });
        var set = new OpaqueSet(new HashSet<string>(StringComparer.Ordinal) { "json", "JSON" });
        var defaults = InspectionSettings.CaptureDefaults();
        Assert.Throws<ArgumentException>(() => defaults with { DetectionScoreAdjustments = scores });
        Assert.Throws<ArgumentException>(() => defaults with { KnownToolHashes = hashes });
        Assert.Throws<ArgumentException>(() => defaults with { DangerousExtensionsOverride = set });

        var snapshot = defaults.WithDetectionScoreAdjustments(scores, StringComparer.OrdinalIgnoreCase)
            .WithKnownToolHashes(hashes, StringComparer.OrdinalIgnoreCase)
            .WithDangerousExtensionsOverride(set, StringComparer.Ordinal);
        Assert.Equal(-20, snapshot.DetectionScoreAdjustments["ext:json"]);
        Assert.Equal("abc", snapshot.KnownToolHashes["tool"]);
        Assert.Equal(2, snapshot.DangerousExtensionsOverride!.Count);
        Assert.False(snapshot.WithDetectionScoreAdjustments(snapshot.DetectionScoreAdjustments, StringComparer.Ordinal)
            .DetectionScoreAdjustments.ContainsKey("ext:json"));

        var previousSet = Settings.DangerousExtensionsOverride;
        var previousHashes = Settings.KnownToolHashes;
        try
        {
            Settings.DangerousExtensionsOverride = set;
            Settings.KnownToolHashes = hashes;
            Assert.Throws<ArgumentException>(() => InspectionSettings.CaptureDefaults());
            var captured = InspectionSettings.CaptureDefaults(toolHashComparer: StringComparer.OrdinalIgnoreCase, dangerousExtensionComparer: StringComparer.Ordinal);
            Assert.Equal(2, captured.DangerousExtensionsOverride!.Count);
            Assert.Equal("abc", captured.KnownToolHashes["tool"]);
        }
        finally { Settings.DangerousExtensionsOverride = previousSet; Settings.KnownToolHashes = previousHashes; }
    }

    [Fact]
    public void DeferredAssessmentsUseResultPolicyAndAllowAnExplicitOverride()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, "{\"value\":1}");
            var settings = InspectionSettings.CaptureDefaults() with { AssessmentWarnThreshold = 0, AssessmentBlockThreshold = 100 };
            var analysis = FileInspector.Inspect(path, new() { Settings = settings, DetectOnly = true });
            Assert.Null(analysis.Assessment);
            Assert.Equal(AssessmentDecision.Warn, FileInspector.Assess(analysis).Decision);
            Assert.Equal(AssessmentDecision.Warn, FileInspector.AssessMulti(analysis).Balanced.Decision);
            Assert.Equal(AssessmentDecision.Warn, analysis.ToAssessmentView(path).Decision);
            var overrideSettings = settings with { AssessmentWarnThreshold = 100 };
            Assert.Equal(AssessmentDecision.Allow, FileInspector.Assess(analysis, overrideSettings).Decision);
            Assert.Equal(AssessmentDecision.Allow, FileInspector.AssessMulti(analysis, overrideSettings).Balanced.Decision);
        }
        finally { File.Delete(path); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void EtlQuickAndInputFailureResultsRetainProjectionPolicy(bool detectOnly)
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".etl");
        try
        {
            var settings = InspectionSettings.CaptureDefaults() with {
                EtlValidation = Settings.EtlValidationMode.MagicOnly, EtlLargeFileQuickScanBytes = 1, ReportHostFileMetadataEnabled = true
            };
            File.WriteAllBytes(path, new byte[] { 0x45, 0x6C, 0x66, 0x46, 0x00, 0x01 });
            var quick = FileInspector.Inspect(path, new() { Settings = settings, DetectOnly = detectOnly });
            Assert.Equal("etl", quick.DetectedExtension);
            Assert.Null(quick.Assessment);
            quick.Security = new FileSecurity { Owner = "snapshot-owner" };
            Assert.Equal("snapshot-owner", ReportView.From(quick).Owner);
            File.Delete(path);
            var failed = FileInspector.Analyze(path, new() { Settings = settings });
            Assert.False(failed.AnalysisComplete);
            failed.Security = new FileSecurity { Owner = "snapshot-owner" };
            Assert.Equal("snapshot-owner", ReportView.From(failed).Owner);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void LegacyReferenceProjectionKeepsThePolicyChosenBeforeEnumeration()
    {
        bool previous = Settings.ReferenceFullListsEnabled;
        try
        {
            Settings.ReferenceFullListsEnabled = true;
            var analysis = new FileAnalysis { References = new[] { new Reference { Value = "raw", ExpandedValue = "expanded" } } };
            var rows = analysis.ToReferencesView("test");
            Settings.ReferenceFullListsEnabled = false;
            Assert.Equal("expanded", Assert.Single(rows).ExpandedValue);
        }
        finally { Settings.ReferenceFullListsEnabled = previous; }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ResultProjectionsKeepFrozenPrivacyAndReferencePolicy(bool detectOnly)
    {
        bool previousHost = Settings.ReportHostFileMetadataEnabled;
        bool previousLists = Settings.ReferenceFullListsEnabled;
        int previousLimit = Settings.ReferenceFullListsMaxChars;
        var path = Path.GetTempFileName();
        try
        {
            Settings.ReportHostFileMetadataEnabled = true;
            Settings.ReferenceFullListsEnabled = false;
            Settings.ReferenceFullListsMaxChars = 200;
            var snapshot = InspectionSettings.CaptureDefaults() with {
                ReportHostFileMetadataEnabled = false, ReferenceFullListsEnabled = true, ReferenceFullListsMaxChars = 8
            };
            File.WriteAllText(path, "{\"value\":1}");
            var analysis = FileInspector.Inspect(path, new() {
                Settings = snapshot, DetectOnly = detectOnly, IncludePermissions = false, IncludeAuthenticode = false
            });
            // Use a portable security/reference result to exercise projections independently of host APIs.
            analysis.Security = new FileSecurity { Owner = "private-owner", OwnerId = "private-id" };
            analysis.References = new[] {
                new Reference { Kind = ReferenceKind.Url, Value = "https://example.org/one", ExpandedValue = "expanded-one", SourceTag = "html:link" },
                new Reference { Kind = ReferenceKind.Url, Value = "https://example.org/two", ExpandedValue = "expanded-two", SourceTag = "html:link" }
            };
            var report = ReportView.From(analysis);
            Assert.Null(report.Owner);
            Assert.Null(report.OwnerId);
            Assert.Equal("https://…", report.HtmlExternalLinksFull);
            Assert.Equal("expanded-one", report.References![0].ExpandedValue);

            using var rows = analysis.ToReferencesView(path).GetEnumerator();
            Assert.True(rows.MoveNext());
            Assert.Equal("expanded-one", rows.Current.ExpandedValue);
            Settings.ReferenceFullListsEnabled = false;
            Assert.True(rows.MoveNext());
            Assert.Equal("expanded-two", rows.Current.ExpandedValue);
        }
        finally
        {
            Settings.ReportHostFileMetadataEnabled = previousHost;
            Settings.ReferenceFullListsEnabled = previousLists;
            Settings.ReferenceFullListsMaxChars = previousLimit;
            File.Delete(path);
        }
    }

    [Theory]
    [InlineData("note.txt", true)]
    [InlineData("note.exe", true)]
    [InlineData("nested.zip", true)]
    [InlineData("note.txt", false)]
    [InlineData("note.exe", false)]
    [InlineData("nested.zip", false)]
    public void DeepZipAnalysisPropagatesProviderCancellationAndRequiredFailure(string entryName, bool cancel)
    {
        var path = Path.GetTempFileName();
        try
        {
            var content = entryName.EndsWith(".exe", StringComparison.Ordinal)
                ? new byte[] { (byte)'M', (byte)'Z', 0, 0, 0, 0, 0, 0 }
                : Encoding.UTF8.GetBytes("plain text for inner analysis");
            if (entryName.EndsWith(".zip", StringComparison.Ordinal)) content = CreateZip("note.txt", content);
            File.WriteAllBytes(path, CreateZip(entryName, content));
            var provider = new InnerFailureProvider(cancel);
            var options = new FileInspector.DetectionOptions {
                Settings = InspectionSettings.CaptureDefaults() with { DeepContainerScanEnabled = true },
                LearnedClassifier = provider, LearnedClassificationMode = LearnedClassificationMode.Required,
                IncludePermissions = false, IncludeAuthenticode = false
            };
            if (cancel) Assert.Throws<OperationCanceledException>(() => FileInspector.Analyze(path, options));
            else Assert.Throws<LearnedClassificationException>(() => FileInspector.Analyze(path, options));
            Assert.Equal(2, provider.Calls);
            // Temp child streams and the outer archive must be closed even on propagated failure.
            using var exclusive = File.Open(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        }
        finally { File.Delete(path); }
    }

#if NET8_0_OR_GREATER
    [Fact]
    public async Task FailingParallelWorkerCancelsSiblingProviderAndCompletesWithFailure()
    {
        var directory = Directory.CreateTempSubdirectory();
        using var provider = new SiblingFailureProvider();
        using var cleanup = new CancellationTokenSource();
        Task? read = null;
        try
        {
            File.WriteAllText(Path.Combine(directory.FullName, "a.json"), "{\"value\":1}");
            File.WriteAllText(Path.Combine(directory.FullName, "b.json"), "{\"value\":2}");
            read = Consume();
            var finished = await Task.WhenAny(read, Task.Delay(TimeSpan.FromSeconds(5)));
            Assert.Same(read, finished);
            await Assert.ThrowsAsync<LearnedClassificationException>(async () => await read);
            Assert.True(provider.SiblingCanceled);

            async Task Consume()
            {
                await foreach (var unused in FileInspector.AnalyzeDirectoryAsync(directory.FullName, maxDegreeOfParallelism: 2,
                    options: new() {
                        LearnedClassifier = provider, LearnedClassificationMode = LearnedClassificationMode.Required,
                        IncludePermissions = false, IncludeAuthenticode = false
                    }, ct: cleanup.Token)) { }
            }
        }
        finally
        {
            cleanup.Cancel();
            provider.Release.Set();
            if (read != null) { try { await read; } catch (Exception ex) when (ex is OperationCanceledException or LearnedClassificationException) { } }
            directory.Delete(true);
        }
    }

    private sealed class SiblingFailureProvider : ICancellableLearnedContentClassifier, IConcurrentLearnedContentClassifier, IDisposable
    {
        internal readonly ManualResetEventSlim SecondEntered = new(false);
        internal readonly ManualResetEventSlim Release = new(false);
        internal bool SiblingCanceled;
        private int _calls;
        public LearnedContentPrediction Predict(Stream content) => throw new InvalidOperationException("Token required.");
        public LearnedContentPrediction Predict(ReadOnlyMemory<byte> content) => throw new InvalidOperationException("Token required.");
        public LearnedContentPrediction Predict(ReadOnlyMemory<byte> content, CancellationToken token) => Predict(Stream.Null, token);
        public LearnedContentPrediction Predict(Stream content, CancellationToken token)
        {
            if (Interlocked.Increment(ref _calls) == 1)
            {
                if (!SecondEntered.Wait(TimeSpan.FromSeconds(10))) throw new TimeoutException("Sibling never entered.");
                throw new InvalidOperationException("Required worker failed.");
            }
            SecondEntered.Set();
            WaitHandle.WaitAny(new[] { token.WaitHandle, Release.WaitHandle });
            SiblingCanceled = token.IsCancellationRequested;
            token.ThrowIfCancellationRequested();
            throw new InvalidOperationException("Cleanup released sibling.");
        }
        public void Dispose() { SecondEntered.Dispose(); Release.Dispose(); }
    }
#endif

    private static byte[] CreateZip(string name, byte[] content)
    {
        using var bytes = new MemoryStream();
        using (var archive = new ZipArchive(bytes, ZipArchiveMode.Create, leaveOpen: true))
        {
            using var entry = archive.CreateEntry(name).Open();
            entry.Write(content, 0, content.Length);
        }
        return bytes.ToArray();
    }

    private sealed class InnerFailureProvider : ILearnedContentClassifier
    {
        private readonly bool _cancel;
        internal int Calls;
        internal InnerFailureProvider(bool cancel) => _cancel = cancel;
        public LearnedContentPrediction Predict(ReadOnlyMemory<byte> content) => Predict(Stream.Null);
        public LearnedContentPrediction Predict(Stream content)
        {
            if (++Calls > 1)
            {
                if (_cancel) throw new OperationCanceledException("Provider canceled child.");
                throw new InvalidOperationException("Required child classification failed.");
            }
            return new LearnedContentPrediction { Provider = "test", Extension = "zip", OutputLabel = "zip", Probability = 1, ThresholdMet = true };
        }
    }

    private sealed class OpaqueSet : ISet<string>, IReadOnlyCollection<string>
    {
        private readonly ISet<string> _values;
        internal OpaqueSet(ISet<string> values) => _values = values;
        public int Count => _values.Count;
        public bool IsReadOnly => true;
        public bool Contains(string item) => _values.Contains(item);
        public IEnumerator<string> GetEnumerator() => _values.GetEnumerator();
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
        public void CopyTo(string[] array, int index) => _values.CopyTo(array, index);
        public bool IsProperSubsetOf(IEnumerable<string> other) => _values.IsProperSubsetOf(other);
        public bool IsProperSupersetOf(IEnumerable<string> other) => _values.IsProperSupersetOf(other);
        public bool IsSubsetOf(IEnumerable<string> other) => _values.IsSubsetOf(other);
        public bool IsSupersetOf(IEnumerable<string> other) => _values.IsSupersetOf(other);
        public bool Overlaps(IEnumerable<string> other) => _values.Overlaps(other);
        public bool SetEquals(IEnumerable<string> other) => _values.SetEquals(other);
        public bool Add(string item) => throw new NotSupportedException();
        void ICollection<string>.Add(string item) => throw new NotSupportedException();
        public void Clear() => throw new NotSupportedException();
        public bool Remove(string item) => throw new NotSupportedException();
        public void ExceptWith(IEnumerable<string> other) => throw new NotSupportedException();
        public void IntersectWith(IEnumerable<string> other) => throw new NotSupportedException();
        public void SymmetricExceptWith(IEnumerable<string> other) => throw new NotSupportedException();
        public void UnionWith(IEnumerable<string> other) => throw new NotSupportedException();
    }
}
