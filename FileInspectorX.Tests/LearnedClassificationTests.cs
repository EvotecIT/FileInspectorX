using System.Text;
using System.IO.Compression;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class LearnedClassificationTests
{
    [Fact]
    public void Detect_DefaultDoesNotInvokeLearnedClassifier()
    {
        var classifier = new StubClassifier(CreatePrediction("javascript", "js"));

        var result = FileInspector.Detect(
            Encoding.UTF8.GetBytes("hello world this is ordinary prose"),
            new FileInspector.DetectionOptions { LearnedClassifier = classifier });

        Assert.NotNull(result);
        Assert.Equal(0, classifier.CallCount);
        Assert.Null(result!.LearnedClassification);
    }

    [Fact]
    public void Detect_AssistPromotesGenericLowConfidenceDetection()
    {
        var classifier = new StubClassifier(CreatePrediction("javascript", "js"));

        var result = FileInspector.Detect(
            Encoding.UTF8.GetBytes("hello world this is ordinary prose"),
            new FileInspector.DetectionOptions
            {
                LearnedClassifier = classifier,
                LearnedClassificationMode = LearnedClassificationMode.Assist
            });

        Assert.NotNull(result);
        Assert.Equal("js", result!.Extension);
        Assert.Equal(LearnedClassificationDisposition.Promoted, result.LearnedClassification!.Disposition);
        Assert.NotEqual(result.Score, (int?)(result.LearnedClassification.Prediction!.Probability * 100));
    }

    [Fact]
    public void Detect_StrongDeterministicEvidenceWinsAndConflictIsVisible()
    {
        var classifier = new StubClassifier(CreatePrediction("javascript", "js"));
        var png = new byte[]
        {
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
            0, 0, 0, 0, 0, 0, 0, 0
        };

        var result = FileInspector.Detect(
            png,
            new FileInspector.DetectionOptions
            {
                LearnedClassifier = classifier,
                LearnedClassificationMode = LearnedClassificationMode.Assist
            });

        Assert.NotNull(result);
        Assert.Equal("png", result!.Extension);
        Assert.Equal(LearnedClassificationDisposition.Conflict, result.LearnedClassification!.Disposition);
        Assert.Equal("png", result.LearnedClassification.DeterministicExtension);
    }

    [Fact]
    public void Detect_AssistRecordsProviderFailure()
    {
        var result = FileInspector.Detect(
            Encoding.UTF8.GetBytes("plain text"),
            new FileInspector.DetectionOptions
            {
                LearnedClassifier = new ThrowingClassifier(),
                LearnedClassificationMode = LearnedClassificationMode.Assist
            });

        Assert.NotNull(result);
        Assert.Equal(LearnedClassificationDisposition.Failed, result!.LearnedClassification!.Disposition);
        Assert.Equal("provider-failed:InvalidOperationException", result.LearnedClassification.Message);
    }

    [Fact]
    public void Detect_RequiredPropagatesProviderFailure()
    {
        var options = new FileInspector.DetectionOptions
        {
            LearnedClassifier = new ThrowingClassifier(),
            LearnedClassificationMode = LearnedClassificationMode.Required
        };

        Assert.Throws<LearnedClassificationException>(
            () => FileInspector.Detect(Encoding.UTF8.GetBytes("plain text"), options));
    }

    [Fact]
    public void Detect_PathArbitratesAfterPeFamilyRefinement()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".exe");
        File.WriteAllBytes(path, CreateMinimalPeDll());
        try
        {
            var result = FileInspector.Detect(
                path,
                new FileInspector.DetectionOptions
                {
                    LearnedClassifier = new StubClassifier(CreatePrediction("executable", "exe")),
                    LearnedClassificationMode = LearnedClassificationMode.Assist
                });

            Assert.NotNull(result);
            Assert.Equal("dll", result!.Extension);
            Assert.Equal(LearnedClassificationDisposition.Conflict, result.LearnedClassification!.Disposition);
            Assert.Equal("dll", result.LearnedClassification.DeterministicExtension);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Detect_StreamArbitratesAfterStructuredTextValidation()
    {
        using var content = new MemoryStream(Encoding.UTF8.GetBytes("{ \"value\": ] }"));

        var result = FileInspector.Detect(
            content,
            new FileInspector.DetectionOptions
            {
                LearnedClassifier = new StubClassifier(CreatePrediction("javascript", "js")),
                LearnedClassificationMode = LearnedClassificationMode.Assist
            },
            declaredExtension: "json");

        Assert.NotNull(result);
        Assert.Equal("json", result!.Extension);
        Assert.Equal("failed", result.ValidationStatus);
        Assert.Contains("json:validation-error", result.Reason);
        Assert.Equal("Low", result.LearnedClassification!.DeterministicConfidence);
        Assert.Contains("json:validation-error", result.LearnedClassification.DeterministicReason);
    }

    [Fact]
    public void Detect_LearnedPredictionCanAgreeWithDeterministicZipSubtype()
    {
        var path = CreateZip(
            ("AndroidManifest.xml", "<manifest />"),
            ("classes.dex", "dex"));
        try
        {
            var result = FileInspector.Detect(
                path,
                new FileInspector.DetectionOptions
                {
                    LearnedClassifier = new StubClassifier(CreatePrediction("apk", "apk")),
                    LearnedClassificationMode = LearnedClassificationMode.Assist
                });

            Assert.NotNull(result);
            Assert.Equal("zip", result!.Extension);
            Assert.Equal("apk", result.GuessedExtension);
            Assert.Equal(LearnedClassificationDisposition.Agreed, result.LearnedClassification!.Disposition);
            Assert.Equal("apk", result.LearnedClassification.DeterministicAgreementExtension);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Analyze_PathArbitratesAfterFullDeterministicRefinement()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".exe");
        File.WriteAllBytes(path, CreateMinimalPeDll());
        try
        {
            var result = FileInspector.Analyze(
                path,
                new FileInspector.DetectionOptions
                {
                    LearnedClassifier = new StubClassifier(CreatePrediction("executable", "exe")),
                    LearnedClassificationMode = LearnedClassificationMode.Assist,
                    IncludeAssessment = false,
                    IncludeAuthenticode = false,
                    IncludePermissions = false,
                    IncludeShellProperties = false
                });

            Assert.Equal("dll", result.Detection!.Extension);
            Assert.Equal(LearnedClassificationDisposition.Conflict, result.Detection.LearnedClassification!.Disposition);
            Assert.Equal("dll", result.Detection.LearnedClassification.DeterministicExtension);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Analyze_PreservesMacroSubtypeAndUsesItForLearnedAgreement()
    {
        var path = CreateZip(
            ("[Content_Types].xml", "<Types />"),
            ("word/document.xml", "<document />"),
            ("word/vbaProject.bin", "macro"));
        try
        {
            var result = FileInspector.Analyze(
                path,
                new FileInspector.DetectionOptions
                {
                    LearnedClassifier = new StubClassifier(CreatePrediction("docm", "docm")),
                    LearnedClassificationMode = LearnedClassificationMode.Assist,
                    IncludeAssessment = false,
                    IncludeAuthenticode = false,
                    IncludePermissions = false,
                    IncludeShellProperties = false
                });

            Assert.Equal("docx", result.Detection!.Extension);
            Assert.Equal("docm", result.GuessedExtension);
            Assert.Equal("docm", result.Detection.GuessedExtension);
            Assert.Equal(LearnedClassificationDisposition.Agreed, result.Detection.LearnedClassification!.Disposition);
            Assert.Equal("docm", result.Detection.LearnedClassification.DeterministicAgreementExtension);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void AnalyzeDirectory_RequiredPropagatesProviderFailure()
    {
        var directory = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N")));
        File.WriteAllText(Path.Combine(directory.FullName, "sample.txt"), "plain text");
        try
        {
            var options = new FileInspector.DetectionOptions
            {
                LearnedClassifier = new ThrowingClassifier(),
                LearnedClassificationMode = LearnedClassificationMode.Required
            };

            Assert.Throws<LearnedClassificationException>(
                () => FileInspector.AnalyzeDirectory(directory.FullName, options: options).ToList());
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

#if NET8_0_OR_GREATER
    [Fact]
    public async Task AnalyzeDirectoryAsync_RequiredPropagatesProviderFailure()
    {
        var directory = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N")));
        File.WriteAllText(Path.Combine(directory.FullName, "sample.txt"), "plain text");
        try
        {
            var options = new FileInspector.DetectionOptions
            {
                LearnedClassifier = new ThrowingClassifier(),
                LearnedClassificationMode = LearnedClassificationMode.Required
            };

            await Assert.ThrowsAsync<LearnedClassificationException>(async () =>
            {
                await foreach (var _ in FileInspector.AnalyzeDirectoryAsync(directory.FullName, options: options))
                {
                }
            });
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }
#endif

    private static LearnedContentPrediction CreatePrediction(string label, string extension)
        => new()
        {
            Provider = "Test",
            ModelId = "test-v1",
            RawLabel = label,
            OutputLabel = label,
            Extension = extension,
            MimeType = "application/javascript",
            Probability = 0.99,
            Threshold = 0.5,
            ThresholdMet = true,
            PredictionMode = "HighConfidence",
            IsText = true
        };

    private static byte[] CreateMinimalPeDll()
    {
        var bytes = new byte[512];
        bytes[0] = (byte)'M';
        bytes[1] = (byte)'Z';
        BitConverter.GetBytes(0x80).CopyTo(bytes, 0x3C);
        bytes[0x80] = (byte)'P';
        bytes[0x81] = (byte)'E';
        BitConverter.GetBytes((ushort)0x014C).CopyTo(bytes, 0x84);
        BitConverter.GetBytes((ushort)0).CopyTo(bytes, 0x86);
        BitConverter.GetBytes((ushort)0x00E0).CopyTo(bytes, 0x94);
        BitConverter.GetBytes((ushort)0x2000).CopyTo(bytes, 0x96);
        BitConverter.GetBytes((ushort)0x010B).CopyTo(bytes, 0x98);
        return bytes;
    }

    private static string CreateZip(params (string Name, string Content)[] entries)
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".zip");
        using var archive = ZipFile.Open(path, ZipArchiveMode.Create);
        foreach (var item in entries)
        {
            var entry = archive.CreateEntry(item.Name);
            using var writer = new StreamWriter(entry.Open());
            writer.Write(item.Content);
        }
        return path;
    }

    private sealed class StubClassifier : ILearnedContentClassifier
    {
        private readonly LearnedContentPrediction _prediction;

        internal StubClassifier(LearnedContentPrediction prediction)
        {
            _prediction = prediction;
        }

        internal int CallCount { get; private set; }

        public LearnedContentPrediction Predict(ReadOnlyMemory<byte> content)
        {
            CallCount++;
            return _prediction;
        }

        public LearnedContentPrediction Predict(Stream content)
        {
            CallCount++;
            return _prediction;
        }
    }

    private sealed class ThrowingClassifier : ILearnedContentClassifier
    {
        public LearnedContentPrediction Predict(ReadOnlyMemory<byte> content)
            => throw new InvalidOperationException("test");

        public LearnedContentPrediction Predict(Stream content)
            => throw new InvalidOperationException("test");
    }
}
