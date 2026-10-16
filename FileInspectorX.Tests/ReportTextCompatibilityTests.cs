using Xunit;

namespace FileInspectorX.Tests;

public sealed class ReportTextCompatibilityTests
{
    [Fact]
    public void CompatibleProfilesCompareAndEvidenceDetachesBothDescriptors()
    {
        var left = Report("left");
        var right = Report("right");
        var rightSettings = right.Content.Extraction!.Settings.Reverse().ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
        right.Content.Extraction.Settings = rightSettings;
        Assert.Equal(1, ReportSimilarity.Compare(left, right));
        var evidence = Assert.Single(ReportComparison.Compare(left, right), item => item.Basis == "extracted-text-shingles");
        Assert.Equal("bottom-k-word-sha256-128/v1", evidence.Algorithm);
        Assert.NotSame(left.Content.Extraction, evidence.LeftExtraction);
        Assert.NotSame(right.Content.Extraction, evidence.RightExtraction);
        Assert.NotSame(rightSettings, evidence.RightExtraction!.Settings);
        rightSettings["encoding"] = "changed";
        left.Content.Extraction!.ReaderVersion = "changed";
        Assert.Equal("utf-8", evidence.RightExtraction.Settings["encoding"]);
        Assert.Equal("1.0.0", evidence.LeftExtraction!.ReaderVersion);
    }

    [Theory]
    [InlineData("encoding")]
    [InlineData("stories")]
    [InlineData("page-order")]
    [InlineData("cached-cell-policy")]
    public void ChangedTextPolicyDeclinesShinglesButKeepsExactBytesComparable(string setting)
    {
        var left = Report("left");
        var right = Report("right");
        ((Dictionary<string, string>)right.Content.Extraction!.Settings)[setting] = "changed";
        Assert.Null(ReportSimilarity.Compare(left, right));
        Assert.DoesNotContain(ReportComparison.Compare(left, right), item => item.Basis == "extracted-text-shingles");
        right.File.Sha256 = left.File.Sha256.ToUpperInvariant();
        Assert.Equal(1, ReportSimilarity.Compare(left, right));
        Assert.Contains(ReportComparison.Compare(left, right), item => item.Basis == "exact-bytes");
    }

    [Theory]
    [InlineData("reader")]
    [InlineData("version")]
    [InlineData("profile")]
    [InlineData("basis")]
    [InlineData("setting-key-case")]
    [InlineData("incomplete")]
    public void CompatibilityRequiresCompleteOrdinalDescriptorEquality(string difference)
    {
        var left = Report("left");
        var right = Report("right");
        var descriptor = right.Content.Extraction!;
        switch (difference)
        {
            case "reader": descriptor.ReaderId = descriptor.ReaderId.ToUpperInvariant(); break;
            case "version": descriptor.ReaderVersion = "1.0.1"; break;
            case "profile": descriptor.ProfileId = "document/v2"; break;
            case "basis": descriptor.TextBasis = ReportTextBasis.BuiltinPlainText; break;
            case "setting-key-case": descriptor.Settings = descriptor.Settings.ToDictionary(pair => pair.Key.ToUpperInvariant(), pair => pair.Value, StringComparer.OrdinalIgnoreCase); break;
            case "incomplete": descriptor.ProfileId = string.Empty; break;
        }
        Assert.Null(ReportSimilarity.Compare(left, right));
        Assert.DoesNotContain(ReportComparison.Compare(left, right), item => item.Basis == "extracted-text-shingles");
    }

    [Fact]
    public void DiagnosticOnlyEvidenceProvidesNoTextComparison()
    {
        var left = Report("left");
        var right = Report("right");
        left.Content.Text = right.Content.Text = string.Empty;
        left.Content.TextFingerprint = right.Content.TextFingerprint = Array.Empty<string>();
        left.Content.Diagnostics = right.Content.Diagnostics = new[] { new ReportDiagnostic { Code = "native:page-failed", Message = "Page text could not be read" } };
        Assert.Null(ReportSimilarity.Compare(left, right));
        Assert.DoesNotContain(ReportComparison.Compare(left, right), item => item.Basis == "extracted-text-shingles");
    }

#if NET8_0_OR_GREATER
    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public void ActualLegacyJsonWithShinglesStaysUnknownAndComparesOnlyExactBytes(int schema)
    {
        var json = "{\"SchemaVersion\":" + schema + ",\"File\":{\"Sha256\":\"" + FileInspector.ReportHash(new byte[] { 1 }) +
            "\"},\"Content\":{\"Reader\":\"utf-text\",\"Text\":\"legacy saved text\",\"TextFingerprint\":[\"one\",\"two\",\"three\"]}}";
        var legacy = System.Text.Json.JsonSerializer.Deserialize<InspectionReport>(json)!;
        var current = Report("current");
        Assert.Null(legacy.Content.Extraction);
        Assert.Null(ReportSimilarity.Compare(legacy, current));
        Assert.DoesNotContain(ReportComparison.Compare(legacy, current), item => item.Basis == "extracted-text-shingles");
        current.File.Sha256 = legacy.File.Sha256;
        Assert.Equal(1, ReportSimilarity.Compare(legacy, current));
        Assert.Contains(ReportComparison.Compare(legacy, current), item => item.Basis == "exact-bytes");
    }
#endif

    private static InspectionReport Report(string identity) => new()
    {
        File = new ReportFileIdentity { Sha256 = FileInspector.ReportHash(System.Text.Encoding.UTF8.GetBytes(identity)) },
        Content = new ContentProfile
        {
            Reader = "canonical-reader", Text = "canonical document text",
            TextFingerprint = new[] { "one", "two", "three" },
            Extraction = new ReportExtractionDescriptor
            {
                ReaderId = "canonical-reader", ReaderVersion = "1.0.0", ProfileId = "document/v1",
                TextBasis = ReportTextBasis.CanonicalDocumentText,
                Settings = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["encoding"] = "utf-8", ["stories"] = "body", ["page-order"] = "source", ["cached-cell-policy"] = "cached-values"
                }
            }
        }
    };
}
