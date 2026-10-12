using System.IO.Compression;
using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class SurfaceReportingTests
{
    [Fact]
    public void ReportAndMetadataRetainRequestedContentIdentityAndLearnedEvidence()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".json");
        try
        {
            File.WriteAllText(path, "{\"value\":1}");
            var result = FileInspector.InspectWithMetadata(path, new FileInspector.DetectionOptions
            {
                ComputeSha256 = true, MagicHeaderBytes = 4,
                LearnedClassifier = new JsonClassifier(), LearnedClassificationMode = LearnedClassificationMode.Assist
            });
            var detection = result.Analysis.Detection!;
            Assert.NotNull(detection.Sha256Hex);
            Assert.Equal(detection.Sha256Hex, result.Report.Sha256Hex);
            Assert.Equal(detection.MagicHeaderHex, result.Report.MagicHeaderHex);
            Assert.Same(detection.LearnedClassification, result.Report.LearnedClassification);
            Assert.Equal(detection.Sha256Hex, result.Metadata[nameof(ReportView.Sha256Hex)]);
            Assert.Equal(detection.MagicHeaderHex, result.Metadata[nameof(ReportView.MagicHeaderHex)]);
            Assert.Same(detection.LearnedClassification, result.Metadata[nameof(ReportView.LearnedClassification)]);
            Assert.Equal(detection.StructuredValidation, result.Metadata[nameof(ReportView.StructuredValidation)]);
            var markdown = MarkdownRenderer.From(result.Report);
            Assert.Contains("SHA-256: `" + detection.Sha256Hex + "`", markdown);
            Assert.Contains("Header (hex): `" + detection.MagicHeaderHex + "`", markdown);
            Assert.Contains("Provider: fixture", markdown);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void ReportsShowPartialOutcomeWhenAnOptionalProviderFails()
    {
        var analysis = FileInspector.Inspect(Encoding.UTF8.GetBytes("{\"value\":1}"), new FileInspector.DetectionOptions
        {
            IncludePermissions = false, IncludeAuthenticode = false,
            LearnedClassifier = new JsonClassifier(fail: true), LearnedClassificationMode = LearnedClassificationMode.Assist
        });
        Assert.True(analysis.AnalysisComplete); // Existing compatibility flag remains unchanged.
        Assert.Equal(InspectionOutcome.Partial, analysis.Outcome);
        var report = ReportView.From(analysis);
        Assert.False(report.AnalysisComplete);
        Assert.Equal(InspectionOutcome.Partial, report.Outcome);
        Assert.False(report.AssessmentSafeForAutomation);
        Assert.Equal("Review incomplete inspection stages before applying the assessment.", report.AssessmentRecommendedAction);
        Assert.False(analysis.ToPolicySummaryView("sample.json").SafeForAutomation);
        var markdown = MarkdownRenderer.From(report);
        Assert.Contains("### Analysis incomplete", markdown);
        Assert.Contains("LearnedClassification: Failed", markdown);
        Assert.Contains("classifier&#58;failed", markdown);
    }

    [Fact]
    public void ArchiveEntryNamesCannotInjectMarkdownOrHtmlIntoReports()
    {
        const string name = "innocent\n### Spoofed\n<img src=x onerror=alert(1)>[link](javascript:alert(1)).msi";
        using var buffer = new MemoryStream();
        using (var archive = new ZipArchive(buffer, ZipArchiveMode.Create, leaveOpen: true))
        {
            using var writer = new StreamWriter(archive.CreateEntry(name).Open());
            writer.Write("not a real installer");
        }
        var analysis = FileInspector.Analyze(buffer.ToArray(), new FileInspector.DetectionOptions
        {
            IncludePermissions = false, IncludeAuthenticode = false,
            Settings = InspectionSettings.CaptureDefaults() with { DeepContainerScanEnabled = true }
        }, "archive.zip");
        Assert.Contains(analysis.ArchivePreviewEntries!, entry => entry.Name == name);
        var report = ReportView.From(analysis);
        Assert.Contains(report.ArchivePreview!, preview => preview.Contains(name));
        var markdown = MarkdownRenderer.From(report);
        Assert.DoesNotContain("<img", markdown);
        Assert.DoesNotContain("\n### Spoofed", markdown);
        Assert.DoesNotContain("[link](javascript:", markdown);
        Assert.Contains("&lt;img", markdown);
        Assert.Contains("\\[link\\](javascript&#58;", markdown);
    }

    [Fact]
    public void DynamicMetadataCandidatesAndFindingsAreRenderedAsText()
    {
        const string hostile = "1. <svg onload=alert(1)>![look](https://example.invalid/image)\n### Spoofed `tick` www.example.invalid user@example.invalid";
        var report = new ReportView
        {
            DetectedTypeName = hostile, CompanyName = hostile, SignerSubject = hostile,
            InstallerName = hostile, ScriptUrlsSample = hostile, Owner = hostile,
            SecurityFindingsHumanShort = hostile, InnerFindingsHumanLong = hostile,
            VersionInfo = new Dictionary<string, string> { [hostile] = hostile },
            DetectionCandidates = new[] { new ContentTypeDetectionCandidate { Extension = hostile, Reason = hostile } },
            AssessmentFactors = new Dictionary<string, int> { [hostile] = 1 },
            ArchivePreview = new[] { hostile },
            LearnedClassification = new LearnedClassificationEvidence { Message = hostile }
        };
        var markdown = MarkdownRenderer.From(report);
        Assert.DoesNotContain("<svg", markdown);
        Assert.DoesNotContain("![look]", markdown);
        Assert.DoesNotContain("\n### Spoofed", markdown);
        Assert.DoesNotContain("https://", markdown);
        Assert.DoesNotContain("www.example", markdown);
        Assert.DoesNotContain("user@example", markdown);
        Assert.Contains("&lt;svg", markdown);
        Assert.Contains("1\\. &lt;svg", markdown);
        Assert.Equal(hostile, report.CompanyName);
    }

    [Fact]
    public void InlineCodeCannotBeClosedByContentBackticks()
    {
        var markdown = MarkdownRenderer.From(new ReportView { CertificateBlobSha256 = "``<img src=x>``" });
        Assert.Contains("- PKCS#7 SHA-256: ``` ``<img src=x>`` ```", markdown);
    }

    [Fact]
    public void FileTypeCannotOpenATildeFenceAroundFollowingSections()
    {
        var report = new ReportView { DetectedTypeName = "~~~", CompanyName = "Publisher" };

        var markdown = MarkdownRenderer.From(report);

        Assert.Contains(Environment.NewLine + "\\~\\~\\~" + Environment.NewLine, markdown);
        Assert.DoesNotContain(Environment.NewLine + "~~~" + Environment.NewLine, markdown);
        Assert.Contains("### Properties" + Environment.NewLine + "- Company: Publisher", markdown);
        Assert.Equal("~~~", report.DetectedTypeName);
    }

    [Fact]
    public void MsiSummaryPreservesClosingParenthesis()
    {
        var view = SummaryView.From("setup.msi", new FileAnalysis
        {
            Installer = new InstallerInfo { Kind = InstallerKind.Msi, Name = "Tool (Desktop)", Manufacturer = "Publisher", ProductCode = "{1234}" }
        });
        Assert.Equal("MSI: Tool (Desktop) by Publisher ({1234})", view.InstallerSummary);
    }

    private sealed class JsonClassifier : ILearnedContentClassifier
    {
        private readonly bool _fail;
        internal JsonClassifier(bool fail = false) => _fail = fail;
        public LearnedContentPrediction Predict(Stream content) => Predict(ReadOnlyMemory<byte>.Empty);
        public LearnedContentPrediction Predict(ReadOnlyMemory<byte> content) => _fail
            ? throw new InvalidOperationException("fixture provider unavailable")
            : new LearnedContentPrediction { Provider = "fixture", OutputLabel = "json", Extension = "json", MimeType = "application/json", Probability = 1, ThresholdMet = true };
    }
}
