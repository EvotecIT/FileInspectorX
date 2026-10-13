using System.IO.Compression;
using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public class InspectionReportTests
{
    [Fact]
    public void ReportIdentifiesExactBytesRestoresStreamAndExplainsEvidence()
    {
        var bytes = Encoding.UTF8.GetBytes("Report discusses invoices and revenue. Invoices include quarterly revenue summaries.");
        using var stream = new MemoryStream(bytes); stream.Position = 7;
        var report = FileInspector.AnalyzeReport(stream, "/private/sample.txt");
        Assert.Equal(7, stream.Position); Assert.True(stream.CanRead);
        Assert.Equal(InspectionReport.CurrentSchemaVersion, report.SchemaVersion); Assert.Equal("sample.txt", report.File.Name);
        Assert.Equal(bytes.Length, report.File.SizeBytes); Assert.Equal(FileInspector.ReportHash(bytes), report.File.Sha256);
        Assert.Contains("invoices", report.Content.Keywords);
        Assert.Contains(report.Observations, o => o.Code == "text-topics" && o.Evidence == "Content.Keywords");
    }

    [Fact]
    public void ReportRejectsOversizeInputAndRetainsPosition()
    {
        using var stream = new MemoryStream(new byte[33]); stream.Position = 4;
        Assert.Throws<InvalidDataException>(() => FileInspector.AnalyzeReport(stream, options: new InspectionReportOptions { MaxInputBytes = 32 }));
        Assert.Equal(4, stream.Position);
    }

    [Fact]
    public void TruncatedTextIsExplicitlyPartialAndKeepsExactWholeFileHash()
    {
        var bytes = Encoding.UTF8.GetBytes("This document discusses quarterly revenue and customer invoices.");
        using var stream = new MemoryStream(bytes);
        var report = FileInspector.AnalyzeReport(stream, "sample.txt", new InspectionReportOptions { MaxTextCharacters = 12 });
        Assert.Equal(12, report.Content.Text.Length); Assert.Equal(InspectionOutcome.Partial, report.Outcome);
        Assert.Contains("content:text-character-limit", report.Content.Issues);
        Assert.Equal(FileInspector.ReportHash(bytes), report.File.Sha256);
    }

    [Fact]
    public void WordTextAndTableStructureComeFromPackageContent()
    {
        using var zip = Package(("word/document.xml", "<w:document xmlns:w='http://schemas.openxmlformats.org/wordprocessingml/2006/main'><w:body><w:p><w:r><w:t>Quarterly invoices</w:t></w:r></w:p><w:tbl><w:tr><w:tc><w:p><w:r><w:t>Revenue</w:t></w:r></w:p></w:tc></w:tr></w:tbl></w:body></w:document>"));
        var report = FileInspector.AnalyzeReport(zip, "renamed.bin");
        Assert.Equal("ooxml-word", report.Content.Reader); Assert.Contains("Quarterly invoices", report.Content.Text);
        Assert.Equal("1", report.Content.Metadata["Tables"]); Assert.Equal(InspectionStageStatus.Partial, report.Content.Status);
        Assert.NotNull(report.Content.Entries.Single().Sha256);
    }

    [Fact]
    public void ExcelReadsSharedAndInlineStringsWithoutExecutingFormulas()
    {
        using var zip = Package(("xl/workbook.xml", "<workbook xmlns='http://schemas.openxmlformats.org/spreadsheetml/2006/main'><sheets><sheet name='Budget'/></sheets></workbook>"),
            ("xl/sharedStrings.xml", "<sst xmlns='http://schemas.openxmlformats.org/spreadsheetml/2006/main'><si><t>Revenue</t></si></sst>"),
            ("xl/worksheets/sheet1.xml", "<worksheet xmlns='http://schemas.openxmlformats.org/spreadsheetml/2006/main'><sheetData><row><c t='s'><v>0</v></c><c t='inlineStr'><is><t>Forecast</t></is></c><c><f>SUM(A1:A3)</f><v>123</v></c></row></sheetData></worksheet>"));
        var report = FileInspector.AnalyzeReport(zip, "book.xlsx");
        Assert.Contains("Revenue", report.Content.Text); Assert.Contains("Forecast", report.Content.Text);
        Assert.Contains("=SUM(A1:A3)", report.Content.Text); Assert.Equal("1", report.Content.Metadata["SampledFormulas"]);
        Assert.Contains("content:spreadsheet-formulas-not-calculated", report.Content.Issues);
    }

    [Fact]
    public void PowerPointExtractsSlideTextAndStatesRenderingLimit()
    {
        using var zip = Package(("ppt/presentation.xml", "<presentation xmlns='http://schemas.openxmlformats.org/presentationml/2006/main'/>"), ("ppt/slides/slide1.xml", "<p:sld xmlns:p='http://schemas.openxmlformats.org/presentationml/2006/main' xmlns:a='http://schemas.openxmlformats.org/drawingml/2006/main'><a:t>Project roadmap</a:t></p:sld>"));
        var report = FileInspector.AnalyzeReport(zip, "slides.pptx");
        Assert.Equal("ooxml-powerpoint", report.Content.Reader); Assert.Contains("Project roadmap", report.Content.Text);
        Assert.Contains("content:presentation-layout-and-notes-not-inspected", report.Content.Issues);
    }

    [Theory]
    [InlineData("word")]
    [InlineData("excel")]
    [InlineData("powerpoint")]
    public void StrictOfficeNamespacesRetainTextAndStructure(string kind)
    {
        var sheet = "http://purl.oclc.org/ooxml/spreadsheetml/main";
        using var zip = kind switch
        {
            "word" => Package(("word/document.xml", "<document xmlns='http://purl.oclc.org/ooxml/wordprocessingml/main'><body><p><r><t>Quarterly invoices</t></r></p><tbl/></body></document>")),
            "excel" => Package(("xl/workbook.xml", "<workbook xmlns='" + sheet + "'><sheets><sheet name='Budget'/></sheets></workbook>"),
                ("xl/sharedStrings.xml", "<sst xmlns='" + sheet + "'><si><t>Quarterly invoices</t></si></sst>"),
                ("xl/worksheets/sheet1.xml", "<worksheet xmlns='" + sheet + "'><sheetData><row><c t='s'><v>0</v></c></row></sheetData></worksheet>")),
            _ => Package(("ppt/presentation.xml", "<presentation xmlns='http://purl.oclc.org/ooxml/presentationml/main'/>"),
                ("ppt/slides/slide1.xml", "<sld xmlns='http://purl.oclc.org/ooxml/presentationml/main' xmlns:a='http://purl.oclc.org/ooxml/drawingml/main'><a:t>Quarterly invoices</a:t></sld>"))
        };
        var report = FileInspector.AnalyzeReport(zip, "document.bin");
        Assert.Contains("Quarterly invoices", report.Content.Text);
        Assert.DoesNotContain("content:package-xml-namespace-unsupported", report.Content.Issues);
        Assert.Equal("1", report.Content.Metadata[kind == "word" ? "Tables" : kind == "excel" ? "Sheets" : "SampledSlides"]);
    }

    [Fact]
    public void UnsupportedPackageNamespaceExplainsMissingText()
    {
        using var zip = Package(("word/document.xml", "<document xmlns='urn:unsupported'><p><t>Invisible text</t></p></document>"));
        var report = FileInspector.AnalyzeReport(zip);
        Assert.Empty(report.Content.Text);
        Assert.Contains("content:package-xml-namespace-unsupported", report.Content.Issues);
    }

#if NET8_0_OR_GREATER
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void SavedReportRoundtripPreservesPartialStageEvidenceAndMeasurements(bool web)
    {
        using var input = new MemoryStream(Encoding.UTF8.GetBytes("Quarterly invoices describe customer revenue."));
        var report = FileInspector.AnalyzeReport(input, "invoices.txt", new InspectionReportOptions
        {
            Detection = new FileInspector.DetectionOptions { IncludePermissions = true, CollectMetrics = true }
        });
        // The legacy mutable flag is independent of typed stage evidence in saved consumer snapshots.
        report.Analysis.AnalysisComplete = true;
        Assert.Equal(InspectionOutcome.Partial, report.Outcome);
        var options = new System.Text.Json.JsonSerializerOptions(web ? System.Text.Json.JsonSerializerDefaults.Web : System.Text.Json.JsonSerializerDefaults.General);
        if (web) options.Converters.Add(new System.Text.Json.Serialization.JsonStringEnumConverter());
        var json = System.Text.Json.JsonSerializer.Serialize(report, options);
        var saved = System.Text.Json.JsonSerializer.Deserialize<InspectionReport>(json, options)!;
        Assert.Equal(report.Outcome, saved.Outcome);
        Assert.Equal(report.Analysis.StageOutcomes.Select(s => (s.Stage, s.Status, string.Join(";", s.Issues))),
            saved.Analysis.StageOutcomes.Select(s => (s.Stage, s.Status, string.Join(";", s.Issues))));
        Assert.NotNull(saved.Analysis.Metrics);
        Assert.Equal(report.Analysis.Metrics!.HashBytes, saved.Analysis.Metrics!.HashBytes);
        Assert.Equal(report.Analysis.Metrics.Stages.Select(s => (s.Stage, s.Invocations, s.Elapsed)),
            saved.Analysis.Metrics.Stages.Select(s => (s.Stage, s.Invocations, s.Elapsed)));
        Assert.Equal(report.File.Sha256, saved.File.Sha256);
        Assert.Equal(report.Analysis.SourceName, saved.Analysis.SourceName);
        Assert.Equal(report.Content.Text, saved.Content.Text);
    }
#endif

    [Fact]
    public void PackageXmlCannotResolveExternalEntities()
    {
        using var zip = Package(("word/document.xml", "<!DOCTYPE x [<!ENTITY remote SYSTEM 'file:///etc/passwd'>]><x>&remote;</x>"));
        var report = FileInspector.AnalyzeReport(zip, "sample.docx");
        Assert.Empty(report.Content.Text); Assert.Contains("content:package-xml-invalid-or-limited", report.Content.Issues);
    }

    [Fact]
    public void ArchiveLimitsRetainInventoryWithoutClaimingCompleteCoverage()
    {
        using var zip = Package(("first.txt", "Invoice one"), ("second.txt", "Invoice two"));
        var report = FileInspector.AnalyzeReport(zip, "archive.zip", new InspectionReportOptions { MaxArchiveEntries = 1 });
        Assert.True(report.Content.Entries.Count <= 1); Assert.Equal(InspectionOutcome.Partial, report.Outcome);
        Assert.Contains("archive:entry-count-limit", report.Content.Issues);
    }

    [Fact]
    public void SimilarityDistinguishesExactBytesTextOverlapAndUnavailableText()
    {
        InspectionReport Text(string value) { using var stream = new MemoryStream(Encoding.UTF8.GetBytes(value)); return FileInspector.AnalyzeReport(stream, "sample.txt"); }
        var first = Text("Quarterly customer invoices summarize revenue from consulting work and recurring subscription renewals.");
        var same = Text("Quarterly customer invoices summarize revenue from consulting work and recurring subscription renewals.");
        var edited = Text("Quarterly customer invoices summarize revenue from consulting work and recurring subscription renewals. Added appendix.");
        var unrelated = Text("Weather forecasts describe cloud coverage with heavy rain and snow expected tomorrow afternoon.");
        Assert.Equal(1, ReportSimilarity.Compare(first, same)); Assert.True(ReportSimilarity.Compare(first, edited) > 0.5);
        Assert.Equal(0, ReportSimilarity.Compare(first, unrelated)); Assert.Null(ReportSimilarity.Compare(first, Text("a")));
    }

    [Fact]
    public void BatchPreservesMissingInputsAndDirectoryTraversalFailures()
    {
        var missing = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"), "missing.txt");
        var item = FileInspector.AnalyzeReports(new[] { missing }).Single();
        Assert.Equal(missing, item.Source); Assert.Equal("batch:input-unavailable", item.Issue);
        var directory = FileInspector.AnalyzeDirectoryReports(Path.GetDirectoryName(missing)!).Single();
        Assert.Equal(".", directory.Source); Assert.Equal("batch:directory-unavailable", directory.Issue);
    }

    private static MemoryStream Package(params (string Name, string Content)[] members)
    {
        var output = new MemoryStream();
        using (var zip = new ZipArchive(output, ZipArchiveMode.Create, true))
            foreach (var member in members) { using var writer = new StreamWriter(zip.CreateEntry(member.Name).Open()); writer.Write(member.Content); }
        output.Position = 0; return output;
    }
}
