using System.Globalization;
using OfficeIMO.PowerPoint;
using Xunit;

namespace FileInspectorX.OfficeIMO.Tests;

public sealed class NativeMetadataTests
{
    [Fact]
    public void NativeCommentRepliesAndHiddenShapesKeepTheirSourceIdentity()
    {
        var fixture = ReviewPresentation();
        InspectionReport report = Read(fixture.Bytes, "review.pptx");
        ReportFact parent = Assert.Single(report.Content.Facts, fact => fact.Name == "inspection.comment.Modern");
        ReportFact reply = Assert.Single(report.Content.Facts, fact => fact.Name == "inspection.comment.ModernReply");
        Assert.Equal(fixture.ParentId, parent.Source?.Record);
        Assert.Equal(fixture.ReplyId, reply.Source?.Record);
        Assert.Equal(parent.Source!.Record, reply.Attributes["parentId"]);
        ReportFact hidden = Assert.Single(report.Content.Facts, fact => fact.Name == "inspection.visibility.Shape");
        Assert.Equal(fixture.HiddenId, hidden.Source?.Record);
        foreach (ReportFact fact in new[] { parent, reply, hidden })
        {
            Assert.Equal(ReportByteSpace.Unknown, fact.Source!.ByteSpace);
            Assert.Null(fact.Source.ByteOffset); Assert.Null(fact.Source.ByteLength);
        }
    }

    [Fact]
    public void ReadablePageAfterFailureKeepsItsNativeSelectionIdentity()
    {
        InspectionReport report = Read(NativeFixtures.Pdf(failedFirstPage: true), "mixed-pages.pdf");
        ReportDocumentUnit page = Assert.Single(report.Content.DocumentUnits, unit => unit.Kind == "page");
        Assert.Equal(2, page.Location?.Page);
        Assert.Equal(1, page.Location?.SourceBlockIndex);
        Assert.Equal("page-2-selection-0001", page.Location?.BlockAnchor);
        ReportDocumentUnit failed = Assert.Single(report.Content.DocumentUnits, unit => unit.Kind == "page-outcome" && unit.Status == InspectionStageStatus.Failed);
        Assert.Equal(0, failed.Location?.SourceBlockIndex);
        ReportDiagnostic diagnostic = Assert.Single(report.Content.Diagnostics, item => item.Code == "pdf-page-unsupported-content-filter");
        Assert.True(diagnostic.IsRecoverable); Assert.Equal(ReportRecoveryKind.Skipped, diagnostic.Recovery);
        Assert.Contains(NativeFixtures.Text, report.Content.Text);
        Assert.DoesNotContain("unsupported", report.Content.Text, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(false, "creator", "Creator-only fixture")]
    [InlineData(true, "pdfAConformance", "B")]
    public void AttributeOnlyXmpRemainsEvidenceAndDoesNotBecomePrimaryText(bool conformance, string key, string value)
    {
        string attributes = conformance
            ? "<pdfaid:part>4</pdfaid:part><pdfaid:conformance>B</pdfaid:conformance>"
            : "<dc:creator><rdf:Seq><rdf:li>Creator-only fixture</rdf:li></rdf:Seq></dc:creator>";
        string xmp = "<x:xmpmeta xmlns:x='adobe:ns:meta/'><rdf:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#'>" +
            "<rdf:Description xmlns:dc='http://purl.org/dc/elements/1.1/' xmlns:pdfaid='http://www.aiim.org/pdfa/ns/id/'>" +
            attributes + "</rdf:Description></rdf:RDF></x:xmpmeta>";
        InspectionReport report = Read(NativeFixtures.Pdf(xmp: xmp), "metadata.pdf");
        ReportFact fact = Assert.Single(report.Content.Facts, item => item.Name == "pdf.xmp.XmpMetadata");
        Assert.Equal(string.Empty, fact.Value); Assert.Equal(value, fact.Attributes[key]);
        Assert.Equal("6", fact.Source?.Record); Assert.Equal(ReportFactOrigin.Embedded, fact.Origin);
        Assert.Contains(NativeFixtures.Text, report.Content.Text);
        Assert.DoesNotContain("Creator-only fixture", report.Content.Text);
    }

    [Fact]
    public void StructureWithoutAlternateTextRetainsItsObjectDescriptor()
    {
        InspectionReport report = Read(NativeFixtures.Pdf(tagged: true), "structure.pdf");
        ReportFact fact = Assert.Single(report.Content.Facts, item => item.Name == "pdf.taggedContent.element.P");
        Assert.Equal(string.Empty, fact.Value); Assert.Equal("P", fact.Attributes["structureType"]);
        Assert.Equal("7", fact.Source?.Record); Assert.Equal("6", fact.Attributes["parentObjectNumber"]);
        Assert.Null(fact.Source!.ByteOffset); Assert.Null(fact.Source.ByteLength);
    }

    [Theory]
    [InlineData(1024, true)]
    [InlineData(32, false)]
    public void NativeObjectIdsUseTheirCompleteIdentifierAllowance(int limit, bool retained)
    {
        var fixture = ReviewPresentation();
        var options = new InspectionReportOptions { ContentReader = new OfficeImoContentReader(), MaxIdentifierCharacters = limit, MaxFactCharacters = 8 };
        using var source = new MemoryStream(fixture.Bytes);
        InspectionReport report = FileInspector.AnalyzeReport(source, "review.pptx", options);
        ReportFact parent = Assert.Single(report.Content.Facts, fact => fact.Name == "inspection.comment.Modern");
        Assert.Equal(retained ? fixture.ParentId : null, parent.Source?.Record);
        Assert.Equal(InspectionStageStatus.Partial, report.Content.Status);
        Assert.Contains(report.Content.Omissions, omission => omission.Code == "officeimo:response-limit");
    }

    private static (byte[] Bytes, string ParentId, string ReplyId, string HiddenId) ReviewPresentation()
    {
        using PowerPointPresentation presentation = PowerPointPresentation.Create();
        var slide = presentation.AddSlide();
        var hidden = slide.AddTextBox(NativeFixtures.Text, 100000, 100000, 6000000, 500000); hidden.Hidden = true;
        var author = new PowerPointCommentAuthor("Synthetic Reviewer");
        var parent = presentation.AddModernComment(slide, author, "Parent review", created: new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        var reply = parent.AddReply(author, "Reply review", created: new DateTime(2026, 1, 1, 0, 1, 0, DateTimeKind.Utc));
        return (presentation.ToBytes(), parent.Id, reply.Id, hidden.Id!.Value.ToString(CultureInfo.InvariantCulture));
    }

    private static InspectionReport Read(byte[] bytes, string name)
    {
        using var source = new MemoryStream(bytes);
        return FileInspector.AnalyzeReport(source, name, new InspectionReportOptions { ContentReader = new OfficeImoContentReader() });
    }
}
