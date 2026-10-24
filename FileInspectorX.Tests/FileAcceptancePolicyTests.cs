using System.Text;
using System.IO.Compression;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class FileAcceptancePolicyTests
{
    private static FileAnalysis Inspect(string content, string name) => FileInspector.Inspect(Encoding.UTF8.GetBytes(content),
        new FileInspector.DetectionOptions { IncludePermissions = false, IncludeAuthenticode = false, IncludeShellProperties = false }, name);

    [Fact]
    public void RecognizedCompleteTextIsAcceptedUnderTheSelectedPolicy()
    {
        var analysis = Inspect("A normal message for the recipient.\n", "message.txt");
        var verdict = FileInspector.EvaluateAcceptance(analysis, "message.txt");
        Assert.Equal(FileAcceptanceDecision.Accepted, verdict.Decision);
        Assert.Empty(verdict.Reasons);
    }

    [Theory]
    [InlineData("report.pdf:payload.exe")]
    [InlineData("../report.pdf")]
    [InlineData("C:\\uploads\\report.pdf")]
    [InlineData("report.pdf.")]
    [InlineData("report.pdf ")]
    [InlineData("report\u202eexe.pdf")]
    [InlineData("report\n.pdf")]
    [InlineData("")]
    public void UnsafeClientNamesAreRejectedWithoutEchoingTheName(string name)
    {
        var result = FileInspector.EvaluateAcceptance(Inspect("normal text", "message.txt"), name);
        Assert.Equal(FileAcceptanceDecision.Rejected, result.Decision);
        Assert.Contains("file-policy:invalid-filename", result.Reasons);
        Assert.All(result.Reasons, reason => Assert.StartsWith("file-policy:", reason));
    }

    [Fact]
    public void ARecognizedFileCannotPassWithAMismatchedClientExtension()
    {
        var result = FileInspector.EvaluateAcceptance(Inspect("normal text", "message.txt"), "invoice.pdf");
        Assert.Equal(FileAcceptanceDecision.Rejected, result.Decision);
        Assert.Contains("file-policy:declared-type-mismatch", result.Reasons);
    }

    [Fact]
    public void UnknownUnavailableAndPartialEvidenceNeverPasses()
    {
        Assert.Equal(FileAcceptanceDecision.Incomplete, FileInspector.EvaluateAcceptance(null, "input.bin").Decision);
        Assert.Equal(FileAcceptanceDecision.Incomplete, FileInspector.EvaluateAcceptance(new FileAnalysis(), "input.bin").Decision);
        var analysis = Inspect("ordinary text", "message.txt");
        analysis.AnalysisComplete = false;
        Assert.Equal(FileAcceptanceDecision.Incomplete, FileInspector.EvaluateAcceptance(analysis, "message.txt").Decision);
    }

    [Fact]
    public void DetectionOnlyDoesNotEstablishAcceptance()
    {
        var analysis = FileInspector.Inspect(Encoding.UTF8.GetBytes("ordinary text"),
            new FileInspector.DetectionOptions { DetectOnly = true }, "message.txt");
        var result = FileInspector.EvaluateAcceptance(analysis, "message.txt");
        Assert.Equal(FileAcceptanceDecision.Incomplete, result.Decision);
        Assert.Contains("file-policy:analysis-not-completed", result.Reasons);
    }

    [Fact]
    public void OmittingContainerInspectionCannotEstablishDocumentAcceptance()
    {
        var bytes = ZipTestArchive.Create(("word/document.xml", "<document/>"));
        var analysis = FileInspector.Inspect(bytes, new FileInspector.DetectionOptions { IncludeContainer = false, IncludeAuthenticode = false, IncludePermissions = false }, "report.zip");
        var verdict = FileInspector.EvaluateAcceptance(analysis, "report.zip");
        Assert.Equal(FileAcceptanceDecision.Incomplete, verdict.Decision);
        Assert.Contains("file-policy:container-not-completed", verdict.Reasons);
    }

    [Theory]
    [InlineData("7z", "application/x-7z-compressed")]
    [InlineData("rar", "application/vnd.rar")]
    public void RecognizedArchiveWithoutACompletedContainerStageCannotBeAccepted(string extension, string mime)
    {
        var analysis = Inspect("ordinary text", "message.txt");
        analysis.Detection!.Extension = extension;
        analysis.Detection.MimeType = mime;
        analysis.Kind = ContentKind.Archive;
        var verdict = FileInspector.EvaluateAcceptance(analysis, "upload." + extension);
        Assert.Equal(FileAcceptanceDecision.Incomplete, verdict.Decision);
        Assert.Contains("file-policy:container-not-completed", verdict.Reasons);
    }

    [Theory]
    [InlineData("doc", "WordDocument")]
    [InlineData("xls", "Workbook")]
    [InlineData("ppt", "PowerPoint Document")]
    public void LegacyOfficeDirectoryHintsDoNotEstablishFullDocumentAcceptance(string extension, string marker)
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + "." + extension);
        try
        {
            DetectorTests.WriteSyntheticOleDirectoryFile(path, marker);
            var analysis = FileInspector.Inspect(File.ReadAllBytes(path), new FileInspector.DetectionOptions { IncludePermissions = false, IncludeAuthenticode = false }, "document." + extension);
            Assert.Equal(extension, analysis.Detection!.Extension);
            Assert.False(analysis.AnalysisComplete);
            Assert.Contains("office:directory-inspection-only", analysis.AnalysisIssues!);
            Assert.Equal(FileAcceptanceDecision.Incomplete, FileInspector.EvaluateAcceptance(analysis, "document." + extension).Decision);
        }
        finally { TestHelpers.SafeDelete(path); }
    }

    [Fact]
    public void RtfRecognitionDoesNotEstablishActiveContentCoverage()
    {
        var analysis = Inspect("{\\rtf1\\ansi Ordinary text}", "document.rtf");
        Assert.Equal("rtf", analysis.Detection!.Extension);
        var verdict = FileInspector.EvaluateAcceptance(analysis, "document.rtf");
        Assert.Equal(FileAcceptanceDecision.Incomplete, verdict.Decision);
        Assert.Contains("file-policy:document-coverage-unavailable", verdict.Reasons);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void StructuredXmlResourceLimitsRemainPolicyRejectionsInStageEvidence(bool sizeLimit)
    {
        var xml = sizeLimit ? "<?xml version='1.0'?><root>" + new string(' ', 2048) + "</root>" :
            "<?xml version='1.0'?>" + string.Concat(Enumerable.Repeat("<n>", 260)) + string.Concat(Enumerable.Repeat("</n>", 260));
        var options = new FileInspector.DetectionOptions { IncludePermissions = false, IncludeAuthenticode = false,
            Settings = InspectionSettings.CaptureDefaults() with { DetectionReadBudgetBytes = sizeLimit ? 128 : 32768 } };
        var analysis = FileInspector.Inspect(Encoding.UTF8.GetBytes(xml), options, "document.xml");
        var reason = sizeLimit ? "xml:validation-size-limit" : "xml:validation-depth-limit";
        Assert.Contains(reason, analysis.StageOutcomes.Single(stage => stage.Stage == InspectionStage.StructuredValidation).Issues);
        var verdict = FileInspector.EvaluateAcceptance(analysis, "document.xml");
        Assert.Equal(FileAcceptanceDecision.Rejected, verdict.Decision);
        Assert.Contains("file-policy:resource-limit", verdict.Reasons);
        Assert.Equal(FileAcceptanceDecision.Incomplete, FileInspector.EvaluateAcceptance(analysis, "document.xml", new FileAcceptanceOptions { RejectResourceLimits = false }).Decision);
    }

    [Fact]
    public void OfficeContentTypesDepthLimitsRemainPolicyRejections()
    {
        var xml = "<Types xmlns='http://schemas.openxmlformats.org/package/2006/content-types'>" +
            string.Concat(Enumerable.Repeat("<n>", 260)) + string.Concat(Enumerable.Repeat("</n>", 260)) + "</Types>";
        var bytes = ZipTestArchive.Create(("[Content_Types].xml", xml), ("word/document.xml", "<document/>"));
        var analysis = FileInspector.Inspect(bytes, new FileInspector.DetectionOptions { IncludePermissions = false, IncludeAuthenticode = false }, "document.docx");
        Assert.Contains("archive:ooxml-content-types-depth-limit", analysis.AnalysisIssues!);
        var verdict = FileInspector.EvaluateAcceptance(analysis, "document.docx");
        Assert.Equal(FileAcceptanceDecision.Rejected, verdict.Decision);
        Assert.Contains("file-policy:resource-limit", verdict.Reasons);
    }

    [Theory]
    [InlineData("External", true)]
    [InlineData("Internal", false)]
    public void WordSettingsRelationshipsDetectExternalTemplatesWithXmlAttributeSyntax(string mode, bool expected)
    {
        var bytes = ZipTestArchive.Create(("word/document.xml", "<document/>"),
            ("word/_rels/settings.xml.rels", "<Relationships xmlns='http://schemas.openxmlformats.org/package/2006/relationships'><Relationship Id='r1' Type='http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate' TargetMode = '" + mode + "' Target='file:///untrusted/template.dotm'/></Relationships>"));
        var analysis = FileInspector.Inspect(bytes, new FileInspector.DetectionOptions { IncludeAuthenticode = false, IncludePermissions = false }, "report.docx");
        Assert.Equal(expected, (analysis.Flags & ContentFlags.OfficeRemoteTemplate) != 0);
        if (expected) Assert.Contains("file-policy:active-document", FileInspector.EvaluateAcceptance(analysis, "report.docx").Reasons);
    }

    [Fact]
    public void ArchiveExpansionLimitsRejectTheInputBeforeScannerAdmission()
    {
        using var archiveBytes = new MemoryStream();
        using (var archive = new ZipArchive(archiveBytes, ZipArchiveMode.Create, leaveOpen: true))
        {
            using var writer = new StreamWriter(archive.CreateEntry("word/document.xml", CompressionLevel.Optimal).Open());
            writer.Write(new string('A', 64 * 1024));
        }
        var analysis = FileInspector.Inspect(archiveBytes.ToArray(), new FileInspector.DetectionOptions
        {
            IncludePermissions = false, IncludeAuthenticode = false,
            Settings = InspectionSettings.CaptureDefaults() with { ArchiveMaxCompressionRatio = 2 }
        }, "report.docx");
        Assert.Contains("archive:compression-ratio-limit", analysis.AnalysisIssues!);
        var verdict = FileInspector.EvaluateAcceptance(analysis, "report.docx");
        Assert.Equal(FileAcceptanceDecision.Rejected, verdict.Decision);
        Assert.Contains("file-policy:resource-limit", verdict.Reasons);
    }

    [Theory]
    [InlineData(ContentFlags.PdfEncrypted, "file-policy:encrypted-content")]
    [InlineData(ContentFlags.ArchiveHasEncryptedEntries, "file-policy:encrypted-content")]
    [InlineData(ContentFlags.OoxmlEncrypted, "file-policy:encrypted-content")]
    [InlineData(ContentFlags.ArchiveHasPathTraversal, "file-policy:unsafe-archive-path")]
    [InlineData(ContentFlags.ArchiveHasSymlinks, "file-policy:unsafe-archive-path")]
    public void ObservedOpaqueAndUnsafeContentCannotPassTheDefaultPolicy(ContentFlags flags, string reason)
    {
        var analysis = Inspect("ordinary text", "message.txt");
        analysis.Flags |= flags;
        var result = FileInspector.EvaluateAcceptance(analysis, "message.txt");
        Assert.Equal(FileAcceptanceDecision.Rejected, result.Decision);
        Assert.Contains(reason, result.Reasons);
    }

    [Theory]
    [InlineData("failed", FileAcceptanceDecision.Rejected)]
    [InlineData("timeout", FileAcceptanceDecision.Incomplete)]
    [InlineData("skipped", FileAcceptanceDecision.Incomplete)]
    [InlineData("unavailable", FileAcceptanceDecision.Incomplete)]
    public void StructuredValidationEvidenceIsRequiredEvenWhenRecognitionSucceeded(string status, FileAcceptanceDecision decision)
    {
        var analysis = Inspect("ordinary text", "message.txt");
        analysis.Detection!.ValidationStatus = status;
        Assert.Equal(decision, FileInspector.EvaluateAcceptance(analysis, "message.txt").Decision);
    }

    [Theory]
    [InlineData("/S /GoToR", ContentFlags.PdfHasRemoteActions)]
    [InlineData("/S /GoToE", ContentFlags.PdfHasRemoteActions)]
    [InlineData("/S /ImportData", ContentFlags.PdfHasRemoteActions)]
    [InlineData("/S /SubmitForm", ContentFlags.PdfHasFormSubmission)]
    [InlineData("/S /Submit#46orm", ContentFlags.PdfHasFormSubmission)]
    [InlineData("/Subtype /RichMedia", ContentFlags.PdfHasRichMedia)]
    public void PdfActiveActionsAreDetectedAndRejectedDespiteIncompleteLexicalInspection(string action, ContentFlags expected)
    {
        var analysis = Inspect("%PDF-1.7\n1 0 obj << /Type /Catalog " + action + " >> endobj\n%%EOF", "report.pdf");
        Assert.True((analysis.Flags & expected) != 0);
        var verdict = FileInspector.EvaluateAcceptance(analysis, "report.pdf");
        Assert.Equal(FileAcceptanceDecision.Rejected, verdict.Decision);
        Assert.Contains("file-policy:active-document", verdict.Reasons);
    }

    [Fact]
    public void PdfActionNamesInsideStringsAndCommentsDoNotBecomeActiveContent()
    {
        var analysis = Inspect("%PDF-1.7\n% /SubmitForm /RichMedia\n1 0 obj << /Type /Catalog /Title (/GoToR /SubmitForm) >> endobj\n%%EOF", "report.pdf");
        Assert.Equal(ContentFlags.None, analysis.Flags & (ContentFlags.PdfHasRemoteActions | ContentFlags.PdfHasFormSubmission | ContentFlags.PdfHasRichMedia));
        Assert.Equal(FileAcceptanceDecision.Incomplete, FileInspector.EvaluateAcceptance(analysis, "report.pdf").Decision);
    }

    [Theory]
    [InlineData("application/vnd.ms-office.vbaProject", ContentFlags.HasOoxmlMacros, "file-policy:active-document")]
    [InlineData("application/vnd.ms-office.activeX+xml", ContentFlags.OfficeHasActiveX, "file-policy:active-document")]
    [InlineData("application/vnd.openxmlformats-officedocument.oleObject", ContentFlags.OfficeHasEmbeddedObjects, "file-policy:embedded-payload")]
    public void DeclaredOfficePayloadTypesAreDetectedWithoutConventionalMemberNames(string type, ContentFlags expected, string reason)
    {
        var bytes = ZipTestArchive.Create(("[Content_Types].xml", "<Types xmlns='http://schemas.openxmlformats.org/package/2006/content-types'><Override PartName='/custom/payload.bin' ContentType='" + type + "'/></Types>"),
            ("word/document.xml", "<document/>"), ("custom/payload.bin", "inert fixture"));
        var analysis = FileInspector.Inspect(bytes, new FileInspector.DetectionOptions { IncludePermissions = false, IncludeAuthenticode = false }, "report.docx");
        Assert.True((analysis.Flags & expected) != 0);
        var verdict = FileInspector.EvaluateAcceptance(analysis, "report.docx");
        Assert.Equal(FileAcceptanceDecision.Rejected, verdict.Decision);
        Assert.Contains(reason, verdict.Reasons);
    }

    [Fact]
    public void RelaxingOneContentRestrictionDoesNotTurnPartialPdfInspectionIntoAcceptance()
    {
        var analysis = Inspect("%PDF-1.7\n1 0 obj << /Type /Catalog /S /SubmitForm >> endobj\n%%EOF", "report.pdf");
        var result = FileInspector.EvaluateAcceptance(analysis, "report.pdf", new FileAcceptanceOptions { RejectActiveDocuments = false });
        Assert.Equal(FileAcceptanceDecision.Incomplete, result.Decision);
        Assert.DoesNotContain("file-policy:active-document", result.Reasons);
    }
}
