using System.Text;
using System.Threading;
using OfficeIMO.Drawing;
using OfficeIMO.Rtf;
using Xunit;

namespace FileInspectorX.OfficeIMO.Tests;

public sealed class NativeIntegrationTests
{
    public static IEnumerable<object[]> Documents()
    {
        yield return new object[] { "docx", NativeFixtures.Word() };
        yield return new object[] { "xlsx", NativeFixtures.Excel() };
        yield return new object[] { "pptx", NativeFixtures.PowerPoint() };
        yield return new object[] { "odt", NativeFixtures.Odf() };
        yield return new object[] { "rtf", NativeFixtures.Rtf() };
        yield return new object[] { "pdf", NativeFixtures.Pdf() };
    }

    [Theory]
    [MemberData(nameof(Documents))]
    public void NativeDocumentTextAndEvidenceComeThroughTheOptionalPublicPipeline(string extension, byte[] bytes)
    {
        var observed = new ObservedReader();
        using var source = new MemoryStream(bytes); source.Position = 3;
        InspectionReport report = FileInspector.AnalyzeReport(source, "source." + extension, Options(observed));
        Assert.Equal(3, source.Position); Assert.True(source.CanRead);
        Assert.True(report.Content.Text.Contains(NativeFixtures.Text), "Detected=" + report.Analysis.DetectedExtension + "; Reader=" + report.Content.Reader +
            "; Native=" + observed.Root!.Disposition + "; Diagnostics=" + string.Join(",", report.Content.Diagnostics.Select(diagnostic => diagnostic.Code)));
        Assert.Equal("officeimo.reader", report.Content.Extraction!.ReaderId);
        Assert.Equal(ReportTextBasis.CanonicalDocumentText, report.Content.Extraction.TextBasis);
        Assert.Contains(report.Content.DocumentUnits, unit => unit.Status == InspectionStageStatus.Completed);
        Assert.All(report.Content.Facts, fact => Assert.NotEqual(ReportByteSpace.SnapshotBytes, fact.Source?.ByteSpace ?? ReportByteSpace.Unknown));
        Assert.Equal(64L * 1024 * 1024, observed.Root!.Work.DecodedBytes);
        Assert.True(observed.Root.Work.ReadBytes >= bytes.Length);
        Assert.DoesNotContain(report.Content.DocumentUnits, unit => unit.Location?.Part?.StartsWith("/Volumes/", StringComparison.Ordinal) == true);
    }

    [Theory]
    [InlineData("odt")]
    [InlineData("rtf")]
    public void DeferredNativePayloadsAreCompleteDetachedAndDispatchedOnlyByCore(string format)
    {
        var observed = new ObservedReader();
        InspectionReport report = Read(format == "odt" ? NativeFixtures.Odf(image: true) : NativeFixtures.Rtf(image: true), "source." + format, Options(observed));
        InspectionContentMember member = Assert.Single(observed.Root!.SelectedMembers);
        using Stream bytes = member.OpenRead();
        Assert.False(bytes.CanWrite); Assert.Equal(NativeFixtures.Pixel.Length, bytes.Length);
        using var copy = new MemoryStream(); bytes.CopyTo(copy); Assert.Equal(NativeFixtures.Pixel, copy.ToArray());
        ReportArchiveEntry entry = Assert.Single(report.Content.Entries, entry => entry.InventorySource == ReportArchiveInventorySource.ContentReader && entry.MemberId == member.Id && entry.Ordinal == member.Ordinal);
        Assert.NotNull(entry.Report); Assert.Equal(NativeFixtures.Pixel.Length, entry.SizeBytes);
        Assert.Equal(member.SizeBytes, observed.Root.Work.SelectedBytes);
        Assert.Equal("officeimo-image", entry.Report!.Content.Reader);
    }

    [Fact]
    public void ImageMetadataDistinguishesDefaultResolutionFromAnAuthoredClaimAndNeverBecomesText()
    {
        InspectionReport absent = Read(NativeFixtures.Pixel, "pixel.png");
        Assert.Empty(absent.Content.Text);
        Assert.Contains(absent.Content.Facts, fact => fact.Name == "image.resolution.declared" && fact.Value == "False");
        Assert.DoesNotContain(absent.Content.Facts, fact => fact.Name == "image.resolution.horizontal");
        Assert.Contains(absent.Content.Facts, fact => fact.Name == "image.width" && fact.Value == "1" && fact.Origin == ReportFactOrigin.Embedded);
        byte[] authored = OfficeImageMetadata.Apply(NativeFixtures.Pixel, new OfficeImageMetadata
        { Resolution = new OfficeImageResolution(300, 150, OfficeImageResolutionUnit.PixelsPerInch) });
        InspectionReport present = Read(authored, "pixel.png");
        Assert.Contains(present.Content.Facts, fact => fact.Name == "image.resolution.horizontal" && fact.Origin == ReportFactOrigin.Embedded);
        Assert.Empty(present.Content.Text); Assert.Empty(present.Content.TextFingerprint);
    }

    [Fact]
    public void UnreadablePdfPageIsASeparateFailedOutcomeAndCannotBecomeSearchableFailureText()
    {
        InspectionReport report = Read(NativeFixtures.Pdf(unsupportedFilter: true), "page.pdf");
        Assert.Empty(report.Content.Text); Assert.Empty(report.Content.TextFingerprint); Assert.Empty(report.Content.Keywords);
        Assert.Contains(report.Content.DocumentUnits, unit => unit.Kind == "page-outcome" && unit.Status == InspectionStageStatus.Failed);
        Assert.Contains(report.Content.Diagnostics, diagnostic => diagnostic.Code == "pdf-page-unsupported-content-filter" && diagnostic.Recovery == ReportRecoveryKind.Skipped);
        Assert.Contains(report.Content.Facts, fact => fact.Name == "pdf.source.structure.SourcePageCount" && fact.Value == "1");
    }

    [Fact]
    public void PdfAttachmentUsesItsNativeObjectIdentityAndACompleteDetachedCopy()
    {
        var observed = new ObservedReader();
        InspectionReport report = Read(NativeFixtures.Pdf(attachment: true), "source.pdf", Options(observed));
        InspectionContentMember selected = Assert.Single(observed.Root!.SelectedMembers);
        Assert.Contains("filespec:6:stream:7:occurrence:0", selected.Id);
        Assert.Null(selected.DeclaredSizeBytes);
        ReportArchiveEntry entry = Assert.Single(report.Content.Entries);
        Assert.Equal(ReportArchiveInventorySource.ContentReader, entry.InventorySource);
        Assert.Equal(selected.Id, entry.MemberId); Assert.NotNull(entry.Report);
        Assert.Equal("Complete attached text", entry.Report!.Content.Text);
    }

    [Fact]
    public void CabDuplicateNamesKeepDistinctOrdinalChildrenAndDecodeTheirSharedFolderOnce()
    {
        var observed = new ObservedReader();
        byte[] cab = NativeFixtures.Cab(("../duplicate.txt", Encoding.UTF8.GetBytes("first child")), ("../duplicate.txt", Encoding.UTF8.GetBytes("second child")));
        InspectionReport report = Read(cab, "sample.cab", Options(observed));
        Assert.Equal(2, report.Content.Entries.Count); Assert.Equal(report.Content.Entries[0].Name, report.Content.Entries[1].Name);
        Assert.NotEqual(report.Content.Entries[0].MemberId, report.Content.Entries[1].MemberId);
        Assert.Equal("first child", report.Content.Entries[0].Report!.Content.Text);
        Assert.Equal("second child", report.Content.Entries[1].Report!.Content.Text);
        Assert.Equal(32768, observed.Root!.Work.DecompressionWorkBytes);
        Assert.Equal(23, observed.Root.Work.SelectedBytes); Assert.Equal(cab.Length + 23, observed.Root.Work.ReadBytes);
        Assert.All(report.Content.Entries, entry => Assert.Equal(0, entry.CompressedBytes));
        Assert.All(report.Content.Entries, entry => Assert.Equal(ReportArchiveInventorySource.ContentReader, entry.InventorySource));
    }

    [Fact]
    public void MsiProvidesPassiveMappedFilesAndSeparateStorageInventory()
    {
        byte[] fixture = File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "two-cabinets.msi"));
        var observed = new ObservedReader();
        InspectionReport report = Read(fixture, "sample.msi", Options(observed));
        Assert.Equal(2, observed.Root!.SelectedMembers.Count); Assert.Equal(65536, observed.Root.Work.DecompressionWorkBytes);
        Assert.All(report.Content.Entries, entry => Assert.NotNull(entry.Report));
        Assert.Contains(report.Content.Facts, fact => fact.Name == "archives.storage-stream" && fact.Attributes["selection"] == "inventory-only");
    }

    [Fact]
    public void ConfiguredNativeRtfLimitRemainsTerminalWithExactOriginalMeasurements()
    {
        byte[] bytes = Encoding.ASCII.GetBytes("{\\rtf1 " + new string('x', 900) + "}");
        var options = Options(new OfficeImoContentReader(new OfficeImoContentReaderOptions { MaxNativeExpandedBytes = 512 }));
        var exception = Assert.Throws<InspectionContentLimitException>(() => Read(bytes, "sample.rtf", options));
        Assert.Equal(InspectionContentLimitDomain.Resource, exception.Domain);
        var native = Assert.IsType<RtfReadLimitException>(exception.InnerException);
        Assert.Equal(native.LimitSource, exception.LimitName); Assert.Equal((double)native.Limit, exception.Maximum);
        Assert.Equal((double)native.Actual, exception.Actual);
    }

    [Fact]
    public void ZeroNativeAllowanceRefusesTheClaimedFormatWithoutBuiltinTextFallback()
    {
        var options = Options(); options.MaxNativeExpandedBytes = 0;
        InspectionReport report = Read(NativeFixtures.Rtf(), "source.rtf", options);
        Assert.Empty(report.Content.Text); Assert.Equal(InspectionStageStatus.Unavailable, report.Content.Status);
        Assert.Contains(report.Content.Diagnostics, diagnostic => diagnostic.Code == "officeimo:zero-native-allowance");
    }

    [Fact]
    public void InvalidPdfRetainsAClaimedMalformedResultWithoutLexicalFallback()
    {
        InspectionReport report = Read(Encoding.ASCII.GetBytes("%PDF-1.7\nBT (Do not use lexical fallback) Tj ET"), "source.pdf");
        Assert.Empty(report.Content.Text); Assert.Equal(InspectionStageStatus.Failed, report.Content.Status);
        Assert.Contains(report.Content.Diagnostics, diagnostic => diagnostic.Code.StartsWith("officeimo:pdf-", StringComparison.Ordinal));
    }

    [Fact]
    public void PlainTextIsGenuinelyNotApplicableAndRetainsTheBuiltinReader()
    {
        InspectionReport report = Read(Encoding.UTF8.GetBytes("ordinary text invoices"), "source.txt");
        Assert.Contains("ordinary text", report.Content.Text); Assert.DoesNotContain("officeimo", report.Content.Reader);
    }

    [Fact]
    public void RenamedOpenDocumentUsesDetectedMimeAndRetainsRawZipInventory()
    {
        InspectionReport report = Read(NativeFixtures.Odf(), "renamed.bin");
        Assert.Equal("zip", report.Analysis.DetectedExtension);
        Assert.Equal("application/vnd.oasis.opendocument.text", report.Analysis.DetectedMimeType);
        Assert.Equal("officeimo-opendocument", report.Content.Reader);
        Assert.Contains(NativeFixtures.Text, report.Content.Text);
        Assert.Contains(report.Content.Entries, entry => entry.InventorySource == ReportArchiveInventorySource.RawZip && entry.Name == "content.xml" && entry.MemberId!.StartsWith("zip:entry:", StringComparison.Ordinal));
        Assert.All(report.Content.Entries, entry => Assert.Null(entry.Report));
    }

    [Fact]
    public void FractionalPackageAdmissionRetainsExactNativeMeasurementsAndInnerException()
    {
        var options = Options(new OfficeImoContentReader(new OfficeImoContentReaderOptions { MaxCompressionRatio = 1.25 }));
        InspectionContentLimitException exception = Assert.Throws<InspectionContentLimitException>(() => Read(NativeFixtures.Word(), "source.docx", options));
        var native = Assert.IsType<global::OfficeIMO.OfficePackageSecurityException>(exception.InnerException);
        Assert.Equal(InspectionContentLimitDomain.Admission, exception.Domain);
        Assert.Equal(1.25, exception.Maximum); Assert.Equal(native.ObservedValue, exception.Actual); Assert.Equal(native.Rule.ToString(), exception.LimitName);
    }

    [Fact]
    public void NativePdfRepairIsRecordedAsRecoveredWithoutReplacingPrimaryText()
    {
        InspectionReport report = Read(NativeFixtures.Pdf(incorrectLength: true), "repair.pdf");
        Assert.Contains(NativeFixtures.Text, report.Content.Text);
        Assert.Contains(report.Content.Diagnostics, diagnostic => diagnostic.Code == "pdf-repair-IncorrectStreamLength" && diagnostic.Recovery == ReportRecoveryKind.Repaired);
    }

    [Fact]
    public void MemberRetentionLimitKeepsInventoryAndNeverPublishesAPrefixChild()
    {
        var options = Options(); options.MaxEntryBytes = 4;
        InspectionReport report = Read(NativeFixtures.Cab(("entry.txt", Encoding.ASCII.GetBytes("complete text"))), "source.cab", options);
        ReportArchiveEntry entry = Assert.Single(report.Content.Entries);
        Assert.Equal(13, entry.DeclaredSizeBytes); Assert.Null(entry.Report); Assert.Null(entry.Sha256);
        Assert.Contains(report.Content.Omissions, omission => omission.Code == "officeimo:member-not-selected");
    }

    [Fact]
    public void SmallDisplayAndValueCapsPreserveCompleteNativeMemberIdentity()
    {
        var observed = new ObservedReader();
        var options = Options(observed); options.MaxEntryNameCharacters = 3; options.MaxFactCharacters = 8;
        InspectionReport report = Read(NativeFixtures.Cab(("long-display-name.txt", Encoding.ASCII.GetBytes("complete child"))), "source.cab", options);
        ReportArchiveEntry entry = Assert.Single(report.Content.Entries);
        Assert.Equal("officeimo-archive", report.Content.Reader);
        Assert.Equal("lon", entry.Name); Assert.True(entry.NameTruncated);
        InspectionContentMember selected = Assert.Single(observed.Root!.SelectedMembers);
        Assert.Equal(selected.Id, entry.MemberId); Assert.True(entry.MemberId!.Length > options.MaxFactCharacters);
        Assert.Equal(ReportArchiveInventorySource.ContentReader, entry.InventorySource);
        Assert.Equal("complete child", entry.Report!.Content.Text);
        Assert.Contains(report.Content.Facts, fact => fact.Name == "archives.member.compression");
        Assert.Null(report.Content.Extraction); // Some required profile settings exceed the deliberately small value allowance.
        Assert.Equal(InspectionStageStatus.Partial, report.Content.Status);
    }

    [Fact]
    public void OversizedNativeHeadingLocationIsOmittedWholeWithoutChangingItsPrimaryText()
    {
        string heading = new('h', 300);
        var observed = new ObservedReader();
        var options = Options(observed); options.MaxIdentifierCharacters = 64;
        InspectionReport report = Read(NativeFixtures.WordHeading(heading), "heading.docx", options);
        Assert.Contains(heading, report.Content.Text);
        ReportDocumentUnit nativeUnit = Assert.Single(observed.Root!.Content.DocumentUnits, unit => unit.Kind == "paragraph");
        Assert.Null(nativeUnit.Location!.HeadingPath);
        Assert.Equal(InspectionStageStatus.Partial, report.Content.Status);
        Assert.Contains(observed.Root.Content.Omissions, omission => omission.Code == "officeimo:response-limit");
    }

    [Fact]
    public void NativeCoverageAndComputedCountsRemainDerivedEvidence()
    {
        InspectionReport report = Read(NativeFixtures.Rtf(), "source.rtf");
        Assert.Contains(report.Content.Facts, fact => fact.Name == "rtf.summary.SourceBlockCount" &&
            fact.Origin == ReportFactOrigin.Derived && fact.Kind == ReportFactKind.Integer);
        Assert.All(report.Content.Facts.Where(fact => fact.Name.StartsWith("inspection.coverage.", StringComparison.Ordinal)),
            fact => Assert.Equal(ReportFactOrigin.Derived, fact.Origin));
    }

    [Fact]
    public void NativeExcelConfiguredSharedStringQuotaRemainsTerminal()
    {
        var reader = new OfficeImoContentReader(new OfficeImoContentReaderOptions { MaxSourceRecords = 32 });
        InspectionContentLimitException exception = Assert.Throws<InspectionContentLimitException>(() =>
            Read(NativeFixtures.ExcelStrings(64), "source.xlsx", Options(reader)));
        var native = Assert.IsType<global::OfficeIMO.Reader.ReaderResourceLimitException>(exception.InnerException);
        Assert.Equal("excel.MaxSharedStringItems", native.LimitName);
        Assert.Equal(native.LimitName, exception.LimitName); Assert.Equal(32d, exception.Maximum);
    }

    [Fact]
    public void ConstructorSnapshotsTextChangingPolicyAndComparisonPreservesItsBasis()
    {
        var settings = new OfficeImoContentReaderOptions { IncludeNotes = true };
        var reader = new OfficeImoContentReader(settings); settings.IncludeNotes = false;
        InspectionReport left = Read(NativeFixtures.Rtf(), "left.rtf", Options(reader));
        InspectionReport right = Read(Encoding.ASCII.GetBytes("{\\rtf1 " + NativeFixtures.Text + " Additional invoices.}"), "right.rtf", Options(new OfficeImoContentReader(settings)));
        Assert.Equal("True", left.Content.Extraction!.Settings["notes"]);
        Assert.Equal("False", right.Content.Extraction!.Settings["notes"]);
        Assert.DoesNotContain(ReportComparison.Compare(left, right), evidence => evidence.Basis == "extracted-text-shingles");
    }

    private static InspectionReportOptions Options(IInspectionContentReader? reader = null) => new() { ContentReader = reader ?? new OfficeImoContentReader() };
    private static InspectionReport Read(byte[] bytes, string name, InspectionReportOptions? options = null)
    { using var source = new MemoryStream(bytes); return FileInspector.AnalyzeReport(source, name, options ?? Options()); }

    private sealed class ObservedReader : IInspectionContentReader
    {
        private readonly OfficeImoContentReader _inner = new();
        internal InspectionContentReadResult? Root { get; private set; }
        public InspectionContentReadResult Read(InspectionContentReadRequest request, CancellationToken token = default)
        { InspectionContentReadResult result = _inner.Read(request, token); if (request.Depth == 0) Root = result; return result; }
    }
}
