using System.IO.Compression;
using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class OptionalContentReaderIntegrationTests
{
    [Theory]
    [InlineData(InspectionContentReadDisposition.NotApplicable)]
    [InlineData(InspectionContentReadDisposition.Handled)]
    [InlineData(InspectionContentReadDisposition.Refused)]
    [InlineData(InspectionContentReadDisposition.Malformed)]
    public void OnlyAnEmptyNotApplicableResponseEnablesBuiltinPrimary(InspectionContentReadDisposition disposition)
    {
        const string original = "Original invoices describe quarterly customer revenue.";
        var reader = new CallbackReader(request => disposition == InspectionContentReadDisposition.NotApplicable ? Empty() :
            Result(disposition, new ContentProfile { Reader = "native", Text = "Canonical project planning text.",
                Diagnostics = new[] { new ReportDiagnostic { Category = "parse", Code = "warning", Message = "Invisible diagnostic-only zebra", Severity = ReportDiagnosticSeverity.Warning } } }));
        using var source = new MemoryStream(Encoding.UTF8.GetBytes(original));
        var report = FileInspector.AnalyzeReport(source, "original.txt", new InspectionReportOptions { ContentReader = reader });
        Assert.Equal(1, reader.Calls);
        Assert.Equal(FileInspector.ReportHash(source.ToArray()), report.File.Sha256);
        if (disposition == InspectionContentReadDisposition.NotApplicable)
        { Assert.Equal(original, report.Content.Text); Assert.Equal("utf-text", report.Content.Reader); }
        else if (disposition == InspectionContentReadDisposition.Handled)
        { Assert.Equal("Canonical project planning text.", report.Content.Text); Assert.DoesNotContain("zebra", report.Content.Keywords); }
        else
        { Assert.Empty(report.Content.Text); Assert.Empty(report.Content.Keywords); Assert.Empty(report.Content.TextFingerprint); }
    }

#if NET8_0_OR_GREATER
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public void ActualSnapshotAccessIsNeutralAndExpiresOnSuccessOrFailure(bool spill, bool fail)
    {
        var directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N")); Directory.CreateDirectory(directory);
        InspectionContentReadRequest? retainedRequest = null; Stream? retainedStream = null;
        var bytes = Encoding.UTF8.GetBytes("Bounded original source text.");
        var reader = new CallbackReader(request =>
        {
            retainedRequest = request;
            Assert.Equal("file.txt", request.DisplayName); Assert.Equal(FileInspector.ReportHash(bytes), request.SnapshotSha256);
            request.OpenRead(stream =>
            {
                retainedStream = stream;
                Assert.False(stream is MemoryStream or FileStream); Assert.False(stream.CanWrite);
                Assert.Equal(0, stream.Position); Assert.Equal(bytes.Length, stream.Length);
                Assert.Throws<NotSupportedException>(() => stream.WriteByte(1));
                using var copy = new MemoryStream(); stream.CopyTo(copy); Assert.Equal(bytes, copy.ToArray());
                return 0;
            });
            Assert.False(retainedStream!.CanRead);
            if (fail) throw new InspectionContentLimitException(InspectionContentLimitDomain.Resource, "native:limit", "native", 1, 2);
            return Empty();
        });
        try
        {
            using var source = new MemoryStream(bytes); source.Position = 5;
            var options = new InspectionReportOptions { ContentReader = reader, SnapshotDirectory = directory, MaxMemorySnapshotBytes = spill ? 1 : 1024 };
            if (fail) Assert.Throws<InspectionContentLimitException>(() => FileInspector.AnalyzeReport(source, "/private/file.txt", options));
            else Assert.NotNull(FileInspector.AnalyzeReport(source, "/private/file.txt", options));
            Assert.Equal(5, source.Position); Assert.True(source.CanRead); Assert.Empty(Directory.GetFiles(directory));
            Assert.Throws<ObjectDisposedException>(() => retainedRequest!.OpenRead(stream => stream.ReadByte()));
            Assert.Throws<ObjectDisposedException>(() => retainedStream!.ReadByte());
        }
        finally { Directory.Delete(directory, true); }
    }
#endif

    [Fact]
    public void ClaimedPackageKeepsRawInventoryWithoutBuiltinTextOrPackagePartChildren()
    {
        using var source = new MemoryStream();
        using (var zip = new ZipArchive(source, ZipArchiveMode.Create, true))
        {
            using var writer = new StreamWriter(zip.CreateEntry("word/document.xml").Open());
            writer.Write("<document xmlns='http://schemas.openxmlformats.org/wordprocessingml/2006/main'><p><t>Wrong builtin primary</t></p></document>");
        }
        source.Position = 0;
        var reader = new CallbackReader(_ => Result(InspectionContentReadDisposition.Handled, new ContentProfile { Reader = "native", Text = "Canonical source text" }));
        var report = FileInspector.AnalyzeReport(source, "package.docx", new InspectionReportOptions { ContentReader = reader });
        Assert.Equal(1, reader.Calls); Assert.Equal("Canonical source text", report.Content.Text);
        var member = Assert.Single(report.Content.Entries);
        Assert.Equal("zip:entry:0", member.MemberId); Assert.NotNull(member.Sha256); Assert.Null(member.Report);
        Assert.DoesNotContain(report.Content.Issues, issue => issue.StartsWith("content:ooxml-", StringComparison.Ordinal));
    }

    [Fact]
    public void SelectedChildUsesIdentityAndRunsAfterParentReaderReturns()
    {
        var first = Encoding.UTF8.GetBytes("Selected first member has invoice text.");
        var second = Encoding.UTF8.GetBytes("Second native member has weather text.");
        var reader = new CallbackReader(request => request.Depth != 0 ? Empty() :
            Result(InspectionContentReadDisposition.Handled, new ContentProfile { Reader = "native", Entries = new[]
            {
                new ReportArchiveEntry { MemberId = "part:first", Name = "same.txt", Ordinal = 0, Kind = ReportArchiveEntryKind.File, SizeBytes = first.Length },
                new ReportArchiveEntry { MemberId = "part:second", Name = "same.txt", Ordinal = 1, Kind = ReportArchiveEntryKind.File, SizeBytes = second.Length }
            } }, new[] { new InspectionContentMember(1, "part:second", "same.txt", ReportArchiveEntryKind.File, null, second) },
                new InspectionContentWork(second.Length, 0, 0, 0)));
        using var source = new MemoryStream(new byte[] { 1, 2, 3 });
        var report = FileInspector.AnalyzeReport(source, "parent.bin", new InspectionReportOptions { ContentReader = reader });
        Assert.Equal(2, reader.Calls); Assert.Null(report.Content.Entries[0].Report);
        var child = report.Content.Entries[1].Report!;
        Assert.Equal(FileInspector.ReportHash(second), child.File.Sha256); Assert.Contains("weather", child.Content.Text);
        Assert.Equal(FileInspector.ReportHash(second), report.Content.Entries[1].Sha256);
    }

    [Fact]
    public void OutputAdmissionBoundsLocationsAttributesIdentifiersAndRetainedTextSpans()
    {
        var reader = new CallbackReader(_ => Result(InspectionContentReadDisposition.Handled, new ContentProfile
        {
            Reader = "native", Text = "abcd😀z",
            Extraction = new ReportExtractionDescriptor { ReaderId = "native", ReaderVersion = "1", ProfileId = new string('p', 9), TextBasis = ReportTextBasis.CanonicalDocumentText },
            Facts = new[] { new ReportFact { Name = "fact", Kind = ReportFactKind.Text, Value = "abcdefghijkl",
                LogicalSource = new ReportLogicalLocation { Part = new string('a', 9), Page = 2 }, Attributes = new Dictionary<string, string> { ["ok"] = "yes", ["large"] = new string('b', 9) } },
                new ReportFact { Name = "number", Kind = ReportFactKind.Integer, Value = "123456789" } },
            DocumentUnits = new[] { new ReportDocumentUnit { Id = "unit", Kind = "page", Ordinal = 0, TextStart = 2, TextLength = 5, Status = InspectionStageStatus.Completed } },
            Diagnostics = new[] { new ReportDiagnostic { Code = "warning", Category = "parse", Message = "abcdefghijk", Attributes = new Dictionary<string, string> { ["count"] = "123456789" } } }
        }));
        using var source = new MemoryStream(new byte[] { 1 });
        var report = FileInspector.AnalyzeReport(source, options: new InspectionReportOptions { ContentReader = reader,
            MaxFactCharacters = 8, MaxIdentifierCharacters = 8, MaxTextCharacters = 5 });
        Assert.Equal("abcd", report.Content.Text); Assert.Null(report.Content.Extraction);
        var fact = Assert.Single(report.Content.Facts); Assert.Equal("abcdefgh", fact.Value); Assert.True(fact.Truncated);
        Assert.Null(fact.LogicalSource!.Part); Assert.Equal(2, fact.LogicalSource.Page); Assert.Single(fact.Attributes);
        var unit = Assert.Single(report.Content.DocumentUnits); Assert.Equal(2, unit.TextStart); Assert.Equal(2, unit.TextLength); Assert.Equal(InspectionStageStatus.Partial, unit.Status);
        var diagnostic = Assert.Single(report.Content.Diagnostics); Assert.Equal("abcdefgh", diagnostic.Message); Assert.Empty(diagnostic.Attributes);
    }

    internal static InspectionContentReadResult Empty() => Result(InspectionContentReadDisposition.NotApplicable, new ContentProfile());
    internal static InspectionContentReadResult Result(InspectionContentReadDisposition disposition, ContentProfile content,
        IReadOnlyList<InspectionContentMember>? members = null, InspectionContentWork? work = null)
        => new(disposition, content, members ?? Array.Empty<InspectionContentMember>(), work ?? new InspectionContentWork(0, 0, 0, 0));

    internal sealed class CallbackReader(Func<InspectionContentReadRequest, InspectionContentReadResult> read) : IInspectionContentReader
    {
        internal int Calls;
        public InspectionContentReadResult Read(InspectionContentReadRequest request, CancellationToken cancellationToken = default)
        { Interlocked.Increment(ref Calls); return read(request); }
    }
}
