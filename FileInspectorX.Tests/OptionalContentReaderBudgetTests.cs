using Xunit;
using static FileInspectorX.Tests.OptionalContentReaderIntegrationTests;

namespace FileInspectorX.Tests;

public sealed class OptionalContentReaderBudgetTests
{
    [Fact]
    public void DescendantsShareNativeReservationsAndBothDetachedCopiesAreCharged()
    {
        var observed = new List<(long Expanded, long Read, long Work, long Members)>();
        var reader = new CallbackReader(request =>
        {
            var b = request.Budgets; observed.Add((b.NativeExpandedBytes, b.NativeReadBytes, b.DecompressionWorkBytes, b.RemainingExpandedBytes));
            if (request.Depth != 0)
                return Result(b.NativeExpandedBytes == 0 ? InspectionContentReadDisposition.Refused : InspectionContentReadDisposition.Handled,
                    new ContentProfile { Reader = "native" }, work: new InspectionContentWork(0, 1, b.NativeExpandedBytes, 2));
            return Result(InspectionContentReadDisposition.Handled, new ContentProfile { Reader = "native", Entries = new[]
            {
                new ReportArchiveEntry { MemberId = "a", Name = "a.bin", Kind = ReportArchiveEntryKind.File, Ordinal = 0, SizeBytes = 2 },
                new ReportArchiveEntry { MemberId = "b", Name = "b.bin", Kind = ReportArchiveEntryKind.File, Ordinal = 1, SizeBytes = 2 }
            } }, new[] { new InspectionContentMember(0, "a", "a.bin", ReportArchiveEntryKind.File, null, new byte[] { 1, 2 }),
                new InspectionContentMember(1, "b", "b.bin", ReportArchiveEntryKind.File, null, new byte[] { 3, 4 }) },
                new InspectionContentWork(4, 1, b.NativeExpandedBytes, 2));
        });
        using var source = new MemoryStream(new byte[] { 9 });
        var report = FileInspector.AnalyzeReport(source, options: new InspectionReportOptions { ContentReader = reader,
            MaxNativeExpandedBytes = 32, MaxTotalNativeExpandedBytes = 64, MaxNativeReadBytes = 100, MaxDecompressionWorkBytes = 100, MaxExpandedBytes = 8 });
        Assert.Equal(new[] { (32L, 100L, 100L, 8L), (32L, 99L, 98L, 0L), (0L, 98L, 96L, 0L) }, observed);
        Assert.All(report.Content.Entries, entry => Assert.NotNull(entry.Report));
        Assert.Contains("content:reader-refused", report.Content.Entries[1].Report!.Content.Issues);
    }

    [Fact]
    public void ClaimedNativeWorkBeyondTheReservationIsTerminal()
    {
        var reader = new CallbackReader(request => Result(InspectionContentReadDisposition.Handled, new ContentProfile(),
            work: new InspectionContentWork(0, request.Budgets.NativeReadBytes + 1, 0, 0)));
        using var source = new MemoryStream(new byte[] { 1 });
        var error = Assert.Throws<InspectionContentLimitException>(() => FileInspector.AnalyzeReport(source,
            options: new InspectionReportOptions { ContentReader = reader, MaxNativeReadBytes = 4 }));
        Assert.Equal(nameof(InspectionReportOptions.MaxNativeReadBytes), error.LimitName); Assert.Equal(4, error.Maximum); Assert.Equal(5, error.Actual);
    }

    [Fact]
    public void BatchKeepsSnapshotLimitDistinctFromTerminalAndOrdinaryReaderFailures()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".bin"); File.WriteAllBytes(path, new byte[] { 1, 2 });
        try
        {
            Assert.Equal("batch:input-size-limit", Assert.Single(FileInspector.AnalyzeReports(new[] { path }, new InspectionReportOptions { MaxInputBytes = 1 })).Issue);
            var native = new InspectionContentLimitException(InspectionContentLimitDomain.Admission, "ratio", "ratio", 1.5, 2.5, new InvalidDataException());
            foreach (var failure in new Exception[] { native, new InvalidOperationException("configuration"), new OutOfMemoryException("synthetic"), new InvalidDataException("untranslated parser failure") })
            {
                var reader = new CallbackReader(_ => throw failure);
                var observed = Record.Exception(() => FileInspector.AnalyzeReports(new[] { path }, new InspectionReportOptions { ContentReader = reader }).ToArray());
                Assert.Same(failure, observed);
            }
            var ordinary = new CallbackReader(_ => throw new IOException("source I/O"));
            Assert.Equal("batch:input-unavailable", Assert.Single(FileInspector.AnalyzeReports(new[] { path }, new InspectionReportOptions { ContentReader = ordinary })).Issue);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void NonemptyNotApplicableCannotSilentlyFallback()
    {
        using var source = new MemoryStream(new byte[] { 1 });
        var reader = new CallbackReader(_ => Result(InspectionContentReadDisposition.NotApplicable, new ContentProfile { Text = "hidden source work" }));
        Assert.Throws<InvalidOperationException>(() => FileInspector.AnalyzeReport(source, options: new InspectionReportOptions { ContentReader = reader }));
    }
}
