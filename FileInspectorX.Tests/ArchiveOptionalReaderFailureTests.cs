using System.Text;
using Xunit;
using static FileInspectorX.Tests.OptionalContentReaderIntegrationTests;

namespace FileInspectorX.Tests;

public sealed class ArchiveOptionalReaderFailureTests
{
    [Theory]
    [InlineData("zip", "configuration")]
    [InlineData("tar", "configuration")]
    [InlineData("zip", "io")]
    [InlineData("tar", "io")]
    [InlineData("zip", "terminal")]
    [InlineData("tar", "terminal")]
    public void ADescendantReaderFailureKeepsItsPublicErrorBoundary(string format, string kind)
    {
        Exception failure = kind == "configuration" ? new ArgumentException("Invalid reader configuration.") :
            kind == "io" ? new IOException("Source I/O failed.") :
            new InspectionContentLimitException(InspectionContentLimitDomain.Resource, "native:limit", "native", 1, 2);
        using var archive = ArchiveReportCoverageTests.Archive(format, ("member.txt", Encoding.UTF8.GetBytes("Stored member content.")));
        var reader = new CallbackReader(request => request.Depth == 0 ? Empty() : throw failure);
        var observed = Record.Exception(() => FileInspector.AnalyzeReport(archive, "root." + format,
            new InspectionReportOptions { ContentReader = reader }));
        Assert.Same(failure, observed);
    }

    [Theory]
    [InlineData(InspectionContentReadDisposition.NotApplicable)]
    [InlineData(InspectionContentReadDisposition.Handled)]
    [InlineData(InspectionContentReadDisposition.Refused)]
    [InlineData(InspectionContentReadDisposition.Malformed)]
    public void CorruptRawZipPayloadCannotDiscardAnAdmittedReaderResponse(InspectionContentReadDisposition disposition)
    {
        using var archive = UnsupportedMethodZip();
        var reader = new CallbackReader(_ => disposition == InspectionContentReadDisposition.NotApplicable ? Empty() :
            Result(disposition, new ContentProfile { Reader = "native", Diagnostics = new[]
                { new ReportDiagnostic { Code = "source-refused", Category = "parse", Message = "Source profile is unavailable." } } }));
        var report = FileInspector.AnalyzeReport(archive, "malformed.zip", new InspectionReportOptions { ContentReader = reader });
        Assert.Equal(InspectionOutcome.Partial, report.Outcome);
        if (disposition != InspectionContentReadDisposition.NotApplicable)
            Assert.Equal("source-refused", Assert.Single(report.Content.Diagnostics).Code);
        Assert.Empty(report.Content.Text);
    }

#if NET8_0_OR_GREATER
    [Fact]
    public void NativeAndRawMemberIdentitiesRemainDistinctInSavedReports()
    {
        using var archive = ArchiveReportCoverageTests.Archive("zip", ("member.txt", Encoding.UTF8.GetBytes("Stored member content.")));
        var reader = new CallbackReader(_ => Result(InspectionContentReadDisposition.Handled, new ContentProfile { Reader = "native", Entries = new[]
            { new ReportArchiveEntry { MemberId = "zip:entry:0", Ordinal = 0, Name = "native.txt", Kind = ReportArchiveEntryKind.File } } }));
        var report = FileInspector.AnalyzeReport(archive, "package.zip", new InspectionReportOptions { ContentReader = reader });
        using var saved = System.Text.Json.JsonDocument.Parse(System.Text.Json.JsonSerializer.Serialize(report.Content.Entries));
        var identities = saved.RootElement.EnumerateArray().Select(entry => (
            entry.TryGetProperty("InventorySource", out var scope) ? scope.GetInt32() : 0,
            entry.GetProperty("MemberId").GetString(), entry.GetProperty("Ordinal").GetInt32())).ToArray();
        Assert.Equal(2, identities.Distinct().Count());
    }
#endif

    [Fact]
    public void WholeMemberMatchesIdentifyTheirProducingInventories()
    {
        var bytes = Encoding.UTF8.GetBytes("Stored member content.");
        using var archive = ArchiveReportCoverageTests.Archive("zip", ("member.txt", bytes));
        var reader = new CallbackReader(_ => Result(InspectionContentReadDisposition.Handled, new ContentProfile { Reader = "native", Entries = new[]
            { new ReportArchiveEntry { MemberId = "zip:entry:0", Ordinal = 0, Name = "member.txt", Kind = ReportArchiveEntryKind.File,
                SizeBytes = bytes.Length, Sha256 = FileInspector.ReportHash(bytes) } } }));
        var report = FileInspector.AnalyzeReport(archive, "package.zip", new InspectionReportOptions { ContentReader = reader });
        var comparison = Assert.Single(ReportComparison.Compare(report, report), evidence => evidence.Basis == "whole-archive-members");
        Assert.Equal(new[] { ReportArchiveInventorySource.ContentReader, ReportArchiveInventorySource.RawZip }, comparison.Matches.Select(match => match.LeftInventorySource));
        Assert.All(comparison.Matches, match =>
        {
            Assert.Equal(match.LeftInventorySource, match.RightInventorySource);
            Assert.Equal("zip:entry:0", match.LeftMemberId); Assert.Equal("zip:entry:0", match.RightMemberId);
        });
    }

    [Theory]
    [InlineData("zip")]
    [InlineData("tar")]
    public void FactValueLimitsDoNotChangeWholeMemberHashes(string format)
    {
        var bytes = Encoding.UTF8.GetBytes("Stored member content.");
        using var archive = ArchiveReportCoverageTests.Archive(format, ("member.txt", bytes));
        var report = FileInspector.AnalyzeReport(archive, "root." + format,
            new InspectionReportOptions { MaxFactCharacters = 2, MaxNestedReports = 0 });
        Assert.Equal(FileInspector.ReportHash(bytes), Assert.Single(report.Content.Entries).Sha256);
    }

    [Fact]
    public void BytesReadBeforeATarHeaderFailureStillReduceTheNextSiblingsAllowance()
    {
        using var original = ArchiveReportCoverageTests.Archive("tar", ("first.bin", new byte[] { 1, 2, 3, 4 }));
        var brokenTar = original.ToArray(); brokenTar[1024] = 1; // Nonempty next header with an invalid checksum.
        var next = new byte[] { 9 }; long? observed = null;
        using var outer = ArchiveReportCoverageTests.Archive("zip", ("broken.tar", brokenTar), ("next.bin", next));
        var reader = new CallbackReader(request =>
        {
            if (request.DisplayName != "next.bin") return Empty();
            observed = request.Budgets.RemainingExpandedBytes;
            return Result(InspectionContentReadDisposition.Handled, new ContentProfile { Reader = "native" });
        });
        var report = FileInspector.AnalyzeReport(outer, "outer.zip", new InspectionReportOptions { ContentReader = reader,
            MaxEntryBytes = 4096, MaxExpandedBytes = brokenTar.Length + next.Length + 8 });
        Assert.Equal(4, observed);
        var interrupted = report.Content.Entries[0].Report!.Content;
        Assert.Equal(InspectionStageStatus.Partial, interrupted.Status);
        Assert.Contains("tar:invalid-header", interrupted.Issues);
        Assert.Equal("native", report.Content.Entries[1].Report!.Content.Reader);
    }

    private static MemoryStream UnsupportedMethodZip()
    {
        using var original = ArchiveReportCoverageTests.Archive("zip", ("member.txt", Encoding.UTF8.GetBytes("Stored member content.")));
        var bytes = original.ToArray();
        bytes[8] = 99; bytes[9] = 0;
        for (var index = 0; index + 12 <= bytes.Length; index++)
            if (BitConverter.ToUInt32(bytes, index) == 0x02014b50)
            { bytes[index + 10] = 99; bytes[index + 11] = 0; break; }
        return new MemoryStream(bytes, writable: false);
    }
}
