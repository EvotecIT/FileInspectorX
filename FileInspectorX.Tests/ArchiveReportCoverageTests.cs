using System.IO.Compression;
using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class ArchiveReportCoverageTests
{
    [Theory]
    [InlineData("tar")]
    [InlineData("zip")]
    public void OversizedMemberRetainsInventoryAndMarksContentPartial(string format)
    {
        var oversized = Encoding.ASCII.GetBytes("Oversized member");
        var readable = Encoding.ASCII.GetBytes("one");
        using var archive = Archive(format, ("large.bin", oversized), ("small.bin", readable));

        var report = FileInspector.AnalyzeReport(archive, "files." + format,
            new InspectionReportOptions { MaxEntryBytes = readable.Length });

        Assert.Equal(new[] { "large.bin", "small.bin" }, report.Content.Entries.Select(entry => entry.Name));
        Assert.Null(report.Content.Entries[0].Sha256);
        Assert.Equal(FileInspector.ReportHash(readable), report.Content.Entries[1].Sha256);
        Assert.Contains("content:member-not-fully-read", report.Content.Issues);
        Assert.Equal(InspectionStageStatus.Partial, report.Content.Status);
        Assert.Equal(InspectionOutcome.Partial, report.Outcome);
    }

    [Theory]
    [InlineData("tar")]
    [InlineData("zip")]
    public void ExhaustedTotalBudgetExplainsUnhashedMember(string format)
    {
        var readable = Encoding.ASCII.GetBytes("one");
        using var archive = Archive(format, ("first.bin", readable), ("second.bin", new byte[] { 1 }));

        var report = FileInspector.AnalyzeReport(archive, "files." + format,
            new InspectionReportOptions { MaxExpandedBytes = readable.Length, MaxNestedReports = 0 });

        Assert.Equal(2, report.Content.Entries.Count);
        Assert.Equal(FileInspector.ReportHash(readable), report.Content.Entries[0].Sha256);
        Assert.Null(report.Content.Entries[1].Sha256);
        Assert.Contains("archive:total-read-limit", report.Content.Issues);
        Assert.Contains("content:member-not-fully-read", report.Content.Issues);
        Assert.Equal(InspectionStageStatus.Partial, report.Content.Status);
    }

    [Theory]
    [InlineData("tar")]
    [InlineData("zip")]
    public void MembersAtTheReadLimitRetainWholeHashesWithoutPartialCoverage(string format)
    {
        var readable = Encoding.ASCII.GetBytes("one");
        using var archive = Archive(format, ("empty.bin", Array.Empty<byte>()), ("full.bin", readable));

        var report = FileInspector.AnalyzeReport(archive, "files." + format,
            new InspectionReportOptions { MaxEntryBytes = readable.Length, MaxExpandedBytes = readable.Length, MaxNestedReports = 0 });

        Assert.Equal(FileInspector.ReportHash(Array.Empty<byte>()), report.Content.Entries[0].Sha256);
        Assert.Equal(FileInspector.ReportHash(readable), report.Content.Entries[1].Sha256);
        Assert.Empty(report.Content.Issues);
        Assert.Equal(InspectionStageStatus.Completed, report.Content.Status);
    }

    [Theory]
    [InlineData("tar")]
    [InlineData("zip")]
    public void DirectoryInventoryDoesNotImplyMissingMemberContent(string format)
    {
        using var archive = Archive(format, ("folder/", Array.Empty<byte>()));

        var report = FileInspector.AnalyzeReport(archive, "files." + format);

        Assert.Equal("folder/", Assert.Single(report.Content.Entries).Name);
        Assert.Null(report.Content.Entries[0].Sha256);
        Assert.Empty(report.Content.Issues);
        Assert.Equal(InspectionStageStatus.Completed, report.Content.Status);
    }

    [Fact]
    public void OversizedOfficePartKeepsItsSpecificSizeLimitIssue()
    {
        using var archive = Archive("zip", ("word/document.xml", Encoding.ASCII.GetBytes("<document/>")));

        var report = FileInspector.AnalyzeReport(archive, "document.docx",
            new InspectionReportOptions { MaxEntryBytes = 3 });

        Assert.Null(Assert.Single(report.Content.Entries).Sha256);
        Assert.Contains("content:package-part-size-limit", report.Content.Issues);
        Assert.Contains("content:member-not-fully-read", report.Content.Issues);
        Assert.Equal(InspectionStageStatus.Partial, report.Content.Status);
    }

    private static MemoryStream Archive(string format, params (string Name, byte[] Content)[] members)
    {
        var output = new MemoryStream();
        if (format == "zip")
        {
            using var zip = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true);
            foreach (var member in members)
            {
                using var payload = zip.CreateEntry(member.Name, CompressionLevel.NoCompression).Open();
                payload.Write(member.Content, 0, member.Content.Length);
            }
        }
        else
        {
            foreach (var member in members)
            {
                var header = new byte[512];
                Encoding.ASCII.GetBytes(member.Name).CopyTo(header, 0);
                Encoding.ASCII.GetBytes(Convert.ToString(member.Content.Length, 8).PadLeft(11, '0')).CopyTo(header, 124);
                header[156] = member.Name.EndsWith("/", StringComparison.Ordinal) ? (byte)'5' : (byte)'0';
                Encoding.ASCII.GetBytes("ustar").CopyTo(header, 257);
                TestHelpers.SealTarHeader(header);
                output.Write(header, 0, header.Length);
                output.Write(member.Content, 0, member.Content.Length);
                var padding = new byte[(512 - member.Content.Length % 512) % 512];
                output.Write(padding, 0, padding.Length);
            }
            output.Write(new byte[1024], 0, 1024);
        }
        output.Position = 0;
        return output;
    }
}
