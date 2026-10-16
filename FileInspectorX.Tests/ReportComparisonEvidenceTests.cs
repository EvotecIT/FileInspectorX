using System.IO.Compression;
using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class ReportComparisonEvidenceTests
{
    [Fact]
    public void WholeMemberComparisonMatchesRenamedBytesAndRetainsDuplicateOrdinals()
    {
        var left = Archive(("same.txt", "Invoices for the quarter"), ("same.txt", "Invoices for the quarter"), ("left.txt", "Different input"));
        var right = Archive(("renamed.txt", "Invoices for the quarter"), ("right.txt", "Completely unrelated"));
        var result = Assert.Single(ReportComparison.Compare(left, right), e => e.Basis == "whole-archive-members");
        Assert.Equal(3, result.ComparedLeft); Assert.Equal(2, result.ComparedRight); Assert.Equal(0.25, result.Score);
        var match = Assert.Single(result.Matches); Assert.Equal("same.txt", match.LeftName); Assert.Equal("renamed.txt", match.RightName);
        Assert.Equal(0, match.LeftOrdinal); Assert.Equal(0, match.RightOrdinal);
        Assert.Equal(new[] { 0, 1, 2 }, left.Content.Entries.Select(e => e.Ordinal));
        Assert.NotNull(left.Content.Entries[0].Report);
        Assert.Equal(left.Content.Entries[0].Sha256, left.Content.Entries[0].Report!.File.Sha256);
    }

    [Fact]
    public void NestedArchiveReportsShareExpansionAndDescendantBudgets()
    {
        var nested = ZipBytes(("inside.txt", Encoding.UTF8.GetBytes("Nested document evidence")));
        var bytes = ZipBytes(("one.zip", nested), ("two.zip", nested));
        var options = new InspectionReportOptions { MaxExpandedBytes = nested.Length * 2, MaxNestedReports = 1 };
        var report = Analyze(bytes, "archive.zip", options);
        Assert.Equal(2, report.Content.Entries.Count);
        Assert.NotNull(report.Content.Entries[0].Report); Assert.Null(report.Content.Entries[1].Report);
        Assert.Contains("content:nested-report-limit", report.Content.Issues);
        var child = report.Content.Entries[0].Report!;
        Assert.Null(child.Content.Entries[0].Sha256);
        Assert.Contains("archive:total-read-limit", child.Content.Issues);
        Assert.Equal(InspectionOutcome.Partial, report.Outcome);
    }

    [Fact]
    public void DepthLimitKeepsMemberIdentityWithoutInventingNestedCompleteness()
    {
        var leaf = Encoding.UTF8.GetBytes("Nested document evidence");
        var bytes = ZipBytes(("inner.zip", ZipBytes(("leaf.txt", leaf))));
        var report = Analyze(bytes, "outer.zip", new InspectionReportOptions { MaxNestedDepth = 1 });
        var child = Assert.Single(report.Content.Entries).Report!;
        Assert.NotNull(Assert.Single(child.Content.Entries).Sha256);
        Assert.Null(child.Content.Entries[0].Report);
        Assert.Contains("content:nested-report-limit", child.Content.Issues);
        Assert.Equal(InspectionOutcome.Partial, report.Outcome);
    }

    [Fact]
    public void DescendantContentSharesCharacterBudgetAndLongNamesKeepOrdinalIdentity()
    {
        var bytes = ZipBytes(("first.txt", Encoding.UTF8.GetBytes(new string('a', 800))), ("second.txt", Encoding.UTF8.GetBytes(new string('b', 800))));
        const int characterBudget = 512;
        var report = Analyze(bytes, "outer.zip", new InspectionReportOptions { MaxTotalContentCharacters = characterBudget });
        Assert.Equal(2, report.Content.Entries.Count);
        Assert.All(report.Content.Entries, entry => Assert.NotNull(entry.Report));
        var children = report.Content.Entries.Select(e => e.Report!).ToArray();
        var profiles = children.Select(c => c.Content).Append(report.Content).ToArray();
        Assert.NotEmpty(children[0].Content.Text);
        Assert.True(profiles.Sum(c => c.Text.Length + c.Facts.Sum(f => f.Name.Length + f.Value.Length) + c.Metadata.Sum(p => p.Key.Length + p.Value.Length)) <= characterBudget);
        Assert.Contains(profiles, c => c.Issues.Contains("content:aggregate-character-limit"));
        bytes = ZipBytes((new string('x', 200) + ".txt", Encoding.UTF8.GetBytes("Readable text")));
        report = Analyze(bytes, "outer.zip", new InspectionReportOptions { MaxEntryNameCharacters = 12 });
        var member = Assert.Single(report.Content.Entries); Assert.True(member.NameTruncated); Assert.Equal(204, member.SourceNameCharacters);
        Assert.Equal(0, member.Ordinal); Assert.Equal(12, member.Name.Length); Assert.NotNull(member.Sha256); Assert.Null(member.Report);
        Assert.Contains("content:member-name-limit", report.Content.Issues);
    }

    [Fact]
    public void SampledBlocksExposeCoverageInsteadOfWholeFileSimilarity()
    {
        var first = new byte[150000]; for (int i = 0; i < first.Length; i++) first[i] = (byte)(i * 31 + 11);
        var second = (byte[])first.Clone(); second[140000] ^= 255;
        var options = new InspectionReportOptions { MaxRegions = 1 };
        var left = Analyze(first, "first.bin", options); var right = Analyze(second, "second.bin", options);
        Assert.NotEqual(left.File.Sha256, right.File.Sha256);
        var compared = Assert.Single(ReportComparison.Compare(left, right), e => e.Basis == "sampled-fixed-blocks");
        Assert.Equal(1, compared.Score); Assert.True(compared.Partial);
        Assert.Equal(65536, compared.ComparedBytesLeft); Assert.Equal(65536, compared.ComparedBytesRight);
        Assert.Equal(65536, Assert.Single(compared.Matches).ByteLength);
        Assert.Contains("content:region-coverage-limit", left.Content.Issues);
    }

    [Fact]
    public void RegionHashBudgetNeverPublishesPrefixAsWholeRegionDigest()
    {
        var bytes = File.ReadAllBytes(typeof(FileInspector).Assembly.Location);
        var report = Analyze(bytes, "assembly.dll", new InspectionReportOptions { MaxRegionBytes = 1 });
        Assert.NotEmpty(report.Content.Regions);
        Assert.All(report.Content.Regions, region => { Assert.Null(region.Sha256); Assert.Equal(0, region.HashBytes); });
        Assert.Contains("content:region-hash-budget", report.Content.Issues);
        Assert.DoesNotContain(ReportComparison.Compare(report, report), e => e.Basis == "whole-pe-sections");
    }

    [Fact]
    public void PeRegionProofComparesEntireValidatedSectionRanges()
    {
        var bytes = File.ReadAllBytes(typeof(FileInspector).Assembly.Location);
        var report = Analyze(bytes, "assembly.dll");
        Assert.Contains(report.Content.Regions, r => r.Kind == "pe-section" && r.Sha256 != null);
        foreach (var region in report.Content.Regions.Where(r => r.Sha256 != null))
        {
            Assert.InRange(region.ByteOffset + region.ByteLength, 0, bytes.LongLength);
            Assert.Equal(region.ByteLength, region.HashBytes);
            var content = new byte[checked((int)region.ByteLength)]; Buffer.BlockCopy(bytes, (int)region.ByteOffset, content, 0, content.Length);
            Assert.Equal(FileInspector.ReportHash(content), region.Sha256);
        }
        var evidence = Assert.Single(ReportComparison.Compare(report, report), e => e.Basis == "whole-pe-sections");
        Assert.Equal(1, evidence.Score); Assert.Equal(evidence.ComparedLeft, evidence.Matches.Count);
    }

    [Fact]
    public void UnknownSchemasFailClearlyForBothComparisonApis()
    {
        var first = new InspectionReport();
        var second = new InspectionReport { SchemaVersion = 99 };
        Assert.Throws<NotSupportedException>(() => ReportComparison.Compare(first, second));
        Assert.Throws<NotSupportedException>(() => ReportSimilarity.Compare(first, second));
    }

    [Theory]
    [InlineData("zip")]
    [InlineData("tar")]
    public void TruncatedRegularMemberNameCannotChangeItsComparisonKind(string format)
    {
        var bytes = Encoding.UTF8.GetBytes("Inert member evidence");
        var archive = format == "zip" ? ZipBytes(("folder/report.txt", bytes), ("folder/", Array.Empty<byte>())) : TarBytes(("folder/report.txt", bytes), ("folder/", Array.Empty<byte>()));
        var report = Analyze(archive, "files." + format, new InspectionReportOptions { MaxEntryNameCharacters = 7 });
        Assert.Equal("folder/", report.Content.Entries[0].Name); Assert.True(report.Content.Entries[0].NameTruncated);
        Assert.NotNull(report.Content.Entries[0].Sha256); Assert.Null(report.Content.Entries[1].Sha256);
        var compared = Assert.Single(ReportComparison.Compare(report, report), e => e.Basis == "whole-archive-members");
        Assert.Equal(1, compared.ComparedLeft); Assert.Equal(1, compared.ComparedRight); Assert.Equal(1, compared.Score);
        Assert.Equal(0, Assert.Single(compared.Matches).LeftOrdinal);
    }

#if NET8_0_OR_GREATER
    [Fact]
    public void ActualLegacyJsonRecoversMemberIdentityFromInventoryOrder()
    {
        var json = "{\"SchemaVersion\":1,\"Content\":{\"Entries\":[{\"Name\":\"same.txt\",\"SizeBytes\":1,\"Sha256\":\"HASH\"},{\"Name\":\"same.txt\",\"SizeBytes\":1,\"Sha256\":\"HASH\"}]}}".Replace("HASH", FileInspector.ReportHash(new byte[] { 1 }));
        var legacy = System.Text.Json.JsonSerializer.Deserialize<InspectionReport>(json)!;
        Assert.All(legacy.Content.Entries, e => Assert.Equal(0, e.Ordinal));
        var comparison = Assert.Single(ReportComparison.Compare(legacy, legacy), e => e.Basis == "whole-archive-members");
        Assert.Equal(new[] { 0, 1 }, comparison.Matches.Select(m => m.LeftOrdinal));
        Assert.Equal(new[] { 0, 1 }, comparison.Matches.Select(m => m.RightOrdinal));
    }
#endif

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void AllOverlappingPeSectionsAreExcludedRegardlessOfOrderOrContainment(bool reversed, bool contained)
    {
        var bytes = File.ReadAllBytes(typeof(FileInspector).Assembly.Location);
        var peOffset = BitConverter.ToInt32(bytes, 60);
        var sections = peOffset + 24 + BitConverter.ToUInt16(bytes, peOffset + 20);
        var firstOffset = BitConverter.ToUInt32(bytes, sections + 20);
        var firstLength = BitConverter.ToUInt32(bytes, sections + 16);
        Assert.True(firstLength >= 512);
        Set32(bytes, sections + 40 + 20, firstOffset + 128);
        if (contained) Set32(bytes, sections + 40 + 16, 128);
        if (reversed)
            for (int i = 0; i < 40; i++) { var value = bytes[sections + i]; bytes[sections + i] = bytes[sections + 40 + i]; bytes[sections + 40 + i] = value; }
        var report = Analyze(bytes, "overlap.dll");
        Assert.True(report.Content.Regions.Count >= 2);
        foreach (var region in report.Content.Regions.Take(2))
        {
            Assert.Null(region.Sha256); Assert.Equal(0, region.HashBytes);
            Assert.Contains("content:region-overlap", region.Issues);
        }
        Assert.Equal(InspectionOutcome.Partial, report.Outcome);
    }

    private static void Set32(byte[] data, int offset, uint value) => BitConverter.GetBytes(value).CopyTo(data, offset);

    private static byte[] TarBytes(params (string Name, byte[] Content)[] members)
    {
        using var output = new MemoryStream();
        foreach (var member in members)
        {
            var header = new byte[512]; Encoding.ASCII.GetBytes(member.Name).CopyTo(header, 0);
            Encoding.ASCII.GetBytes(Convert.ToString(member.Content.Length, 8).PadLeft(11, '0')).CopyTo(header, 124);
            header[156] = member.Name.EndsWith("/", StringComparison.Ordinal) ? (byte)'5' : (byte)'0';
            Encoding.ASCII.GetBytes("ustar").CopyTo(header, 257); TestHelpers.SealTarHeader(header);
            output.Write(header, 0, header.Length); output.Write(member.Content, 0, member.Content.Length);
            var padding = new byte[(512 - member.Content.Length % 512) % 512]; output.Write(padding, 0, padding.Length);
        }
        output.Write(new byte[1024], 0, 1024); return output.ToArray();
    }

    private static InspectionReport Archive(params (string Name, string Text)[] members) => Analyze(ZipBytes(members.Select(m => (m.Name, Encoding.UTF8.GetBytes(m.Text))).ToArray()), "archive.zip");
    private static InspectionReport Analyze(byte[] bytes, string name, InspectionReportOptions? options = null)
    { using var stream = new MemoryStream(bytes); return FileInspector.AnalyzeReport(stream, name, options); }
    private static byte[] ZipBytes(params (string Name, byte[] Content)[] members)
    {
        using var source = new MemoryStream();
        using (var zip = new ZipArchive(source, ZipArchiveMode.Create, true))
            foreach (var member in members) { using var output = zip.CreateEntry(member.Name, CompressionLevel.NoCompression).Open(); output.Write(member.Content, 0, member.Content.Length); }
        return source.ToArray();
    }
}
