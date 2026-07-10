using System.IO.Compression;
using Xunit;

namespace FileInspectorX.Tests;

[Collection(nameof(ArchiveBudgetSettingsCollection))]
public sealed class ArchiveBudgetTests
{
    [Fact]
    public void Analyze_HighExpansionEntry_IsReportedAsPartial_WithoutExpandingIt()
    {
        var path = Path.Combine(Path.GetTempPath(), "archive-budget-" + Guid.NewGuid().ToString("N") + ".docx");
        try
        {
            using (var file = File.Create(path))
            using (var archive = new ZipArchive(file, ZipArchiveMode.Create))
            {
                WriteEntry(archive, "[Content_Types].xml", "<Types />");
                var entry = archive.CreateEntry("word/document.xml", CompressionLevel.Optimal);
                using var stream = entry.Open();
                var block = new byte[64 * 1024];
                for (var index = 0; index < block.Length; index++) block[index] = (byte)'A';
                for (var index = 0; index < 128; index++)
                    stream.Write(block, 0, block.Length);
            }

            var analysis = FileInspector.Analyze(path);

            Assert.False(analysis.AnalysisComplete);
            Assert.Contains("archive:compression-ratio-limit", analysis.AnalysisIssues!);
            Assert.Contains("archive:compression-ratio-limit", analysis.SecurityFindings!);
        }
        finally
        {
            TestHelpers.SafeDelete(path);
        }
    }

    [Fact]
    public void Analyze_EntryCountAboveLimit_StopsBeforeMaterializingEntries()
    {
        var original = Settings.ArchiveMaxEntries;
        var path = Path.Combine(Path.GetTempPath(), "archive-entry-limit-" + Guid.NewGuid().ToString("N") + ".zip");
        try
        {
            Settings.ArchiveMaxEntries = 2;
            using (var file = File.Create(path))
            using (var archive = new ZipArchive(file, ZipArchiveMode.Create))
            {
                WriteEntry(archive, "one.txt", "one");
                WriteEntry(archive, "two.txt", "two");
                WriteEntry(archive, "three.txt", "three");
            }

            var analysis = FileInspector.Analyze(path);

            Assert.False(analysis.AnalysisComplete);
            Assert.Equal(3, analysis.ContainerEntryCount);
            Assert.Contains("archive:entry-count-limit", analysis.AnalysisIssues!);
        }
        finally
        {
            Settings.ArchiveMaxEntries = original;
            TestHelpers.SafeDelete(path);
        }
    }

    [Fact]
    public void CheckCentralDirectory_IgnoresDecoyEocdInsideArchiveComment()
    {
        using var stream = new MemoryStream();
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            WriteEntry(archive, "one.txt", "one");
            WriteEntry(archive, "two.txt", "two");
            WriteEntry(archive, "three.txt", "three");
        }

        var bytes = stream.ToArray();
        var eocdOffset = FindSignatureFromEnd(bytes, 0x06054b50);
        Assert.True(eocdOffset >= 0);

        const ushort archiveCommentLength = 30;
        WriteUInt16(bytes, eocdOffset + 20, archiveCommentLength);
        stream.SetLength(0);
        stream.Write(bytes, 0, bytes.Length);

        var comment = new byte[archiveCommentLength];
        WriteUInt32(comment, 0, 0x06054b50);
        WriteUInt16(comment, 8, 1);
        WriteUInt16(comment, 10, 1);
        WriteUInt32(comment, 12, 46);
        WriteUInt16(comment, 20, 8);
        stream.Write(comment, 0, comment.Length);
        stream.Position = 0;

        var budget = new ArchiveInspectionBudget(
            maxEntries: 2,
            maxCentralDirectoryBytes: 1024 * 1024,
            maxEntryReadBytes: 1024,
            maxTotalReadBytes: 4096,
            maxCompressionRatio: 100);

        Assert.False(budget.CheckCentralDirectory(stream, out var declaredEntryCount));
        Assert.Equal(3, declaredEntryCount);
        Assert.Contains("archive:entry-count-limit", budget.Issues);
    }

    private static void WriteEntry(ZipArchive archive, string name, string content)
    {
        var entry = archive.CreateEntry(name, CompressionLevel.Optimal);
        using var writer = new StreamWriter(entry.Open());
        writer.Write(content);
    }

    private static int FindSignatureFromEnd(byte[] bytes, uint signature)
    {
        for (var index = bytes.Length - 4; index >= 0; index--)
        {
            var value = (uint)(bytes[index] |
                (bytes[index + 1] << 8) |
                (bytes[index + 2] << 16) |
                (bytes[index + 3] << 24));
            if (value == signature) return index;
        }
        return -1;
    }

    private static void WriteUInt16(byte[] bytes, int offset, ushort value)
    {
        bytes[offset] = (byte)value;
        bytes[offset + 1] = (byte)(value >> 8);
    }

    private static void WriteUInt32(byte[] bytes, int offset, uint value)
    {
        bytes[offset] = (byte)value;
        bytes[offset + 1] = (byte)(value >> 8);
        bytes[offset + 2] = (byte)(value >> 16);
        bytes[offset + 3] = (byte)(value >> 24);
    }
}

[CollectionDefinition(nameof(ArchiveBudgetSettingsCollection), DisableParallelization = true)]
public sealed class ArchiveBudgetSettingsCollection
{
}
