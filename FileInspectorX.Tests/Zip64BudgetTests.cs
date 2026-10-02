using System.IO.Compression;
using System.Threading;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class Zip64BudgetTests
{
    private static ArchiveInspectionBudget Budget(int entries = 10, long directoryBytes = 4096) =>
        new(entries, directoryBytes, 1024, 4096, 100);

    [Theory]
    [InlineData("all")]
    [InlineData("count")]
    [InlineData("offset")]
    [InlineData("size")]
    [InlineData("none")]
    public void ValidSmallZip64UsesFullMetadataAndPreservesBorrowedStream(string sentinel)
    {
        var bytes = ZipTestArchive.WithZip64Footer(ZipTestArchive.Create(("one.txt", "one"), ("two.txt", "two")), sentinel);
        using var stream = new FragmentedStream(bytes);
        stream.Position = 7;
        var budget = Budget();
        Assert.True(budget.CheckCentralDirectory(stream, out var count), string.Join(",", budget.Issues));
        Assert.Equal(2, count);
        Assert.Equal(7, stream.Position);
        Assert.True(stream.CanRead);
        stream.Position = 0;
        using var archive = new ZipArchive(stream, ZipArchiveMode.Read, true);
        Assert.Equal(2, archive.Entries.Count);
        using var reader = new StreamReader(archive.GetEntry("two.txt")!.Open());
        Assert.Equal("two", reader.ReadToEnd());
    }

    [Fact]
    public void Zip64ExtensibleSectorAndEmptyDirectoryAreAcceptedWithoutAllocatingDeclaredSize()
    {
        // A valid special-purpose sector: two-byte ID, four-byte payload size, payload.
        var extension = new byte[] { 0x99, 0x99, 2, 0, 0, 0, 1, 2 };
        using var stream = new MemoryStream(ZipTestArchive.WithZip64Footer(ZipTestArchive.Create(), extension: extension));
        Assert.True(Budget().CheckCentralDirectory(stream, out var count));
        Assert.Equal(0, count);
        using var archive = new ZipArchive(stream, ZipArchiveMode.Read, true);
        Assert.Empty(archive.Entries);
    }

    [Fact]
    public void RealWriterZip64CountIsReportedWithoutTruncatingToTheClassicSentinel()
    {
        using var stream = new MemoryStream();
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, true))
        {
            for (int index = 0; index < 65_536; index++) archive.CreateEntry(index.ToString("D5") + ".txt");
        }
        var budget = Budget();
        Assert.False(budget.CheckCentralDirectory(stream, out var count));
        Assert.Equal(65_536, count);
        Assert.Contains("archive:entry-count-limit", budget.Issues);
        stream.Position = 0;
        using var verified = new ZipArchive(stream, ZipArchiveMode.Read, true);
        Assert.Equal(65_536, verified.Entries.Count);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PublicAnalysisInspectsValidZip64AndReportsBudgetRejectionAsPartial(bool limited)
    {
        var bytes = ZipTestArchive.WithZip64Footer(ZipTestArchive.Create(("one.txt", "one"), ("../script.ps1", "Write-Output 'hello'")));
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".zip");
        try
        {
            File.WriteAllBytes(path, bytes);
            var options = new FileInspector.DetectionOptions
            {
                Settings = InspectionSettings.CaptureDefaults() with { ArchiveMaxEntries = limited ? 1 : 10 },
                IncludePermissions = false, IncludeAuthenticode = false, IncludeInstaller = false,
                IncludeReferences = false, IncludeAssessment = true
            };
            var analysis = FileInspector.Analyze(path, options);
            Assert.Equal(2, analysis.ContainerEntryCount);
            Assert.Equal(!limited, analysis.AnalysisComplete);
            if (limited)
            {
                Assert.Contains("archive:entry-count-limit", analysis.AnalysisIssues!);
                Assert.Equal("Defer", analysis.Assessment!.Decision.ToString());
            }
            else Assert.True(analysis.Flags.HasFlag(ContentFlags.ArchiveHasPathTraversal));
        }
        finally { TestHelpers.SafeDelete(path); }
    }

    [Theory]
    [InlineData("count", "archive:entry-count-limit")]
    [InlineData("huge-count", "archive:entry-count-limit")]
    [InlineData("size", "archive:directory-size-limit")]
    public void Zip64LimitsUseWideValuesBeforeWalkingEntries(string field, string issue)
    {
        var bytes = ZipTestArchive.WithZip64Footer(ZipTestArchive.Create(("one.txt", "one")));
        var record = bytes.Length - 98;
        if (field == "size") ZipTestArchive.Write64(bytes, record + 40, ulong.MaxValue);
        else
        {
            ulong count = field == "count" ? 11UL : (ulong)int.MaxValue + 1;
            ZipTestArchive.Write64(bytes, record + 24, count);
            ZipTestArchive.Write64(bytes, record + 32, count);
        }
        using var stream = new FragmentedStream(bytes);
        stream.Position = 3;
        var budget = Budget();
        Assert.False(budget.CheckCentralDirectory(stream, out var declared));
        Assert.Equal(field == "count" ? 11 : field == "size" ? 1 : (int?)null, declared);
        Assert.Contains(issue, budget.Issues);
        Assert.Equal(3, stream.Position);
        // The bounded tail plus fixed locator/record; rejected metadata never
        // causes a second pass through central-directory entries.
        Assert.True(stream.BytesRead <= bytes.Length + 76);
    }

    [Theory]
    [InlineData("missing-locator")]
    [InlineData("locator-offset")]
    [InlineData("short-record")]
    [InlineData("oversized-record")]
    [InlineData("directory-offset")]
    [InlineData("classic-conflict")]
    [InlineData("entry-header")]
    public void MalformedZip64IsRejectedWithoutLosingPosition(string fault)
    {
        var bytes = ZipTestArchive.WithZip64Footer(ZipTestArchive.Create(("one.txt", "one")));
        var record = bytes.Length - 98;
        switch (fault)
        {
            case "missing-locator": bytes[bytes.Length - 42] = 0; break;
            case "locator-offset": ZipTestArchive.Write64(bytes, bytes.Length - 34, ulong.MaxValue); break;
            case "short-record": ZipTestArchive.Write64(bytes, record + 4, 43); break;
            case "oversized-record": ZipTestArchive.Write64(bytes, record + 4, ulong.MaxValue); break;
            case "directory-offset": ZipTestArchive.Write64(bytes, record + 48, ulong.MaxValue); break;
            case "classic-conflict": ZipTestArchive.Write32(bytes, bytes.Length - 10, 1); break;
            case "entry-header": bytes[record - 46 - "one.txt".Length] = 0; break;
        }
        using var stream = new FragmentedStream(bytes);
        stream.Position = 5;
        var budget = Budget();
        Assert.False(budget.CheckCentralDirectory(stream, out _));
        Assert.Contains("archive:central-directory-invalid", budget.Issues);
        Assert.Equal(5, stream.Position);
    }

    [Theory]
    [InlineData("locator-disk")]
    [InlineData("record-disk")]
    [InlineData("split-count")]
    public void Zip64SplitArchivesRemainUnsupported(string fault)
    {
        var bytes = ZipTestArchive.WithZip64Footer(ZipTestArchive.Create(("one.txt", "one")));
        if (fault == "locator-disk") ZipTestArchive.Write32(bytes, bytes.Length - 26, 2);
        else if (fault == "record-disk") ZipTestArchive.Write32(bytes, bytes.Length - 98 + 16, 1);
        else ZipTestArchive.Write64(bytes, bytes.Length - 98 + 24, 2);
        using var stream = new MemoryStream(bytes);
        var budget = Budget();
        Assert.False(budget.CheckCentralDirectory(stream, out _));
        Assert.Contains("archive:multi-disk-unsupported", budget.Issues);
    }

    [Fact]
    public void ClassicDirectoryOffsetMustMatchTheDirectoryThatWillBeMaterialized()
    {
        var bytes = ZipTestArchive.Create(("one.txt", "one"));
        ZipTestArchive.Write32(bytes, bytes.Length - 6, 0);
        using var stream = new MemoryStream(bytes);
        var budget = Budget();
        Assert.False(budget.CheckCentralDirectory(stream, out _));
        Assert.Contains("archive:central-directory-invalid", budget.Issues);
    }

    [Fact]
    public void MaximumArchiveCommentDoesNotHideTheZip64LocatorOutsideTheTailBuffer()
    {
        var bytes = ZipTestArchive.WithZip64Footer(ZipTestArchive.Create(("one.txt", "one")));
        bytes[bytes.Length - 2] = 255;
        bytes[bytes.Length - 1] = 255;
        using var stream = new MemoryStream();
        stream.Write(bytes, 0, bytes.Length);
        var comment = Enumerable.Repeat((byte)'a', ushort.MaxValue).ToArray();
        stream.Write(comment, 0, comment.Length);
        stream.Position = 7;
        Assert.True(Budget().CheckCentralDirectory(stream, out var count));
        Assert.Equal(1, count);
        Assert.Equal(7, stream.Position);
        stream.Position = 0;
        using var archive = new ZipArchive(stream, ZipArchiveMode.Read, true);
        Assert.Single(archive.Entries);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void DirectoryDigitalSignatureIsPreservedForClassicAndZip64(bool zip64)
    {
        var original = ZipTestArchive.Create(("one.txt", "one"));
        var end = original.Length - 22;
        using var stream = new MemoryStream();
        stream.Write(original, 0, end);
        var signature = new byte[] { 0x50, 0x4b, 0x05, 0x05, 2, 0, 1, 2 };
        stream.Write(signature, 0, signature.Length);
        using var reader = new BinaryReader(new MemoryStream(original));
        reader.BaseStream.Position = end + 12;
        ZipTestArchive.Write32(original, end + 12, reader.ReadUInt32() + (uint)signature.Length);
        stream.Write(original, end, 22);
        var bytes = stream.ToArray();
        if (zip64) bytes = ZipTestArchive.WithZip64Footer(bytes);
        using var input = new MemoryStream(bytes);
        Assert.True(Budget().CheckCentralDirectory(input, out var count));
        Assert.Equal(1, count);
        using var archive = new ZipArchive(input, ZipArchiveMode.Read, true);
        Assert.Single(archive.Entries);
    }

    [Fact]
    public void ACommentDecoyCannotValidateOneDirectoryAndMaterializeAnother()
    {
        var bytes = ZipTestArchive.Create(("one.txt", "one"));
        bytes[bytes.Length - 2] = 30;
        using var stream = new MemoryStream();
        stream.Write(bytes, 0, bytes.Length);
        var comment = new byte[30];
        ZipTestArchive.Write32(comment, 0, 0x06054b50);
        comment[8] = comment[10] = 1;
        ZipTestArchive.Write32(comment, 12, 46);
        comment[20] = 8;
        stream.Write(comment, 0, comment.Length);
        var budget = Budget();
        Assert.False(budget.CheckCentralDirectory(stream, out _));
        Assert.Contains("archive:central-directory-invalid", budget.Issues);
    }

    [Fact]
    public void CancellationDuringFragmentedPreflightRestoresPosition()
    {
        using var cancellation = new CancellationTokenSource();
        var bytes = ZipTestArchive.WithZip64Footer(ZipTestArchive.Create(("one.txt", "one")));
        using var stream = new FragmentedStream(bytes, cancellation);
        stream.Position = 9;
        var operation = InspectionOperation.Begin(new() { CancellationToken = cancellation.Token });
        try
        {
            Assert.Throws<OperationCanceledException>(() => Budget().CheckCentralDirectory(stream, out _));
            Assert.Equal(9, stream.Position);
        }
        finally
        {
            try { operation.Dispose(); }
            catch (OperationCanceledException) { }
        }
    }

    private sealed class FragmentedStream : MemoryStream
    {
        private readonly CancellationTokenSource? _cancellation;
        internal int BytesRead { get; private set; }
        internal FragmentedStream(byte[] bytes, CancellationTokenSource? cancellation = null) : base(bytes) => _cancellation = cancellation;
        public override int Read(byte[] buffer, int offset, int count)
        {
            var read = base.Read(buffer, offset, Math.Min(count, 3));
            BytesRead += read;
            if (BytesRead >= 6) _cancellation?.Cancel();
            return read;
        }
    }
}
