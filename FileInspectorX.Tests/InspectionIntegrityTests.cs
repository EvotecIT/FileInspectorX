using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

[Collection(nameof(ArchiveBudgetSettingsCollection))]
public sealed class InspectionIntegrityTests
{
    private static FileInspector.DetectionOptions Options() => new()
    {
        IncludePermissions = false, IncludeAuthenticode = false, IncludeReferences = false,
        IncludeInstaller = false, IncludeAssessment = true
    };

    [Theory]
    [InlineData(32)]
    [InlineData(12000)]
    public void HashIncludesCompleteMemoryAndForwardOnlyContent(int length)
    {
        var bytes = Encoding.UTF8.GetBytes("{\"key\":\"" + new string('a', length) + "\"}");
        using var sha = SHA256.Create();
        string expected = BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant();
        var options = new FileInspector.DetectionOptions { ComputeSha256 = true, MagicHeaderBytes = 8 };
        Assert.Equal(expected, FileInspector.Detect(bytes, options)!.Sha256Hex);
        Assert.Equal(expected, FileInspector.Detect(bytes.AsMemory(), options)!.Sha256Hex);
        Assert.Equal(expected, FileInspector.Detect(bytes.AsSpan(), options)!.Sha256Hex);
        using var input = new LimitedStream(bytes, seekable: false, maxRead: 3);
        Assert.Equal(expected, FileInspector.Detect(input, options)!.Sha256Hex);
        Assert.Equal(bytes.Length, input.BytesRead);
    }

    [Fact]
    public void ForwardOnlyOleHashIncludesRefinerSample()
    {
        var bytes = new byte[12000];
        new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 }.CopyTo(bytes, 0);
        using var sha = SHA256.Create();
        string expected = BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant();
        using var input = new LimitedStream(bytes, false, 3);
        Assert.Equal(expected, FileInspector.Detect(input, new() { ComputeSha256 = true })!.Sha256Hex);
    }

    [Theory]
    [InlineData("json", "{\"key\":123}")]
    [InlineData("xml", "<?xml version=\"1.0\"?><root />")]
    public void StructuredValidationReadsThroughShortReads(string extension, string prefix)
    {
        var bytes = Encoding.UTF8.GetBytes(prefix + new string(' ', 6000) + "X");
        using var normal = new MemoryStream(bytes);
        using var fragmented = new LimitedStream(bytes, true, 1);
        var expected = FileInspector.Detect(normal, declaredExtension: extension)!;
        var actual = FileInspector.Detect(fragmented, declaredExtension: extension)!;
        Assert.Equal("failed", expected.ValidationStatus);
        Assert.Equal(expected.ValidationStatus, actual.ValidationStatus);
        Assert.Equal(expected.Confidence, actual.Confidence);
        Assert.Equal(0, fragmented.Position);
    }

    public static IEnumerable<object[]> ZipSubtypeCorpus()
    {
        var cases = new (string Marker, string Extension, string? Guess, string Content)[]
        {
            ("word/document.xml", "docx", null, "<document />"),
            ("xl/workbook.xml", "xlsx", null, "<workbook />"),
            ("ppt/presentation.xml", "pptx", null, "<presentation />"),
            ("mimetype", "zip", "epub", "application/epub+zip"),
            ("mimetype", "zip", "odt", "application/vnd.oasis.opendocument.text"),
            ("mimetype", "zip", "ods", "application/vnd.oasis.opendocument.spreadsheet"),
            ("mimetype", "zip", "odp", "application/vnd.oasis.opendocument.presentation"),
            ("mimetype", "zip", "odg", "application/vnd.oasis.opendocument.graphics"),
            ("classes.dex", "zip", "apk", "dex marker"),
            ("AndroidManifest.xml", "zip", "apk", "<manifest />"),
            ("META-INF/MANIFEST.MF", "zip", "jar", "Manifest-Version: 1.0")
        };
        foreach (var item in cases)
        foreach (bool zip64 in new[] { false, true })
            yield return new object[] { item.Marker, item.Extension, item.Guess!, item.Content, zip64 };
    }

    [Theory]
    [MemberData(nameof(ZipSubtypeCorpus))]
    public void ZipSubtypesAgreeAcrossCompleteInputOverloads(string marker, string extension, string? guessed, string content, bool zip64)
    {
        // Put the identifying entry beyond the normal header sample, so a
        // header-only implementation cannot accidentally satisfy this corpus.
        var entries = new List<(string Name, string Content)> { ("padding.bin", new string('x', 32 * 1024)) };
        if (guessed == null) entries.Add(("[Content_Types].xml", "<Types />"));
        entries.Add((marker, content));
        var bytes = ZipTestArchive.Create(entries.ToArray());
        if (zip64) bytes = ZipTestArchive.WithZip64Footer(bytes);
        var framed = new byte[bytes.Length + 19];
        Buffer.BlockCopy(bytes, 0, framed, 11, bytes.Length);
        using var sha = SHA256.Create();
        string expectedHash = BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant();
        var options = new FileInspector.DetectionOptions { ComputeSha256 = true };
        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, bytes);
            using var stream = new MemoryStream(bytes);
            using var fragmented = new LimitedStream(bytes, true, 3);
            stream.Position = 7;
            fragmented.Position = 9;
            var results = new[]
            {
                FileInspector.Detect(path, options), FileInspector.Detect(stream, options),
                FileInspector.Detect(fragmented, options), FileInspector.Detect(bytes, options),
                FileInspector.Detect(framed.AsMemory(11, bytes.Length), options),
                FileInspector.Detect(framed.AsSpan(11, bytes.Length), options)
            };
            Assert.All(results, result =>
            {
                Assert.Equal(extension, result!.Extension);
                Assert.Equal(guessed, result.GuessedExtension);
                Assert.Equal(expectedHash, result.Sha256Hex);
            });
            Assert.Equal(7, stream.Position);
            Assert.Equal(9, fragmented.Position);
            Assert.True(stream.CanRead);
            Assert.True(fragmented.CanRead);
        }
        finally { TestHelpers.SafeDelete(path); }
    }

    [Fact]
    public void MissingInputIsIncompleteAndAssessmentDefers()
    {
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        var analysis = FileInspector.Analyze(path, Options());
        Assert.False(analysis.AnalysisComplete);
        Assert.Contains("input:read-failed", analysis.AnalysisIssues!);
        Assert.Equal("Defer", analysis.Assessment!.Decision.ToString());
        Assert.Equal("Defer", FileInspector.Assess(analysis).Decision.ToString());
        var detectOnly = FileInspector.Inspect(path, new() { DetectOnly = true });
        Assert.False(detectOnly.AnalysisComplete);
        Assert.Contains("input:read-failed", detectOnly.AnalysisIssues!);
        File.WriteAllBytes(path, new byte[] { 0, 1, 2, 3 });
        try { Assert.True(FileInspector.Analyze(path, Options()).AnalysisComplete); }
        finally { TestHelpers.SafeDelete(path); }
    }

    [Fact]
    public void DiscPathDetectionHonorsHashAndHeaderOptions()
    {
        var bytes = new byte[0x9001 + 10];
        Encoding.ASCII.GetBytes("CD001").CopyTo(bytes, 0x8001);
        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, bytes);
            using var sha = SHA256.Create();
            string expected = BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant();
            var result = FileInspector.Detect(path, new() { ComputeSha256 = true, MagicHeaderBytes = 8 })!;
            Assert.Equal("iso", result.Extension);
            Assert.Equal(expected, result.Sha256Hex);
            Assert.Equal("0000000000000000", result.MagicHeaderHex);
            Assert.True(result.BytesInspected > 0);
        }
        finally { TestHelpers.SafeDelete(path); }
    }

    [Fact]
    public void TarMissingEndMarkerIsPartial()
    {
        string path = Path.GetTempFileName();
        try
        {
            using (var output = File.Create(path)) WriteTarHeader(output, "data.txt");
            var result = FileInspector.Analyze(path, Options());
            Assert.False(result.AnalysisComplete);
            Assert.Contains("tar:truncated-header", result.AnalysisIssues!);
            Assert.Equal("Defer", result.Assessment!.Decision.ToString());
        }
        finally { TestHelpers.SafeDelete(path); }
    }

    [Theory]
    [InlineData(0, false)]
    [InlineData(100, false)]
    [InlineData(512, false)]
    [InlineData(512, true)]
    public void TarRequiresTwoCompleteZeroEndBlocks(int secondBlockLength, bool zero)
    {
        string path = Path.GetTempFileName();
        try
        {
            using (var output = File.Create(path))
            {
                WriteTarHeader(output, "data.txt");
                output.Write(new byte[512], 0, 512);
                var second = new byte[secondBlockLength];
                if (!zero && second.Length > 0) second[second.Length - 1] = 1;
                output.Write(second, 0, second.Length);
            }
            var result = FileInspector.Analyze(path, Options());
            Assert.Equal(zero, result.AnalysisComplete);
            if (!zero)
            {
                Assert.Contains("tar:invalid-end-marker", result.AnalysisIssues!);
                Assert.Equal("Defer", result.Assessment!.Decision.ToString());
            }
        }
        finally { TestHelpers.SafeDelete(path); }
    }

    [Fact]
    public void ZipSubtypeDetectionAcceptsStackBackedSpans()
    {
        using var output = new MemoryStream();
        using (var archive = new ZipArchive(output, ZipArchiveMode.Create, true))
        {
            archive.CreateEntry("[Content_Types].xml");
            archive.CreateEntry("word/document.xml");
        }
        Span<byte> bytes = stackalloc byte[(int)output.Length];
        output.ToArray().AsSpan().CopyTo(bytes);
        var result = FileInspector.Detect((ReadOnlySpan<byte>)bytes);
        Assert.Equal("docx", result!.Extension);
    }

#if NET8_0_OR_GREATER
    [Fact]
    public void ZipSpanRefinementAllocationDoesNotScaleWithPayload()
    {
        using var output = new MemoryStream();
        using (var archive = new ZipArchive(output, ZipArchiveMode.Create, true))
        {
            archive.CreateEntry("[Content_Types].xml");
            archive.CreateEntry("word/document.xml");
            using var payload = archive.CreateEntry("large.bin", CompressionLevel.NoCompression).Open();
            payload.Write(new byte[8 * 1024 * 1024]);
        }
        var bytes = output.ToArray();
        FileInspector.Detect(bytes.AsSpan()); // Warm the same subtype path before measuring.
        long before = GC.GetAllocatedBytesForCurrentThread();
        var result = FileInspector.Detect(bytes.AsSpan());
        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.Equal("docx", result!.Extension);
        Assert.True(allocated < 2 * 1024 * 1024, $"ZIP span refinement allocated {allocated:N0} bytes for an 8 MiB payload.");
    }
#endif

    [Theory]
    [InlineData(128, 4096, "archive:entry-read-limit")]
    [InlineData(4096, 128, "archive:total-read-limit")]
    public void TarDeepPayloadHonorsArchiveByteLimits(long entryLimit, long totalLimit, string issue)
    {
        string path = Path.GetTempFileName();
        bool deep = Settings.DeepContainerScanEnabled;
        long entryBytes = Settings.ArchiveMaxEntryReadBytes, totalBytes = Settings.ArchiveMaxTotalReadBytes;
        try
        {
            Settings.DeepContainerScanEnabled = true;
            Settings.ArchiveMaxEntryReadBytes = entryLimit;
            Settings.ArchiveMaxTotalReadBytes = totalLimit;
            using (var output = File.Create(path))
            {
                WriteTarHeader(output, "payload.exe", size: 1024);
                output.Write(new byte[1024], 0, 1024);
                output.Write(new byte[1024], 0, 1024);
            }
            var result = FileInspector.Analyze(path, Options());
            Assert.False(result.AnalysisComplete);
            Assert.Contains(issue, result.AnalysisIssues!);
            Assert.Equal("Defer", result.Assessment!.Decision.ToString());
            Assert.Equal(0, result.InnerExecutablesSampled ?? 0);
        }
        finally { Settings.DeepContainerScanEnabled = deep; Settings.ArchiveMaxEntryReadBytes = entryBytes; Settings.ArchiveMaxTotalReadBytes = totalBytes; TestHelpers.SafeDelete(path); }
    }

    [Fact]
    public void TarQuickSamplesShareTotalReadBudget()
    {
        string path = Path.GetTempFileName();
        long original = Settings.ArchiveMaxTotalReadBytes;
        try
        {
            Settings.ArchiveMaxTotalReadBytes = 128;
            using (var output = File.Create(path))
            {
                for (int i = 0; i < 3; i++) { WriteTarHeader(output, $"file{i}.bin", size: 64); output.Write(new byte[512], 0, 512); }
                output.Write(new byte[1024], 0, 1024);
            }
            var result = FileInspector.Analyze(path, Options());
            Assert.Equal(3, result.ContainerEntryCount);
            Assert.False(result.AnalysisComplete);
            Assert.Contains("archive:total-read-limit", result.AnalysisIssues!);
            Assert.Equal("Defer", result.Assessment!.Decision.ToString());
        }
        finally { Settings.ArchiveMaxTotalReadBytes = original; TestHelpers.SafeDelete(path); }
    }

    [Theory]
    [InlineData("safe/../../escape.txt", "", "")]
    [InlineData("escape.txt", "safe/../..", "")]
    [InlineData("link", "", "safe/../../escape.txt")]
    public void TarInspectsFullUstarNamesAndLinkTargets(string name, string prefix, string link)
    {
        string path = Path.GetTempFileName();
        try
        {
            using (var output = File.Create(path)) { WriteTarHeader(output, name, prefix, link); output.Write(new byte[1024], 0, 1024); }
            var result = FileInspector.Analyze(path, Options());
            Assert.True(result.Flags.HasFlag(ContentFlags.ArchiveHasPathTraversal));
            Assert.True(result.AnalysisComplete);
            if (link.Length > 0) Assert.True(result.Flags.HasFlag(ContentFlags.ArchiveHasSymlinks));
        }
        finally { TestHelpers.SafeDelete(path); }
    }

    [Fact]
    public void TarVisitsBeyondFormerCapAndMarksBudgetExhaustionPartial()
    {
        string path = Path.GetTempFileName();
        int original = Settings.ArchiveMaxEntries;
        try
        {
            using (var output = File.Create(path))
            {
                for (int i = 0; i < 512; i++) WriteTarHeader(output, $"file{i}.txt");
                WriteTarHeader(output, "last.ps1");
                output.Write(new byte[1024], 0, 1024);
            }
            var full = FileInspector.Analyze(path, Options());
            Assert.Equal(513, full.ContainerEntryCount);
            Assert.True(full.AnalysisComplete);
            Assert.True(full.Flags.HasFlag(ContentFlags.ContainerContainsScripts));
            Settings.ArchiveMaxEntries = 512;
            var partial = FileInspector.Analyze(path, Options());
            Assert.False(partial.AnalysisComplete);
            Assert.Contains("archive:entry-count-limit", partial.AnalysisIssues!);
            Assert.Equal("Defer", partial.Assessment!.Decision.ToString());
        }
        finally { Settings.ArchiveMaxEntries = original; TestHelpers.SafeDelete(path); }
    }

#if NET8_0_OR_GREATER
    [Fact]
    public void TarGlobalVendorAttributesDoNotChangeEffectiveEntryNames()
    {
        string path = Path.GetTempFileName();
        try
        {
            var attributes = Enumerable.Range(0, 5000).Select(i => new KeyValuePair<string, string>($"VENDOR.attribute{i}", "value"));
            using (var output = File.Create(path))
            using (var writer = new System.Formats.Tar.TarWriter(output, System.Formats.Tar.TarEntryFormat.Pax))
            {
                writer.WriteEntry(new System.Formats.Tar.PaxGlobalExtendedAttributesTarEntry(attributes));
                for (int i = 0; i < 300; i++) writer.WriteEntry(new System.Formats.Tar.PaxTarEntry(System.Formats.Tar.TarEntryType.RegularFile, $"file{i}.txt"));
                writer.WriteEntry(new System.Formats.Tar.PaxTarEntry(System.Formats.Tar.TarEntryType.RegularFile, "last.ps1"));
            }
            var result = FileInspector.Analyze(path, Options());
            Assert.True(result.AnalysisComplete);
            Assert.Equal(301, result.ContainerEntryCount);
            Assert.True(result.Flags.HasFlag(ContentFlags.ContainerContainsScripts));
            Assert.Contains("txt", result.ContainerTopExtensions!);
        }
        finally { TestHelpers.SafeDelete(path); }
    }

    [Theory]
    [InlineData(System.Formats.Tar.TarEntryFormat.Pax)]
    [InlineData(System.Formats.Tar.TarEntryFormat.Gnu)]
    public void TarUsesExtendedNames(System.Formats.Tar.TarEntryFormat format)
    {
        string path = Path.GetTempFileName();
        try
        {
            using (var output = File.Create(path))
            using (var writer = new System.Formats.Tar.TarWriter(output, format))
            {
                string name = new string('a', 160) + "/../../escape.ps1";
                System.Formats.Tar.TarEntry entry = format == System.Formats.Tar.TarEntryFormat.Pax
                    ? new System.Formats.Tar.PaxTarEntry(System.Formats.Tar.TarEntryType.RegularFile, name)
                    : new System.Formats.Tar.GnuTarEntry(System.Formats.Tar.TarEntryType.RegularFile, name);
                writer.WriteEntry(entry);
            }
            var result = FileInspector.Analyze(path, Options());
            Assert.True(result.Flags.HasFlag(ContentFlags.ArchiveHasPathTraversal));
            Assert.True(result.Flags.HasFlag(ContentFlags.ContainerContainsScripts));
            Assert.True(result.AnalysisComplete);
        }
        finally { TestHelpers.SafeDelete(path); }
    }
#endif

    [Fact]
    public void NonZipDoesNotReadZipVariableHeader()
    {
        using var stream = new LimitedStream(Enumerable.Repeat((byte)'a', 1024 * 1024).ToArray(), true, int.MaxValue);
        Assert.False(Signatures.TryMatchZip(stream, out _));
        Assert.Equal(34, stream.BytesRead);
    }

    private static void WriteTarHeader(Stream output, string name, string prefix = "", string link = "", int size = 0)
    {
        var header = new byte[512];
        Encoding.ASCII.GetBytes(name).CopyTo(header, 0);
        Encoding.ASCII.GetBytes(Convert.ToString(size, 8).PadLeft(11, '0')).CopyTo(header, 124);
        Encoding.ASCII.GetBytes("ustar").CopyTo(header, 257);
        Encoding.ASCII.GetBytes(prefix).CopyTo(header, 345);
        if (link.Length > 0) { header[156] = (byte)'2'; Encoding.ASCII.GetBytes(link).CopyTo(header, 157); }
        TestHelpers.SealTarHeader(header);
        output.Write(header, 0, header.Length);
    }

    private sealed class LimitedStream : Stream
    {
        private readonly MemoryStream _inner;
        private readonly bool _seekable;
        private readonly int _maxRead;
        internal long BytesRead { get; private set; }
        internal LimitedStream(byte[] bytes, bool seekable, int maxRead) { _inner = new MemoryStream(bytes); _seekable = seekable; _maxRead = maxRead; }
        public override bool CanRead => true;
        public override bool CanSeek => _seekable;
        public override bool CanWrite => false;
        public override long Length => _seekable ? _inner.Length : throw new NotSupportedException();
        public override long Position { get => _seekable ? _inner.Position : throw new NotSupportedException(); set { if (!_seekable) throw new NotSupportedException(); _inner.Position = value; } }
        public override int Read(byte[] buffer, int offset, int count) { int read = _inner.Read(buffer, offset, Math.Min(count, _maxRead)); BytesRead += read; return read; }
        public override long Seek(long offset, SeekOrigin origin) => _seekable ? _inner.Seek(offset, origin) : throw new NotSupportedException();
        public override void Flush() { }
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) { if (disposing) _inner.Dispose(); base.Dispose(disposing); }
    }
}
