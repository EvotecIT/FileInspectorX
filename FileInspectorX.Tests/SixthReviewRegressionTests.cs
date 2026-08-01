using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class SixthReviewRegressionTests
{
    public static IEnumerable<object[]> CompleteContainers()
    {
        yield return new object[] { "parquet", Parquet() };
        yield return new object[] { "arrow", Arrow() };
        yield return new object[] { "deb", Deb() };
        yield return new object[] { "vhd", Vhd() };
        yield return new object[] { "qoi", Qoi() };
    }

    [Theory]
    [MemberData(nameof(CompleteContainers))]
    public void CompleteShortNonSeekableContainersUseWholeFileValidators(string extension, byte[] bytes)
    {
        using var stream = new NonSeekableReadStream(bytes);
        var result = FileInspector.Detect(stream);

        Assert.Equal(extension, result?.Extension);
        Assert.Equal("High", result?.Confidence);
    }

    [Fact]
    public void SampledPcapNgBlockRetainsContainerIdentityAtReducedConfidence()
    {
        var bytes = LargePcapNg();
        Assert.Equal("High", FileInspector.Detect(bytes)?.Confidence);

        using var stream = new NonSeekableReadStream(bytes);
        var sampled = FileInspector.Detect(stream);

        Assert.Equal("pcapng", sampled?.Extension);
        Assert.Equal("Medium", sampled?.Confidence);
        Assert.Equal("pcapng:section-header;sampled-block", sampled?.Reason);
    }

    [Fact]
    public void SampledPcapNgStillRequiresAValidVersion()
    {
        var bytes = LargePcapNg();
        WriteUInt16LittleEndian(bytes, 12, 2);
        using var stream = new NonSeekableReadStream(bytes);

        Assert.NotEqual("pcapng", FileInspector.Detect(stream)?.Extension);
    }

    [Fact]
    public void ElfEmNoneIsADefinedUnspecifiedMachine()
    {
        var result = FileInspector.Detect(Elf(machine: 0));

        Assert.Equal("elf", result?.Extension);
        Assert.Contains("unspecified", result?.Reason);
    }

    [Theory]
    [InlineData((ushort)1, "ico")]
    [InlineData((ushort)2, "cur")]
    public void LargeIconDirectoriesKeepApiCoverage(ushort type, string extension)
    {
        var bytes = LargeIcon(type);
        AssertParity(bytes, extension, "High");

        using var stream = new NonSeekableReadStream(bytes);
        var sampled = FileInspector.Detect(stream);
        Assert.Equal(extension, sampled?.Extension);
        Assert.Equal("Medium", sampled?.Confidence);
        Assert.Contains("sampled-length-unknown", sampled?.Reason);
    }

    [Fact]
    public void LargeIconValidatorChecksEveryDirectoryEntryAgainstFileLength()
    {
        var bytes = LargeIcon(1);
        int lastEntry = 6 + 255 * 16;
        WriteUInt32LittleEndian(bytes, lastEntry + 12, (uint)bytes.Length);

        AssertNotDetectedAcrossCompleteApis(bytes, "ico");
    }

    [Fact]
    public void SharedOutlookHeaderReportsGenericNdbIdentity()
    {
        var result = FileInspector.Detect(OutlookNdb());

        Assert.Equal("ndb", result?.Extension);
        Assert.Equal("application/vnd.ms-outlook", result?.MimeType);
        Assert.Equal(ContentKind.Database, KindClassifier.Classify(result));
        Assert.False(FileInspector.CompareDeclared("pst", result).Mismatch);
        Assert.False(FileInspector.CompareDeclared("ost", result).Mismatch);
    }

    [Fact]
    public void CorrectlyNamedOstDoesNotReportAnExtensionMismatch()
    {
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".ost");
        try
        {
            File.WriteAllBytes(path, OutlookNdb());
            var analysis = FileInspector.Analyze(path);

            Assert.Equal("ndb", analysis.Detection?.Extension);
            Assert.Equal(NameIssues.None, analysis.NameIssues & NameIssues.ExtensionMismatch);
        }
        finally
        {
            TestHelpers.SafeDelete(path);
        }
    }

    private static void AssertParity(byte[] bytes, string extension, string confidence)
    {
        Assert.Equal(extension, FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false);
        long originalPosition = Math.Min(7, stream.Length);
        stream.Position = originalPosition;
        var fromStream = FileInspector.Detect(stream);
        Assert.Equal(extension, fromStream?.Extension);
        Assert.Equal(confidence, fromStream?.Confidence);
        Assert.Equal(originalPosition, stream.Position);

        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".bin");
        try
        {
            File.WriteAllBytes(path, bytes);
            var fromPath = FileInspector.Detect(path);
            Assert.Equal(extension, fromPath?.Extension);
            Assert.Equal(confidence, fromPath?.Confidence);
        }
        finally
        {
            TestHelpers.SafeDelete(path);
        }
    }

    private static void AssertNotDetectedAcrossCompleteApis(byte[] bytes, string extension)
    {
        Assert.NotEqual(extension, FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false);
        Assert.NotEqual(extension, FileInspector.Detect(stream)?.Extension);

        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".bin");
        try
        {
            File.WriteAllBytes(path, bytes);
            Assert.NotEqual(extension, FileInspector.Detect(path)?.Extension);
        }
        finally
        {
            TestHelpers.SafeDelete(path);
        }
    }

    private static byte[] Parquet() => TestHelpers.CreateMinimalParquet();

    private static byte[] Arrow() => TestHelpers.CreateMinimalArrow();

    private static byte[] Deb() => TestHelpers.CreateMinimalDeb();

    private static byte[] Vhd() => TestHelpers.CreateMinimalVhd();

    private static byte[] Qoi()
    {
        var bytes = new byte[26];
        Encoding.ASCII.GetBytes("qoif").CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 4, 1);
        WriteUInt32BigEndian(bytes, 8, 1);
        bytes[12] = 4;
        bytes[14] = 0xFE;
        new byte[] { 0, 0, 0, 0, 0, 0, 0, 1 }.CopyTo(bytes, bytes.Length - 8);
        return bytes;
    }

    private static byte[] LargePcapNg()
    {
        const int blockLength = 5000;
        var bytes = new byte[blockLength];
        new byte[] { 0x0A, 0x0D, 0x0D, 0x0A }.CopyTo(bytes, 0);
        WriteUInt32LittleEndian(bytes, 4, blockLength);
        new byte[] { 0x4D, 0x3C, 0x2B, 0x1A }.CopyTo(bytes, 8);
        WriteUInt16LittleEndian(bytes, 12, 1);
        WriteUInt32LittleEndian(bytes, blockLength - 4, blockLength);
        return bytes;
    }

    private static byte[] Elf(ushort machine)
    {
        var bytes = new byte[64];
        new byte[] { 0x7F, (byte)'E', (byte)'L', (byte)'F', 2, 1, 1 }.CopyTo(bytes, 0);
        WriteUInt16LittleEndian(bytes, 16, 1);
        WriteUInt16LittleEndian(bytes, 18, machine);
        WriteUInt32LittleEndian(bytes, 20, 1);
        WriteUInt16LittleEndian(bytes, 52, 64);
        return bytes;
    }

    private static byte[] LargeIcon(ushort type)
    {
        const int count = 256;
        const int directoryEnd = 6 + count * 16;
        var bytes = new byte[directoryEnd + count];
        WriteUInt16LittleEndian(bytes, 2, type);
        WriteUInt16LittleEndian(bytes, 4, count);
        for (int index = 0; index < count; index++)
        {
            int entry = 6 + index * 16;
            bytes[entry] = 1;
            bytes[entry + 1] = 1;
            WriteUInt32LittleEndian(bytes, entry + 8, 1);
            WriteUInt32LittleEndian(bytes, entry + 12, (uint)(directoryEnd + index));
        }
        return bytes;
    }

    private static byte[] OutlookNdb() => TestHelpers.CreateMinimalOutlookNdb();

    private static void WriteArMember(Stream stream, string name, byte[] data)
    {
        string header = (name + "/").PadRight(16) + "0".PadRight(12) + "0".PadRight(6) + "0".PadRight(6) +
                        "100644".PadRight(8) + data.Length.ToString(System.Globalization.CultureInfo.InvariantCulture).PadRight(10) + "`\n";
        byte[] headerBytes = Encoding.ASCII.GetBytes(header);
        stream.Write(headerBytes, 0, headerBytes.Length);
        stream.Write(data, 0, data.Length);
        if ((data.Length & 1) != 0) stream.WriteByte((byte)'\n');
    }

    private static void WriteUInt16LittleEndian(byte[] bytes, int offset, ushort value)
    {
        bytes[offset] = (byte)value;
        bytes[offset + 1] = (byte)(value >> 8);
    }

    private static void WriteUInt32LittleEndian(byte[] bytes, int offset, uint value)
    {
        bytes[offset] = (byte)value;
        bytes[offset + 1] = (byte)(value >> 8);
        bytes[offset + 2] = (byte)(value >> 16);
        bytes[offset + 3] = (byte)(value >> 24);
    }

    private static void WriteUInt32BigEndian(byte[] bytes, int offset, uint value)
    {
        bytes[offset] = (byte)(value >> 24);
        bytes[offset + 1] = (byte)(value >> 16);
        bytes[offset + 2] = (byte)(value >> 8);
        bytes[offset + 3] = (byte)value;
    }

    private sealed class NonSeekableReadStream : Stream
    {
        private readonly MemoryStream _inner;

        internal NonSeekableReadStream(byte[] bytes) => _inner = new MemoryStream(bytes, writable: false);

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing) _inner.Dispose();
            base.Dispose(disposing);
        }
    }
}
