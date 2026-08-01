using System.IO.Compression;
using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class SeventhReviewRegressionTests
{
    [Fact]
    public void ExactSampleLengthNonSeekableContainerProbesEof()
    {
        int sampleLength = Math.Max(256, Math.Min(Settings.HeaderReadBytes, 1 << 20));
        var bytes = Parquet(sampleLength);
        using var stream = new NonSeekableReadStream(bytes);

        var result = FileInspector.Detect(stream);

        Assert.Equal("parquet", result?.Extension);
        Assert.Equal("High", result?.Confidence);
        Assert.Equal(sampleLength, stream.BytesRead);
    }

    [Fact]
    public void SampledNonSeekableHdf5RetainsIdentityAtReducedConfidence()
    {
        using var stream = new NonSeekableReadStream(LargeLegacyHdf5());

        var result = FileInspector.Detect(stream);

        Assert.Equal("h5", result?.Extension);
        Assert.Equal("Medium", result?.Confidence);
        Assert.Equal("hdf5:signature@0;sampled-length-unknown", result?.Reason);
    }

    [Fact]
    public void JavaClassRequiresTheCompleteConstantPoolAndClassStructure()
    {
        Assert.Equal("class", FileInspector.Detect(JavaClass())?.Extension);

        var tagOnly = new byte[] { 0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52, 0, 2, 7 };
        Assert.NotEqual("class", FileInspector.Detect(tagOnly)?.Extension);

        var truncatedMandatoryHeader = JavaClass().Take(JavaClass().Length - 2).ToArray();
        Assert.NotEqual("class", FileInspector.Detect(truncatedMandatoryHeader)?.Extension);
    }

    [Fact]
    public void MatroskaAllowsRootLevelVoidBeforeSegment()
        => AssertParity(MatroskaWithLargeRootVoid(), "matroska", "High");

    [Fact]
    public void GuessedNugetArchiveRoutesToPackageKind()
    {
        var bytes = NugetArchive();
        using var stream = new MemoryStream(bytes, writable: false);

        var result = FileInspector.Detect(stream);

        Assert.Equal("zip", result?.Extension);
        Assert.Equal("nupkg", result?.GuessedExtension);
        Assert.Equal(ContentKind.Package, KindClassifier.Classify(result));
    }

    [Fact]
    public void EmptyMinidumpStreamDirectoryIsValid()
    {
        var bytes = EmptyMinidump();
        var result = FileInspector.Detect(bytes);

        Assert.Equal("dmp", result?.Extension);
        Assert.Equal("High", result?.Confidence);
        Assert.Equal("dmp:minidump-header;empty-directory", result?.Reason);
        AssertParity(bytes, "dmp", "High");
    }

    [Fact]
    public void EmptyMinidumpRejectsANonzeroDirectoryRva()
    {
        var bytes = EmptyMinidump();
        WriteUInt32LittleEndian(bytes, 12, 32);

        Assert.NotEqual("dmp", FileInspector.Detect(bytes)?.Extension);
    }

    private static void AssertParity(byte[] bytes, string extension, string confidence)
    {
        var fromBytes = FileInspector.Detect(bytes);
        using var stream = new MemoryStream(bytes, writable: false);
        long originalPosition = Math.Min(7, stream.Length);
        stream.Position = originalPosition;
        var fromStream = FileInspector.Detect(stream);
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".bin");
        try
        {
            File.WriteAllBytes(path, bytes);
            var fromPath = FileInspector.Detect(path);
            Assert.Equal(extension, fromBytes?.Extension);
            Assert.Equal(extension, fromStream?.Extension);
            Assert.Equal(extension, fromPath?.Extension);
            Assert.Equal(confidence, fromBytes?.Confidence);
            Assert.Equal(confidence, fromStream?.Confidence);
            Assert.Equal(confidence, fromPath?.Confidence);
            Assert.Equal(originalPosition, stream.Position);
        }
        finally
        {
            TestHelpers.SafeDelete(path);
        }
    }

    private static byte[] Parquet(int length)
    {
        var minimal = TestHelpers.CreateMinimalParquet();
        var bytes = new byte[length];
        Encoding.ASCII.GetBytes("PAR1").CopyTo(bytes, 0);
        int footerLength = minimal.Length - 12;
        Buffer.BlockCopy(minimal, 4, bytes, length - 8 - footerLength, footerLength);
        WriteUInt32LittleEndian(bytes, length - 8, (uint)footerLength);
        Encoding.ASCII.GetBytes("PAR1").CopyTo(bytes, length - 4);
        return bytes;
    }

    private static byte[] LargeLegacyHdf5()
    {
        const int length = 5000;
        var bytes = new byte[length];
        new byte[] { 0x89, (byte)'H', (byte)'D', (byte)'F', 0x0D, 0x0A, 0x1A, 0x0A }.CopyTo(bytes, 0);
        bytes[13] = 8;
        bytes[14] = 8;
        WriteUInt16LittleEndian(bytes, 16, 4);
        WriteUInt16LittleEndian(bytes, 18, 16);
        WriteUInt64LittleEndian(bytes, 24, 0);
        FillUndefinedAddress(bytes, 32);
        WriteUInt64LittleEndian(bytes, 40, length);
        FillUndefinedAddress(bytes, 48);
        WriteUInt64LittleEndian(bytes, 56, 80);
        WriteUInt64LittleEndian(bytes, 64, 100);
        return bytes;
    }

    private static byte[] JavaClass() => new byte[]
    {
        0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34, 0x00, 0x05,
        0x01, 0x00, 0x04, (byte)'T', (byte)'e', (byte)'s', (byte)'t',
        0x07, 0x00, 0x01,
        0x01, 0x00, 0x10, (byte)'j', (byte)'a', (byte)'v', (byte)'a', (byte)'/',
        (byte)'l', (byte)'a', (byte)'n', (byte)'g', (byte)'/', (byte)'O', (byte)'b',
        (byte)'j', (byte)'e', (byte)'c', (byte)'t',
        0x07, 0x00, 0x03,
        0x00, 0x21, 0x00, 0x02, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    private static byte[] MatroskaWithLargeRootVoid()
    {
        const int voidLength = 5000;
        var bytes = new byte[16 + 3 + voidLength + 4];
        new byte[] { 0x1A, 0x45, 0xDF, 0xA3, 0x8B, 0x42, 0x82, 0x88 }.CopyTo(bytes, 0);
        Encoding.ASCII.GetBytes("matroska").CopyTo(bytes, 8);
        bytes[16] = 0xEC;
        bytes[17] = 0x53;
        bytes[18] = 0x88;
        new byte[] { 0x18, 0x53, 0x80, 0x67 }.CopyTo(bytes, 19 + voidLength);
        return bytes;
    }

    private static byte[] NugetArchive()
    {
        using var stream = new MemoryStream();
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            var entry = archive.CreateEntry("package.nuspec", CompressionLevel.NoCompression);
            using var writer = new StreamWriter(entry.Open(), Encoding.UTF8);
            writer.Write("<package />");
        }
        return stream.ToArray();
    }

    private static byte[] EmptyMinidump()
    {
        var bytes = new byte[32];
        Encoding.ASCII.GetBytes("MDMP").CopyTo(bytes, 0);
        WriteUInt32LittleEndian(bytes, 4, 0xA793);
        return bytes;
    }

    private static void FillUndefinedAddress(byte[] bytes, int offset)
    {
        for (int index = 0; index < 8; index++) bytes[offset + index] = 0xFF;
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

    private static void WriteUInt64LittleEndian(byte[] bytes, int offset, ulong value)
    {
        for (int index = 0; index < 8; index++) bytes[offset + index] = (byte)(value >> (index * 8));
    }

    private sealed class NonSeekableReadStream : Stream
    {
        private readonly MemoryStream _inner;

        internal NonSeekableReadStream(byte[] bytes) => _inner = new MemoryStream(bytes, writable: false);

        internal int BytesRead { get; private set; }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count)
        {
            int read = _inner.Read(buffer, offset, count);
            BytesRead += read;
            return read;
        }
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
