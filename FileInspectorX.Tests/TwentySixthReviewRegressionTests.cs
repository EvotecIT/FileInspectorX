using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class TwentySixthReviewRegressionTests
{
    [Fact]
    public void SampledDicomRetainsValidatedMetadataIdentity()
    {
        byte[] bytes = TestHelpers.CreateMinimalDicom(metaLength: 5000, totalLength: 6000);
        using var stream = new NonSeekableReadStream(bytes);

        var result = FileInspector.Detect(stream);

        Assert.Equal("dcm", result?.Extension);
        Assert.Equal("Medium", result?.Confidence);
        Assert.Contains("sampled-meta-header", result?.Reason);
    }

    [Theory]
    [InlineData("isom")]
    [InlineData("iso6")]
    [InlineData("av01")]
    public void SampledFtypPreservesRecognizedMajorBrand(string majorBrand)
    {
        byte[] bytes = LargeFtyp(majorBrand);
        using var stream = new NonSeekableReadStream(bytes);

        var result = FileInspector.Detect(stream);

        Assert.Equal("mp4", result?.Extension);
        Assert.Equal("Medium", result?.Confidence);
        Assert.Contains("sampled-compatible-brands", result?.Reason);
    }

    [Fact]
    public void RawPhotoshopCompositeMustEndAtEndOfFile()
    {
        byte[] bytes = TestHelpers.CreateMinimalPhotoshop();
        Array.Resize(ref bytes, bytes.Length + 1);

        AssertNotDetectedAs(bytes, "psd");
    }

    [Fact]
    public void MsiIsClassifiedAsAPackage()
    {
        Assert.Equal(ContentKind.Package, KindClassifier.Classify(new ContentTypeDetectionResult { Extension = "msi" }));
        Assert.Equal(ContentKind.Package, KindClassifier.Classify(new ContentTypeDetectionResult { GuessedExtension = "msi" }));
    }

    [Fact]
    public void CompletePngRequiresAValidIdatStream()
    {
        byte[] valid = TestHelpers.CreateMinimalPng();
        Assert.Equal("High", FileInspector.Detect(valid)?.Confidence);
        using (var validStream = new MemoryStream(valid, writable: false))
            Assert.Equal("High", FileInspector.Detect(validStream)?.Confidence);

        byte[] emptyIdat = EmptyIdatPng();
        AssertNotDetectedAs(emptyIdat, "png");

        byte[] badAdler = (byte[])valid.Clone();
        badAdler[51] ^= 1;
        TestHelpers.WriteUInt32BigEndian(badAdler, 52, ComputeCrc32(new ReadOnlySpan<byte>(badAdler, 37, 15)));
        AssertNotDetectedAs(badAdler, "png");
    }

    [Fact]
    public void DebianRequiresCanonicalFirstThreeMembers()
    {
        byte[] bytes = TestHelpers.CreateMinimalDeb();
        WriteArName(bytes, 72, "data.tar");
        WriteArName(bytes, 1668, "control.tar");

        AssertNotDetectedAs(bytes, "deb");
    }

    private static byte[] LargeFtyp(string majorBrand)
    {
        var bytes = new byte[6000];
        TestHelpers.WriteUInt32BigEndian(bytes, 0, (uint)bytes.Length);
        Encoding.ASCII.GetBytes("ftyp").CopyTo(bytes, 4);
        Encoding.ASCII.GetBytes(majorBrand).CopyTo(bytes, 8);
        return bytes;
    }

    private static byte[] EmptyIdatPng()
    {
        var bytes = new byte[57];
        new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }.CopyTo(bytes, 0);
        bytes[11] = 13;
        Encoding.ASCII.GetBytes("IHDR").CopyTo(bytes, 12);
        bytes[19] = 1;
        bytes[23] = 1;
        bytes[24] = 8;
        bytes[25] = 6;
        TestHelpers.WriteUInt32BigEndian(bytes, 29, ComputeCrc32(new ReadOnlySpan<byte>(bytes, 12, 17)));
        Encoding.ASCII.GetBytes("IDAT").CopyTo(bytes, 37);
        TestHelpers.WriteUInt32BigEndian(bytes, 41, ComputeCrc32(new ReadOnlySpan<byte>(bytes, 37, 4)));
        Encoding.ASCII.GetBytes("IEND").CopyTo(bytes, 49);
        TestHelpers.WriteUInt32BigEndian(bytes, 53, ComputeCrc32(new ReadOnlySpan<byte>(bytes, 49, 4)));
        return bytes;
    }

    private static void WriteArName(byte[] bytes, int offset, string name)
        => Encoding.ASCII.GetBytes((name + "/").PadRight(16)).CopyTo(bytes, offset);

    private static uint ComputeCrc32(ReadOnlySpan<byte> data)
    {
        uint crc = uint.MaxValue;
        for (int index = 0; index < data.Length; index++)
        {
            crc ^= data[index];
            for (int bit = 0; bit < 8; bit++) crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320u : crc >> 1;
        }
        return ~crc;
    }

    private static void AssertNotDetectedAs(byte[] bytes, string extension)
    {
        Assert.NotEqual(extension, FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false);
        Assert.NotEqual(extension, FileInspector.Detect(stream)?.Extension);
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
        protected override void Dispose(bool disposing) { if (disposing) _inner.Dispose(); base.Dispose(disposing); }
    }
}
