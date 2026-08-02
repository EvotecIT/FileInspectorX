using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class FifthReviewRegressionTests
{
    [Fact]
    public void Hdf5AtOffsetZeroUsesTheCompleteSeekableLength()
        => AssertParity(LargeLegacyHdf5(), "h5", "High");

    [Fact]
    public void GenericHeifBrandsPreserveTheImageContainer()
    {
        AssertHeif(Ftyp("mif1"), "High", "ftyp:heif-generic");
        AssertHeif(Ftyp("zzzz", "mif1"), "High", "ftyp:heif-generic");
        AssertHeif(Ftyp("mif2"), "High", "ftyp:heif-generic");
        AssertHeif(Ftyp("msf1"), "High", "ftyp:heif-generic");
    }

    [Fact]
    public void SpecificHeicBrandWinsOverCompatibleGenericHeifBrand()
    {
        var result = FileInspector.Detect(Ftyp("heic", "mif1"));

        Assert.Equal("heic", result?.Extension);
        Assert.Equal("image/heic", result?.MimeType);
        Assert.Equal("High", result?.Confidence);
    }

    [Fact]
    public void LegacyHeifMajorBrandIsRecognizedAtReducedConfidence()
        => AssertHeif(Ftyp("heif"), "Medium", "ftyp:heif-legacy-brand");

    [Fact]
    public void Dex041UsesTheWholeContainerSize()
        => AssertParity(Dex041Container(), "dex", "High");

    [Fact]
    public void Dex041RejectsInvalidContainerMetadata()
    {
        var nonzeroHeaderOffset = Dex041Container();
        WriteUInt32LittleEndian(nonzeroHeaderOffset, 116, 4);
        Assert.NotEqual("dex", FileInspector.Detect(nonzeroHeaderOffset)?.Extension);

        var wrongContainerSize = Dex041Container();
        WriteUInt32LittleEndian(wrongContainerSize, 112, (uint)(wrongContainerSize.Length - 4));
        Assert.NotEqual("dex", FileInspector.Detect(wrongContainerSize)?.Extension);
    }

    [Fact]
    public void NonSeekableZipWithVariableHeaderBeyondTheSampleIsMediumConfidence()
    {
        var bytes = ZipWithLongFileName();
        Assert.Equal("Medium", FileInspector.Detect(bytes)?.Confidence);

        using var stream = new NonSeekableReadStream(bytes);
        var result = FileInspector.Detect(stream);

        Assert.Equal("zip", result?.Extension);
        Assert.Equal("Medium", result?.Confidence);
        Assert.Equal("zip:local-file-header;sampled-variable-header;local-header-only", result?.Reason);
    }

    [Fact]
    public void ShortNonSeekableZipRetainsKnownLengthValidation()
    {
        using var stream = new NonSeekableReadStream(TestHelpers.CreateEmptyZip());
        var result = FileInspector.Detect(stream);

        Assert.Equal("zip", result?.Extension);
        Assert.Equal("High", result?.Confidence);
        Assert.Equal("zip:end-of-central-directory", result?.Reason);
    }

    [Fact]
    public void MidiExtensionsAreEquivalent()
    {
        var result = FileInspector.Detect(Midi());

        Assert.Equal("mid", result?.Extension);
        Assert.False(FileInspector.CompareDeclared("midi", result).Mismatch);
    }

    [Theory]
    [InlineData("mkv")]
    [InlineData("mka")]
    [InlineData("mks")]
    [InlineData("mk3d")]
    [InlineData("matroska")]
    public void MatroskaDocumentTypeDoesNotInferTrackComposition(string declaredExtension)
    {
        var result = FileInspector.Detect(Matroska("matroska"));

        Assert.Equal("matroska", result?.Extension);
        Assert.Equal("application/x-matroska", result?.MimeType);
        Assert.Equal(ContentKind.Unknown, KindClassifier.Classify(result));
        Assert.False(FileInspector.CompareDeclared(declaredExtension, result).Mismatch);
    }

    [Fact]
    public void WebmDocumentTypeDoesNotInferTrackComposition()
    {
        var result = FileInspector.Detect(Matroska("webm"));

        Assert.Equal("webm", result?.Extension);
        Assert.Equal("application/webm", result?.MimeType);
        Assert.Equal(ContentKind.Unknown, KindClassifier.Classify(result));
        Assert.False(FileInspector.CompareDeclared("webm", result).Mismatch);
    }

    private static void AssertHeif(byte[] bytes, string confidence, string reason)
    {
        var result = AssertParity(bytes, "heif", confidence);
        Assert.Equal("image/heif", result.MimeType);
        Assert.Equal(reason, result.Reason);
        Assert.Equal(ContentKind.Image, KindClassifier.Classify(result));
    }

    private static ContentTypeDetectionResult AssertParity(byte[] bytes, string extension, string confidence)
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
            return fromBytes!;
        }
        finally
        {
            TestHelpers.SafeDelete(path);
        }
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

    private static byte[] Ftyp(string majorBrand, string? compatibleBrand = null)
    {
        int fileTypeLength = compatibleBrand is null ? 16 : 20;
        var bytes = new byte[fileTypeLength + 8];
        WriteUInt32BigEndian(bytes, 0, (uint)fileTypeLength);
        Encoding.ASCII.GetBytes("ftyp").CopyTo(bytes, 4);
        Encoding.ASCII.GetBytes(majorBrand).CopyTo(bytes, 8);
        if (compatibleBrand is not null) Encoding.ASCII.GetBytes(compatibleBrand).CopyTo(bytes, 16);
        WriteUInt32BigEndian(bytes, fileTypeLength, 8);
        Encoding.ASCII.GetBytes("free").CopyTo(bytes, fileTypeLength + 4);
        return bytes;
    }

    private static byte[] Dex041Container()
    {
        const int containerSize = 5000;
        var bytes = TestHelpers.CreateMinimalDex("041", length: containerSize);
        WriteUInt32LittleEndian(bytes, 32, 4096);
        TestHelpers.FinalizeDex(bytes, dexLength: 4096);
        return bytes;
    }

    private static byte[] ZipWithLongFileName()
    {
        const ushort nameLength = 5000;
        var bytes = new byte[30 + nameLength];
        WriteUInt32LittleEndian(bytes, 0, 0x04034B50);
        WriteUInt16LittleEndian(bytes, 4, 20);
        WriteUInt16LittleEndian(bytes, 8, 8);
        WriteUInt16LittleEndian(bytes, 26, nameLength);
        for (int i = 30; i < bytes.Length; i++) bytes[i] = (byte)'a';
        return bytes;
    }

    private static byte[] Midi()
    {
        var bytes = new byte[26];
        Encoding.ASCII.GetBytes("MThd").CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 4, 6);
        WriteUInt16BigEndian(bytes, 8, 0);
        WriteUInt16BigEndian(bytes, 10, 1);
        WriteUInt16BigEndian(bytes, 12, 96);
        Encoding.ASCII.GetBytes("MTrk").CopyTo(bytes, 14);
        WriteUInt32BigEndian(bytes, 18, 4);
        new byte[] { 0, 0xFF, 0x2F, 0 }.CopyTo(bytes, 22);
        return bytes;
    }

    private static byte[] Matroska(string documentType) => TestHelpers.CreateMinimalMatroska(documentType);

    private static void FillUndefinedAddress(byte[] bytes, int offset)
    {
        for (int i = 0; i < 8; i++) bytes[offset + i] = 0xFF;
    }

    private static void WriteUInt16LittleEndian(byte[] bytes, int offset, ushort value)
    {
        bytes[offset] = (byte)value;
        bytes[offset + 1] = (byte)(value >> 8);
    }

    private static void WriteUInt16BigEndian(byte[] bytes, int offset, ushort value)
    {
        bytes[offset] = (byte)(value >> 8);
        bytes[offset + 1] = (byte)value;
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

    private static void WriteUInt64LittleEndian(byte[] bytes, int offset, ulong value)
    {
        for (int i = 0; i < 8; i++) bytes[offset + i] = (byte)(value >> (i * 8));
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
