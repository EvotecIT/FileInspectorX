using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class NinthReviewRegressionTests
{
    [Fact]
    public void NonSeekablePeBeyondPrefixRetainsIdentityAtReducedConfidence()
    {
        var bytes = LargePe();
        using var stream = new NonSeekableReadStream(bytes);

        var result = FileInspector.Detect(stream);

        Assert.Equal("exe", result?.Extension);
        Assert.Equal("Medium", result?.Confidence);
        Assert.Equal("pe:dos-header;sampled-pe-offset", result?.Reason);
        Assert.Equal("High", FileInspector.Detect(bytes)?.Confidence);
    }

    [Theory]
    [InlineData(false, true)]
    [InlineData(false, false)]
    [InlineData(true, true)]
    [InlineData(true, false)]
    public void NonSeekableTiffBeyondPrefixRetainsIdentityAtReducedConfidence(bool bigTiff, bool littleEndian)
    {
        var bytes = LargeTiff(bigTiff, littleEndian);
        using var stream = new NonSeekableReadStream(bytes);

        var result = FileInspector.Detect(stream);

        Assert.Equal("tif", result?.Extension);
        Assert.Equal("Medium", result?.Confidence);
        Assert.Contains("sampled-ifd-offset", result?.Reason);
        Assert.Equal("High", FileInspector.Detect(bytes)?.Confidence);
    }

    [Fact]
    public void QoiRequiresEnoughChunksForEveryDeclaredPixelBeforeHighConfidence()
    {
        var emptyPixelStream = Qoi(width: 1, height: 1, includePixel: false);
        var invalid = FileInspector.Detect(emptyPixelStream);

        Assert.Equal("qoi", invalid?.Extension);
        Assert.Equal("Medium", invalid?.Confidence);

        var valid = FileInspector.Detect(Qoi(width: 1, height: 1, includePixel: true));
        Assert.Equal("qoi", valid?.Extension);
        Assert.Equal("High", valid?.Confidence);
        Assert.Equal("qoi:header+pixel-stream+end-marker", valid?.Reason);
    }

    [Fact]
    public void QoiRunChunksMustProduceExactlyTheDeclaredPixelCount()
    {
        Assert.Equal("High", FileInspector.Detect(QoiRun(width: 62, operation: 0xFD))?.Confidence);
        Assert.Equal("Medium", FileInspector.Detect(QoiRun(width: 1, operation: 0xC1))?.Confidence);
    }

    [Fact]
    public void BigTiffRejectsOverflowingDirectoryOffsets()
    {
        var bytes = new byte[16];
        bytes[0] = bytes[1] = (byte)'I';
        WriteUInt16LittleEndian(bytes, 2, 43);
        WriteUInt16LittleEndian(bytes, 4, 8);
        WriteUInt64(bytes, 8, ulong.MaxValue - 1, littleEndian: true);

        Assert.NotEqual("tif", FileInspector.Detect(bytes)?.Extension);
    }

    [Fact]
    public void ZipEocdAtOffsetZeroMustDescribeAnEmptyArchive()
    {
        var invalid = EmptyZipEocd();
        WriteUInt16LittleEndian(invalid, 8, 1);
        WriteUInt16LittleEndian(invalid, 10, 1);
        WriteUInt32LittleEndian(invalid, 12, 46);

        Assert.NotEqual("zip", FileInspector.Detect(invalid)?.Extension);
        Assert.Equal("zip", FileInspector.Detect(EmptyZipEocd())?.Extension);
    }

    [Fact]
    public void SeekableFtypCompatibilityScanHasABoundedIoBudget()
    {
        using var stream = new SparseFtypStream(2L << 20) { Position = 7 };

        Assert.True(Signatures.TryMatchFtyp(stream, out var result));

        Assert.Equal("isobmff", result?.Extension);
        Assert.Equal("Medium", result?.Confidence);
        Assert.Equal("ftyp:sampled-compatible-brands", result?.Reason);
        Assert.Equal(7, stream.Position);
        Assert.InRange(stream.BytesRead, 1, 64);
    }

    [Fact]
    public void EvtxRoutesToCaptureKind()
    {
        var result = FileInspector.Detect(TestHelpers.CreateMinimalEvtx());

        Assert.Equal("evtx", result?.Extension);
        Assert.Equal(ContentKind.Capture, KindClassifier.Classify(result));
    }

    [Fact]
    public void AppleTypeOneFlavorIsAcceptedStandaloneInWoffAndInCollections()
    {
        AssertParity(TypeOneSfnt(), "otf");
        AssertParity(TypeOneWoff(), "woff");
        AssertParity(TypeOneCollection(), "otc");
    }

    private static void AssertParity(byte[] bytes, string extension)
    {
        Assert.Equal(extension, FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false);
        stream.Position = 3;
        Assert.Equal(extension, FileInspector.Detect(stream)?.Extension);
        Assert.Equal(3, stream.Position);
    }

    private static byte[] LargePe()
    {
        const int peOffset = 5000;
        var bytes = new byte[peOffset + 120];
        bytes[0] = (byte)'M';
        bytes[1] = (byte)'Z';
        WriteUInt32LittleEndian(bytes, 0x3C, peOffset);
        Encoding.ASCII.GetBytes("PE\0\0").CopyTo(bytes, peOffset);
        WriteUInt16LittleEndian(bytes, peOffset + 4, 0x014C);
        WriteUInt16LittleEndian(bytes, peOffset + 6, 1);
        WriteUInt16LittleEndian(bytes, peOffset + 20, 96);
        WriteUInt16LittleEndian(bytes, peOffset + 22, 2);
        WriteUInt16LittleEndian(bytes, peOffset + 24, 0x10B);
        return bytes;
    }

    private static byte[] LargeTiff(bool bigTiff, bool littleEndian)
    {
        const int ifdOffset = 5000;
        int length = ifdOffset + (bigTiff ? 16 : 6);
        var bytes = new byte[length];
        bytes[0] = bytes[1] = littleEndian ? (byte)'I' : (byte)'M';
        WriteUInt16(bytes, 2, bigTiff ? (ushort)43 : (ushort)42, littleEndian);
        if (bigTiff)
        {
            WriteUInt16(bytes, 4, 8, littleEndian);
            WriteUInt64(bytes, 8, ifdOffset, littleEndian);
            WriteUInt64(bytes, ifdOffset, 0, littleEndian);
        }
        else
        {
            WriteUInt32(bytes, 4, ifdOffset, littleEndian);
            WriteUInt16(bytes, ifdOffset, 0, littleEndian);
        }
        return bytes;
    }

    private static byte[] Qoi(uint width, uint height, bool includePixel)
    {
        var bytes = new byte[22 + (includePixel ? 4 : 0)];
        Encoding.ASCII.GetBytes("qoif").CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 4, width);
        WriteUInt32BigEndian(bytes, 8, height);
        bytes[12] = 4;
        if (includePixel) bytes[14] = 0xFE;
        new byte[] { 0, 0, 0, 0, 0, 0, 0, 1 }.CopyTo(bytes, bytes.Length - 8);
        return bytes;
    }

    private static byte[] QoiRun(uint width, byte operation)
    {
        var bytes = new byte[23];
        Encoding.ASCII.GetBytes("qoif").CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 4, width);
        WriteUInt32BigEndian(bytes, 8, 1);
        bytes[12] = 4;
        bytes[14] = operation;
        new byte[] { 0, 0, 0, 0, 0, 0, 0, 1 }.CopyTo(bytes, 15);
        return bytes;
    }

    private static byte[] EmptyZipEocd()
    {
        var bytes = new byte[22];
        new byte[] { 0x50, 0x4B, 0x05, 0x06 }.CopyTo(bytes, 0);
        return bytes;
    }

    private static byte[] TypeOneSfnt()
    {
        var bytes = new byte[32];
        WriteSfntDirectory(bytes, 0, 28, 0x74797031);
        Encoding.ASCII.GetBytes("data").CopyTo(bytes, 28);
        return bytes;
    }

    private static byte[] TypeOneWoff()
    {
        var bytes = new byte[68];
        Encoding.ASCII.GetBytes("wOFF").CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 4, 0x74797031);
        WriteUInt32BigEndian(bytes, 8, (uint)bytes.Length);
        WriteUInt16BigEndian(bytes, 12, 1);
        WriteUInt32BigEndian(bytes, 16, 32);
        Encoding.ASCII.GetBytes("head").CopyTo(bytes, 44);
        WriteUInt32BigEndian(bytes, 48, 64);
        WriteUInt32BigEndian(bytes, 52, 4);
        WriteUInt32BigEndian(bytes, 56, 4);
        Encoding.ASCII.GetBytes("data").CopyTo(bytes, 64);
        return bytes;
    }

    private static byte[] TypeOneCollection()
    {
        var bytes = new byte[52];
        Encoding.ASCII.GetBytes("ttcf").CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 4, 0x00010000);
        WriteUInt32BigEndian(bytes, 8, 1);
        WriteUInt32BigEndian(bytes, 12, 16);
        WriteSfntDirectory(bytes, 16, 48, 0x74797031);
        Encoding.ASCII.GetBytes("data").CopyTo(bytes, 48);
        return bytes;
    }

    private static void WriteSfntDirectory(byte[] bytes, int offset, int tableOffset, uint flavor)
    {
        WriteUInt32BigEndian(bytes, offset, flavor);
        WriteUInt16BigEndian(bytes, offset + 4, 1);
        WriteUInt16BigEndian(bytes, offset + 6, 16);
        Encoding.ASCII.GetBytes("head").CopyTo(bytes, offset + 12);
        WriteUInt32BigEndian(bytes, offset + 20, (uint)tableOffset);
        WriteUInt32BigEndian(bytes, offset + 24, 4);
    }

    private static void WriteUInt16LittleEndian(byte[] bytes, int offset, ushort value)
        => WriteUInt16(bytes, offset, value, littleEndian: true);

    private static void WriteUInt32LittleEndian(byte[] bytes, int offset, uint value)
        => WriteUInt32(bytes, offset, value, littleEndian: true);

    private static void WriteUInt16BigEndian(byte[] bytes, int offset, ushort value)
        => WriteUInt16(bytes, offset, value, littleEndian: false);

    private static void WriteUInt32BigEndian(byte[] bytes, int offset, uint value)
        => WriteUInt32(bytes, offset, value, littleEndian: false);

    private static void WriteUInt16(byte[] bytes, int offset, ushort value, bool littleEndian)
    {
        bytes[offset] = (byte)(littleEndian ? value : value >> 8);
        bytes[offset + 1] = (byte)(littleEndian ? value >> 8 : value);
    }

    private static void WriteUInt32(byte[] bytes, int offset, uint value, bool littleEndian)
    {
        for (int index = 0; index < 4; index++)
            bytes[offset + index] = (byte)(value >> ((littleEndian ? index : 3 - index) * 8));
    }

    private static void WriteUInt64(byte[] bytes, int offset, ulong value, bool littleEndian)
    {
        for (int index = 0; index < 8; index++)
            bytes[offset + index] = (byte)(value >> ((littleEndian ? index : 7 - index) * 8));
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

    private sealed class SparseFtypStream : Stream
    {
        private readonly long _length;
        private long _position;
        internal SparseFtypStream(long length) => _length = length;
        internal long BytesRead { get; private set; }
        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => _length;
        public override long Position { get => _position; set => _position = value; }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count)
        {
            int read = (int)Math.Min(count, _length - _position);
            Array.Clear(buffer, offset, read);
            for (int index = 0; index < read; index++)
            {
                long absolute = _position + index;
                buffer[offset + index] = absolute switch
                {
                    4 => (byte)'f', 5 => (byte)'t', 6 => (byte)'y', 7 => (byte)'p',
                    8 => (byte)'i', 9 => (byte)'s', 10 => (byte)'o', 11 => (byte)'m',
                    _ => buffer[offset + index]
                };
            }
            _position += read;
            BytesRead += read;
            return read;
        }
        public override long Seek(long offset, SeekOrigin origin)
        {
            _position = origin switch { SeekOrigin.Begin => offset, SeekOrigin.Current => _position + offset, _ => _length + offset };
            return _position;
        }
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
