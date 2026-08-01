using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class TenthReviewRegressionTests
{
    [Fact]
    public void LargeNonSeekableJavaClassRetainsIdentityAtReducedConfidence()
    {
        var bytes = LargeJavaClass();
        using var stream = new NonSeekableReadStream(bytes);

        var result = FileInspector.Detect(stream);

        Assert.Equal("class", result?.Extension);
        Assert.Equal("Medium", result?.Confidence);
        Assert.Equal("java-class:52.0;sampled-length-unknown", result?.Reason);
        Assert.Equal("High", FileInspector.Detect(bytes)?.Confidence);
    }

    [Fact]
    public void LargeNonSeekableMidiRetainsIdentityAtReducedConfidence()
    {
        var bytes = LargeMidi();
        using var stream = new NonSeekableReadStream(bytes);

        var result = FileInspector.Detect(stream);

        Assert.Equal("mid", result?.Extension);
        Assert.Equal("Medium", result?.Confidence);
        Assert.Contains("sampled-length-unknown", result?.Reason);
        Assert.Equal("High", FileInspector.Detect(bytes)?.Confidence);
    }

    [Fact]
    public void SfntValidatesEveryDeclaredTableRecord()
    {
        var valid = SfntWithTwoTables();
        Assert.Equal("ttf", FileInspector.Detect(valid)?.Extension);
        using var stream = new MemoryStream(valid, writable: false);
        Assert.Equal("ttf", FileInspector.Detect(stream)?.Extension);

        var invalid = (byte[])valid.Clone();
        WriteUInt32BigEndian(invalid, 12 + 16 + 8, 4096);
        Assert.NotEqual("ttf", FileInspector.Detect(invalid)?.Extension);
        using var invalidStream = new MemoryStream(invalid, writable: false);
        Assert.NotEqual("ttf", FileInspector.Detect(invalidStream)?.Extension);
    }

    [Fact]
    public void LargeSeekableQoiFallsBackWithoutScanningThePixelStream()
    {
        using var stream = new SparseQoiStream((1L << 20) + 23) { Position = 5 };

        var result = FileInspector.Detect(stream);

        Assert.Equal("qoi", result?.Extension);
        Assert.Equal("Medium", result?.Confidence);
        Assert.Equal(5, stream.Position);
        Assert.InRange(stream.BytesRead, 1, 32768);
    }

    [Fact]
    public void DexVersion036IsRejected()
    {
        Assert.Equal("dex", FileInspector.Detect(Dex("035"))?.Extension);
        Assert.Equal("dex", FileInspector.Detect(Dex("037"))?.Extension);
        Assert.NotEqual("dex", FileInspector.Detect(Dex("036"))?.Extension);
    }

    [Fact]
    public void CompleteJpeg2000RejectsAnOverlongFileTypeBox()
    {
        var bytes = Jpeg2000();
        WriteUInt32BigEndian(bytes, 12, 100);

        Assert.NotEqual("jp2", FileInspector.Detect(bytes)?.Extension);
        Assert.Equal("jp2", FileInspector.Detect(Jpeg2000())?.Extension);
    }

    [Fact]
    public void CabRequiresDeclaredFolderAndFileRecords()
    {
        var truncated = new byte[36];
        Encoding.ASCII.GetBytes("MSCF").CopyTo(truncated, 0);
        WriteUInt32LittleEndian(truncated, 8, 36);
        WriteUInt32LittleEndian(truncated, 16, 36);
        truncated[24] = 3;
        truncated[25] = 1;
        WriteUInt16LittleEndian(truncated, 26, 1);
        WriteUInt16LittleEndian(truncated, 28, 1);

        Assert.NotEqual("cab", FileInspector.Detect(truncated)?.Extension);
        Assert.Equal("cab", FileInspector.Detect(MinimalCab())?.Extension);
    }

    [Fact]
    public void EvtxRequiresTheHeaderBlockAndDeclaredChunks()
    {
        var truncated = new byte[128];
        WriteEvtxHeader(truncated);
        Assert.NotEqual("evtx", FileInspector.Detect(truncated)?.Extension);

        var complete = TestHelpers.CreateMinimalEvtx();
        Assert.Equal("High", FileInspector.Detect(complete)?.Confidence);
        using var sampledStream = new NonSeekableReadStream(complete);
        var sampled = FileInspector.Detect(sampledStream);
        Assert.Equal("evtx", sampled?.Extension);
        Assert.Equal("Medium", sampled?.Confidence);
    }

    private static byte[] LargeJavaClass()
    {
        using var stream = new MemoryStream();
        WriteUInt32BigEndian(stream, 0xCAFEBABE);
        WriteUInt16BigEndian(stream, 0);
        WriteUInt16BigEndian(stream, 52);
        WriteUInt16BigEndian(stream, 6);
        WriteJavaUtf8(stream, "Test");
        stream.WriteByte(7);
        WriteUInt16BigEndian(stream, 1);
        WriteJavaUtf8(stream, "java/lang/Object");
        stream.WriteByte(7);
        WriteUInt16BigEndian(stream, 3);
        WriteJavaUtf8(stream, "Blob");
        WriteUInt16BigEndian(stream, 0x21);
        WriteUInt16BigEndian(stream, 2);
        WriteUInt16BigEndian(stream, 4);
        WriteUInt16BigEndian(stream, 0);
        WriteUInt16BigEndian(stream, 0);
        WriteUInt16BigEndian(stream, 0);
        WriteUInt16BigEndian(stream, 1);
        WriteUInt16BigEndian(stream, 5);
        WriteUInt32BigEndian(stream, 5000);
        stream.Write(new byte[5000], 0, 5000);
        return stream.ToArray();
    }

    private static void WriteJavaUtf8(Stream stream, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        stream.WriteByte(1);
        WriteUInt16BigEndian(stream, checked((ushort)bytes.Length));
        stream.Write(bytes, 0, bytes.Length);
    }

    private static byte[] LargeMidi()
    {
        const int channelEvents = 1100;
        int trackLength = channelEvents * 4 + 4;
        var bytes = new byte[22 + trackLength];
        Encoding.ASCII.GetBytes("MThd").CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 4, 6);
        WriteUInt16BigEndian(bytes, 8, 0);
        WriteUInt16BigEndian(bytes, 10, 1);
        WriteUInt16BigEndian(bytes, 12, 96);
        Encoding.ASCII.GetBytes("MTrk").CopyTo(bytes, 14);
        WriteUInt32BigEndian(bytes, 18, (uint)trackLength);
        int cursor = 22;
        for (int index = 0; index < channelEvents; index++) {
            bytes[cursor++] = 0;
            bytes[cursor++] = 0x90;
            bytes[cursor++] = 60;
            bytes[cursor++] = 64;
        }
        new byte[] { 0, 0xFF, 0x2F, 0 }.CopyTo(bytes, cursor);
        return bytes;
    }

    private static byte[] SfntWithTwoTables()
    {
        var bytes = new byte[52];
        WriteUInt32BigEndian(bytes, 0, 0x00010000);
        WriteUInt16BigEndian(bytes, 4, 2);
        WriteUInt16BigEndian(bytes, 6, 32);
        WriteUInt16BigEndian(bytes, 8, 1);
        Encoding.ASCII.GetBytes("head").CopyTo(bytes, 12);
        WriteUInt32BigEndian(bytes, 20, 44);
        WriteUInt32BigEndian(bytes, 24, 4);
        Encoding.ASCII.GetBytes("name").CopyTo(bytes, 28);
        WriteUInt32BigEndian(bytes, 36, 48);
        WriteUInt32BigEndian(bytes, 40, 4);
        Encoding.ASCII.GetBytes("datafont").CopyTo(bytes, 44);
        return bytes;
    }

    private static byte[] Dex(string version)
    {
        var bytes = new byte[0x70];
        Encoding.ASCII.GetBytes("dex\n" + version + "\0").CopyTo(bytes, 0);
        WriteUInt32LittleEndian(bytes, 32, (uint)bytes.Length);
        WriteUInt32LittleEndian(bytes, 36, 0x70);
        WriteUInt32LittleEndian(bytes, 40, 0x12345678);
        return bytes;
    }

    private static byte[] Jpeg2000()
    {
        var bytes = new byte[32];
        new byte[] { 0, 0, 0, 12, (byte)'j', (byte)'P', (byte)' ', (byte)' ', 0x0D, 0x0A, 0x87, 0x0A }.CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 12, 20);
        Encoding.ASCII.GetBytes("ftyp").CopyTo(bytes, 16);
        Encoding.ASCII.GetBytes("jp2 ").CopyTo(bytes, 20);
        Encoding.ASCII.GetBytes("jp2 ").CopyTo(bytes, 28);
        return bytes;
    }

    private static byte[] MinimalCab()
    {
        var bytes = new byte[62];
        Encoding.ASCII.GetBytes("MSCF").CopyTo(bytes, 0);
        WriteUInt32LittleEndian(bytes, 8, (uint)bytes.Length);
        WriteUInt32LittleEndian(bytes, 16, 44);
        bytes[24] = 3;
        bytes[25] = 1;
        WriteUInt16LittleEndian(bytes, 26, 1);
        WriteUInt16LittleEndian(bytes, 28, 1);
        WriteUInt32LittleEndian(bytes, 36, (uint)bytes.Length);
        WriteUInt16LittleEndian(bytes, 52, 0);
        bytes[60] = (byte)'a';
        return bytes;
    }

    private static void WriteEvtxHeader(byte[] bytes)
    {
        Encoding.ASCII.GetBytes("ElfFile\0").CopyTo(bytes, 0);
        WriteUInt32LittleEndian(bytes, 0x20, 128);
        WriteUInt16LittleEndian(bytes, 0x24, 1);
        WriteUInt16LittleEndian(bytes, 0x26, 3);
        WriteUInt16LittleEndian(bytes, 0x28, 4096);
        WriteUInt16LittleEndian(bytes, 0x2A, 1);
    }

    private static void WriteUInt16LittleEndian(byte[] bytes, int offset, ushort value)
    {
        bytes[offset] = (byte)value;
        bytes[offset + 1] = (byte)(value >> 8);
    }

    private static void WriteUInt32LittleEndian(byte[] bytes, int offset, uint value)
    {
        for (int index = 0; index < 4; index++) bytes[offset + index] = (byte)(value >> (index * 8));
    }

    private static void WriteUInt16BigEndian(byte[] bytes, int offset, ushort value)
    {
        bytes[offset] = (byte)(value >> 8);
        bytes[offset + 1] = (byte)value;
    }

    private static void WriteUInt32BigEndian(byte[] bytes, int offset, uint value)
    {
        bytes[offset] = (byte)(value >> 24);
        bytes[offset + 1] = (byte)(value >> 16);
        bytes[offset + 2] = (byte)(value >> 8);
        bytes[offset + 3] = (byte)value;
    }

    private static void WriteUInt16BigEndian(Stream stream, ushort value)
    {
        stream.WriteByte((byte)(value >> 8));
        stream.WriteByte((byte)value);
    }

    private static void WriteUInt32BigEndian(Stream stream, uint value)
    {
        stream.WriteByte((byte)(value >> 24));
        stream.WriteByte((byte)(value >> 16));
        stream.WriteByte((byte)(value >> 8));
        stream.WriteByte((byte)value);
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

    private sealed class SparseQoiStream : Stream
    {
        private readonly long _length;
        private long _position;
        internal SparseQoiStream(long length) => _length = length;
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
            uint pixels = checked((uint)(_length - 22));
            for (int index = 0; index < read; index++) {
                long absolute = _position + index;
                buffer[offset + index] = absolute switch {
                    0 => (byte)'q', 1 => (byte)'o', 2 => (byte)'i', 3 => (byte)'f',
                    4 => (byte)(pixels >> 24), 5 => (byte)(pixels >> 16), 6 => (byte)(pixels >> 8), 7 => (byte)pixels,
                    11 => 1, 12 => 4,
                    _ when absolute == _length - 1 => 1,
                    _ => 0
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
