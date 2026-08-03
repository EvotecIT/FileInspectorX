using System.Globalization;
using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class TwentySecondReviewRegressionTests
{
    [Fact]
    public void DebAcceptsStructurallyValidLzmaAloneTarMembers()
    {
        byte[] valid = DebWithLzmaMembers(property: 0x5D);
        Assert.Equal("deb", FileInspector.Detect(valid)?.Extension);
        using (var stream = new MemoryStream(valid, writable: false))
            Assert.Equal("deb", FileInspector.Detect(stream)?.Extension);

        byte[] invalid = DebWithLzmaMembers(property: 225);
        Assert.NotEqual("deb", FileInspector.Detect(invalid)?.Extension);
        using var invalidStream = new MemoryStream(invalid, writable: false);
        Assert.NotEqual("deb", FileInspector.Detect(invalidStream)?.Extension);
    }

    [Fact]
    public void Cdf2UsesComputedSizeForLargeVariableSentinels()
    {
        byte[] validHeader = Cdf2LargeFixedVariable(sentinelLast: true, smallVariable: false);
        long validLength = validHeader.Length + 0x100000000L;
        using (var stream = new SparseHeaderStream(validHeader, validLength) { Position = 7 })
        {
            var result = FileInspector.Detect(stream);
            Assert.Equal("nc", result?.Extension);
            Assert.Equal("High", result?.Confidence);
            Assert.Equal(7, stream.Position);
        }

        byte[] misplacedHeader = Cdf2LargeFixedVariable(sentinelLast: false, smallVariable: false);
        using (var stream = new SparseHeaderStream(misplacedHeader, misplacedHeader.Length + 0x100010000L))
            Assert.NotEqual("nc", FileInspector.Detect(stream)?.Extension);

        byte[] impossibleHeader = Cdf2LargeFixedVariable(sentinelLast: true, smallVariable: true);
        using var impossibleStream = new SparseHeaderStream(impossibleHeader, impossibleHeader.Length + 0x100000000L);
        Assert.NotEqual("nc", FileInspector.Detect(impossibleStream)?.Extension);
    }

    private static byte[] DebWithLzmaMembers(byte property)
    {
        var lzma = new byte[14];
        lzma[0] = property;
        lzma[3] = 0x80; // 8 MiB little-endian dictionary.
        for (int index = 5; index < 13; index++) lzma[index] = 0xFF; // Unknown uncompressed size.

        using var stream = new MemoryStream();
        stream.Write(Encoding.ASCII.GetBytes("!<arch>\n"), 0, 8);
        WriteArMember(stream, "debian-binary", Encoding.ASCII.GetBytes("2.0\n"));
        WriteArMember(stream, "control.tar.lzma", lzma);
        WriteArMember(stream, "data.tar.lzma", lzma);
        return stream.ToArray();
    }

    private static void WriteArMember(Stream stream, string name, byte[] data)
    {
        string memberName = name.Length == 16 ? name : name + "/";
        string header = memberName.PadRight(16) + "0".PadRight(12) + "0".PadRight(6) + "0".PadRight(6) +
                        "100644".PadRight(8) + data.Length.ToString(CultureInfo.InvariantCulture).PadRight(10) + "`\n";
        byte[] headerBytes = Encoding.ASCII.GetBytes(header);
        stream.Write(headerBytes, 0, headerBytes.Length);
        stream.Write(data, 0, data.Length);
        if ((data.Length & 1) != 0) stream.WriteByte((byte)'\n');
    }

    private static byte[] Cdf2LargeFixedVariable(bool sentinelLast, bool smallVariable)
    {
        using var stream = new MemoryStream();
        stream.Write(Encoding.ASCII.GetBytes("CDF"), 0, 3);
        stream.WriteByte(2);
        WriteUInt32BigEndian(stream, 0); // numrecs

        WriteUInt32BigEndian(stream, 10); // dimensions
        WriteUInt32BigEndian(stream, 2);
        WriteNetCdfName(stream, "x");
        WriteUInt32BigEndian(stream, smallVariable ? 1u : 65536u);
        WriteNetCdfName(stream, "y");
        WriteUInt32BigEndian(stream, smallVariable ? 1u : 65536u);
        WriteUInt32BigEndian(stream, 0); // global attributes
        WriteUInt32BigEndian(stream, 0);

        int variableCount = sentinelLast ? 1 : 2;
        WriteUInt32BigEndian(stream, 11);
        WriteUInt32BigEndian(stream, (uint)variableCount);
        var beginOffsets = new int[variableCount];
        WriteNetCdfVariable(stream, "large", new uint[] { 0, 1 }, uint.MaxValue, beginOffsets, 0);
        if (!sentinelLast) WriteNetCdfVariable(stream, "tail", new uint[] { 0 }, smallVariable ? 1u : 65536u, beginOffsets, 1);

        byte[] header = stream.ToArray();
        ulong firstBegin = (ulong)header.Length;
        WriteUInt64BigEndian(header, beginOffsets[0], firstBegin);
        if (!sentinelLast) WriteUInt64BigEndian(header, beginOffsets[1], firstBegin + 0x100000000UL);
        return header;
    }

    private static void WriteNetCdfVariable(Stream stream, string name, uint[] dimensions, uint declaredSize,
        int[] beginOffsets, int index)
    {
        WriteNetCdfName(stream, name);
        WriteUInt32BigEndian(stream, (uint)dimensions.Length);
        foreach (uint dimension in dimensions) WriteUInt32BigEndian(stream, dimension);
        WriteUInt32BigEndian(stream, 0); // attributes
        WriteUInt32BigEndian(stream, 0);
        WriteUInt32BigEndian(stream, 1); // NC_BYTE
        WriteUInt32BigEndian(stream, declaredSize);
        beginOffsets[index] = checked((int)stream.Position);
        WriteUInt64BigEndian(stream, 0);
    }

    private static void WriteNetCdfName(Stream stream, string value)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(value);
        WriteUInt32BigEndian(stream, (uint)bytes.Length);
        stream.Write(bytes, 0, bytes.Length);
        while ((stream.Position & 3) != 0) stream.WriteByte(0);
    }

    private static void WriteUInt32BigEndian(Stream stream, uint value)
    {
        stream.WriteByte((byte)(value >> 24));
        stream.WriteByte((byte)(value >> 16));
        stream.WriteByte((byte)(value >> 8));
        stream.WriteByte((byte)value);
    }

    private static void WriteUInt64BigEndian(Stream stream, ulong value)
    {
        WriteUInt32BigEndian(stream, (uint)(value >> 32));
        WriteUInt32BigEndian(stream, (uint)value);
    }

    private static void WriteUInt64BigEndian(byte[] bytes, int offset, ulong value)
    {
        bytes[offset] = (byte)(value >> 56);
        bytes[offset + 1] = (byte)(value >> 48);
        bytes[offset + 2] = (byte)(value >> 40);
        bytes[offset + 3] = (byte)(value >> 32);
        bytes[offset + 4] = (byte)(value >> 24);
        bytes[offset + 5] = (byte)(value >> 16);
        bytes[offset + 6] = (byte)(value >> 8);
        bytes[offset + 7] = (byte)value;
    }

    private sealed class SparseHeaderStream : Stream
    {
        private readonly byte[] _header;
        private readonly long _length;
        private long _position;

        internal SparseHeaderStream(byte[] header, long length)
        {
            _header = header;
            _length = length;
        }

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
            if (_position < _header.Length)
            {
                int headerRead = (int)Math.Min(read, _header.Length - _position);
                Array.Copy(_header, (int)_position, buffer, offset, headerRead);
            }
            _position += read;
            return read;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            _position = origin switch
            {
                SeekOrigin.Begin => offset,
                SeekOrigin.Current => _position + offset,
                _ => _length + offset
            };
            return _position;
        }

        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
