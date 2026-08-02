using System.Diagnostics;
using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class FiftiethReviewRegressionTests
{
    [Theory]
    [InlineData(107u, 4u, 2u, 8u, 16)] // YUY2: two-pixel groups, 16 bits per pixel.
    [InlineData(102u, 2u, 1u, 16u, 16)] // Y416: 64 bits per pixel.
    [InlineData(103u, 4u, 4u, 4u, 24)] // NV12: even dimensions and a half-height chroma plane.
    public void DdsDxgiYuvLayoutsUseFormatSpecificStorage(uint format, uint width, uint height, uint pitch, int payloadLength)
    {
        AssertParity(Dx10Dds(format, width, height, pitch, payloadLength), "dds", "High");
        AssertNotDetectedAs(Dx10Dds(format, width, height, pitch, payloadLength - 1), "dds");
    }

    [Fact]
    public void PcapUnvalidatedLinkLayerWordCannotReceiveHighConfidence()
    {
        byte[] bytes = MinimalPcap(0xFFFFFFFF);
        ContentTypeDetectionResult result = AssertParity(bytes, "pcap", "Medium");
        Assert.Contains("link-layer-not-validated", result.Reason);
        AssertParity(MinimalPcap(1), "pcap", "High");
    }

    [Fact]
    public void ParquetRowGroupColumnCountMustMatchSchemaLeaves()
    {
        AssertParity(ParquetWithLeavesAndColumns(2, 2), "parquet", "High");
        AssertNotDetectedAs(ParquetWithLeavesAndColumns(2, 1), "parquet");
    }

    [Fact]
    public void Jp2HeaderPropertiesMustMatchCodestreamSiz()
    {
        byte[] bytes = TestHelpers.CreateMinimalJpeg2000();
        TestHelpers.WriteUInt32BigEndian(bytes, 52, 2);
        AssertNotDetectedAs(bytes, "jp2");
    }

    [Fact]
    public void VhdRejectsExcessBatEntriesBeforeReadingTheTable()
    {
        using var stream = new ExcessBatVhdStream(100_000_000);
        var stopwatch = Stopwatch.StartNew();
        Assert.NotEqual("vhd", FileInspector.Detect(stream)?.Extension);
        stopwatch.Stop();
        Assert.True(stream.MaximumRead <= 1024 * 1024, $"Largest read was {stream.MaximumRead} bytes.");
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(5));
    }

    [Fact]
    public void ZipStoredPayloadCrcControlsHighConfidence()
    {
        byte[] valid = StoredZip("payload");
        AssertParity(valid, "zip", "High");
        int payload = FindSequence(valid, Encoding.ASCII.GetBytes("payload"));
        Assert.True(payload >= 0);
        valid[payload] ^= 1;
        ContentTypeDetectionResult result = AssertParity(valid, "zip", "Medium");
        Assert.Contains("local-header-only", result.Reason);
    }

    private static byte[] Dx10Dds(uint format, uint width, uint height, uint pitch, int payloadLength)
    {
        var bytes = new byte[148 + payloadLength];
        Encoding.ASCII.GetBytes("DDS ").CopyTo(bytes, 0);
        TestHelpers.WriteUInt32LittleEndian(bytes, 4, 124);
        TestHelpers.WriteUInt32LittleEndian(bytes, 8, 0x100F);
        TestHelpers.WriteUInt32LittleEndian(bytes, 12, height);
        TestHelpers.WriteUInt32LittleEndian(bytes, 16, width);
        TestHelpers.WriteUInt32LittleEndian(bytes, 20, pitch);
        TestHelpers.WriteUInt32LittleEndian(bytes, 76, 32);
        TestHelpers.WriteUInt32LittleEndian(bytes, 80, 4);
        Encoding.ASCII.GetBytes("DX10").CopyTo(bytes, 84);
        TestHelpers.WriteUInt32LittleEndian(bytes, 108, 0x1000);
        TestHelpers.WriteUInt32LittleEndian(bytes, 128, format);
        TestHelpers.WriteUInt32LittleEndian(bytes, 132, 3);
        TestHelpers.WriteUInt32LittleEndian(bytes, 140, 1);
        return bytes;
    }

    private static byte[] MinimalPcap(uint linkLayer)
    {
        var bytes = new byte[24];
        TestHelpers.WriteUInt32LittleEndian(bytes, 0, 0xA1B2C3D4);
        TestHelpers.WriteUInt16LittleEndian(bytes, 4, 2);
        TestHelpers.WriteUInt16LittleEndian(bytes, 6, 4);
        TestHelpers.WriteUInt32LittleEndian(bytes, 16, 65535);
        TestHelpers.WriteUInt32LittleEndian(bytes, 20, linkLayer);
        return bytes;
    }

    private static byte[] ParquetWithLeavesAndColumns(int leafCount, int columnCount)
    {
        var metadata = new List<byte> { 0x15, 0x02, 0x19, (byte)(leafCount + 1 << 4 | 12) };
        metadata.AddRange(new byte[] { 0x48, 0x04, (byte)'r', (byte)'o', (byte)'o', (byte)'t', 0x15, (byte)(leafCount * 2), 0x00 });
        for (int leaf = 0; leaf < leafCount; leaf++)
            metadata.AddRange(new byte[] { 0x15, 0x00, 0x25, 0x00, 0x18, 0x01, (byte)('a' + leaf), 0x00 });
        metadata.AddRange(new byte[] { 0x16, 0x02, 0x19, 0x1C, 0x19, (byte)(columnCount << 4 | 12) });
        for (int column = 0; column < columnCount; column++)
            metadata.AddRange(new byte[] { 0x18, 0x01, (byte)('a' + column), 0x16, 0x08, 0x00 });
        metadata.AddRange(new byte[] { 0x16, 0x02, 0x16, 0x02, 0x00, 0x00 });
        var bytes = new byte[5 + metadata.Count + 8];
        Encoding.ASCII.GetBytes("PAR1").CopyTo(bytes, 0);
        bytes[4] = 0x2A;
        metadata.CopyTo(bytes, 5);
        TestHelpers.WriteUInt32LittleEndian(bytes, bytes.Length - 8, (uint)metadata.Count);
        Encoding.ASCII.GetBytes("PAR1").CopyTo(bytes, bytes.Length - 4);
        return bytes;
    }

    private static byte[] StoredZip(string text)
    {
        byte[] name = Encoding.ASCII.GetBytes("entry.txt");
        byte[] payload = Encoding.ASCII.GetBytes(text);
        uint crc = Crc32(payload);
        int centralOffset = 30 + name.Length + payload.Length;
        int centralLength = 46 + name.Length;
        var bytes = new byte[centralOffset + centralLength + 22];
        TestHelpers.WriteUInt32LittleEndian(bytes, 0, 0x04034B50);
        TestHelpers.WriteUInt16LittleEndian(bytes, 4, 20);
        TestHelpers.WriteUInt32LittleEndian(bytes, 14, crc);
        TestHelpers.WriteUInt32LittleEndian(bytes, 18, (uint)payload.Length);
        TestHelpers.WriteUInt32LittleEndian(bytes, 22, (uint)payload.Length);
        TestHelpers.WriteUInt16LittleEndian(bytes, 26, (ushort)name.Length);
        name.CopyTo(bytes, 30);
        payload.CopyTo(bytes, 30 + name.Length);
        TestHelpers.WriteUInt32LittleEndian(bytes, centralOffset, 0x02014B50);
        TestHelpers.WriteUInt16LittleEndian(bytes, centralOffset + 4, 20);
        TestHelpers.WriteUInt16LittleEndian(bytes, centralOffset + 6, 20);
        TestHelpers.WriteUInt32LittleEndian(bytes, centralOffset + 16, crc);
        TestHelpers.WriteUInt32LittleEndian(bytes, centralOffset + 20, (uint)payload.Length);
        TestHelpers.WriteUInt32LittleEndian(bytes, centralOffset + 24, (uint)payload.Length);
        TestHelpers.WriteUInt16LittleEndian(bytes, centralOffset + 28, (ushort)name.Length);
        name.CopyTo(bytes, centralOffset + 46);
        int eocd = centralOffset + centralLength;
        TestHelpers.WriteUInt32LittleEndian(bytes, eocd, 0x06054B50);
        TestHelpers.WriteUInt16LittleEndian(bytes, eocd + 8, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, eocd + 10, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, eocd + 12, (uint)centralLength);
        TestHelpers.WriteUInt32LittleEndian(bytes, eocd + 16, (uint)centralOffset);
        return bytes;
    }

    private static uint Crc32(ReadOnlySpan<byte> data)
    {
        uint crc = uint.MaxValue;
        for (int index = 0; index < data.Length; index++)
        {
            crc ^= data[index];
            for (int bit = 0; bit < 8; bit++) crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320u : crc >> 1;
        }
        return ~crc;
    }

    private static int FindSequence(byte[] source, byte[] value)
    {
        for (int offset = 0; offset <= source.Length - value.Length; offset++)
            if (source.AsSpan(offset, value.Length).SequenceEqual(value)) return offset;
        return -1;
    }

    private static ContentTypeDetectionResult AssertParity(byte[] bytes, string extension, string confidence)
    {
        ContentTypeDetectionResult? fromBytes = FileInspector.Detect(bytes);
        using var stream = new MemoryStream(bytes, writable: false) { Position = Math.Min(3, bytes.Length) };
        ContentTypeDetectionResult? fromStream = FileInspector.Detect(stream);
        Assert.Equal(extension, fromBytes?.Extension);
        Assert.Equal(extension, fromStream?.Extension);
        Assert.Equal(confidence, fromBytes?.Confidence);
        Assert.Equal(confidence, fromStream?.Confidence);
        Assert.Equal(Math.Min(3, bytes.Length), stream.Position);
        return fromBytes!;
    }

    private static void AssertNotDetectedAs(byte[] bytes, string extension)
    {
        Assert.NotEqual(extension, FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false);
        Assert.NotEqual(extension, FileInspector.Detect(stream)?.Extension);
    }

    private sealed class ExcessBatVhdStream : Stream
    {
        private readonly byte[] _header;
        private readonly byte[] _footer;
        private readonly long _length;
        private long _position;

        internal ExcessBatVhdStream(uint entries)
        {
            const long headerOffset = 512;
            const long tableOffset = 1536;
            ulong tableLength = ((ulong)entries * 4 + 511) & ~511UL;
            _length = checked((long)((ulong)tableOffset + tableLength + 512));
            _header = new byte[1024];
            Encoding.ASCII.GetBytes("cxsparse").CopyTo(_header, 0);
            TestHelpers.WriteUInt64BigEndian(_header, 8, ulong.MaxValue);
            TestHelpers.WriteUInt64BigEndian(_header, 16, (ulong)tableOffset);
            TestHelpers.WriteUInt32BigEndian(_header, 24, 0x00010000);
            TestHelpers.WriteUInt32BigEndian(_header, 28, entries);
            TestHelpers.WriteUInt32BigEndian(_header, 32, 512 * 1024);
            FinalizeChecksum(_header, 36);
            _footer = new byte[512];
            Encoding.ASCII.GetBytes("conectix").CopyTo(_footer, 0);
            TestHelpers.WriteUInt32BigEndian(_footer, 8, 2);
            TestHelpers.WriteUInt32BigEndian(_footer, 12, 0x00010000);
            TestHelpers.WriteUInt64BigEndian(_footer, 16, (ulong)headerOffset);
            TestHelpers.WriteUInt64BigEndian(_footer, 40, 512 * 1024);
            TestHelpers.WriteUInt64BigEndian(_footer, 48, 512 * 1024);
            TestHelpers.WriteUInt32BigEndian(_footer, 56, 0x00010101);
            TestHelpers.WriteUInt32BigEndian(_footer, 60, 3);
            _footer[68] = 1;
            FinalizeChecksum(_footer, 64);
        }

        internal int MaximumRead { get; private set; }
        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => _length;
        public override long Position { get => _position; set => _position = value; }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count)
        {
            MaximumRead = Math.Max(MaximumRead, count);
            int read = (int)Math.Min(count, _length - _position);
            Array.Clear(buffer, offset, read);
            CopyRegion(_header, 512, buffer, offset, read);
            CopyRegion(_footer, _length - 512, buffer, offset, read);
            _position += read;
            return read;
        }

        private void CopyRegion(byte[] region, long regionOffset, byte[] buffer, int offset, int read)
        {
            long start = Math.Max(_position, regionOffset);
            long end = Math.Min(_position + read, regionOffset + region.Length);
            if (start < end) Buffer.BlockCopy(region, (int)(start - regionOffset), buffer, offset + (int)(start - _position), (int)(end - start));
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            _position = origin switch
            {
                SeekOrigin.Begin => offset,
                SeekOrigin.Current => checked(_position + offset),
                SeekOrigin.End => checked(_length + offset),
                _ => throw new ArgumentOutOfRangeException(nameof(origin))
            };
            return _position;
        }

        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private static void FinalizeChecksum(byte[] bytes, int checksumOffset)
    {
        uint sum = 0;
        for (int index = 0; index < bytes.Length; index++)
            if (index < checksumOffset || index >= checksumOffset + 4) sum += bytes[index];
        TestHelpers.WriteUInt32BigEndian(bytes, checksumOffset, ~sum);
    }
}
