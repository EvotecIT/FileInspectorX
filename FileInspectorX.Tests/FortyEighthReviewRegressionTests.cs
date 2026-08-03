using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class FortyEighthReviewRegressionTests
{
    [Fact]
    public void CabinetBytesPastTheDeclaredCabinetStayAtMediumConfidence()
    {
        byte[] exact = MinimalCab();
        AssertParity(exact, "cab", "High");

        ContentTypeDetectionResult result = AssertParity(exact.Concat(new byte[] { 0xAA }).ToArray(), "cab", "Medium");
        Assert.Contains("trailing-data-not-validated", result.Reason);
    }

    [Fact]
    public void MotionJpeg2000TrackWalkRejectsMalformedTrailingChildren()
    {
        byte[] original = TestHelpers.CreateMinimalJpeg2000("mjp2");
        var malformed = new byte[original.Length + 1];
        Array.Copy(original, 0, malformed, 0, 66);
        Array.Copy(original, 66, malformed, 67, original.Length - 66);
        TestHelpers.WriteUInt32BigEndian(malformed, 32, 35);
        TestHelpers.WriteUInt32BigEndian(malformed, 49, 18);
        AssertNotDetectedAs(malformed, "mj2");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ZipDataDescriptorsMustMatchTheCentralDirectory(bool includeSignature)
    {
        byte[] valid = ZipWithDataDescriptor(includeSignature, corruptDescriptor: false);
        AssertParity(valid, "zip", "High");
        ContentTypeDetectionResult result = AssertParity(
            ZipWithDataDescriptor(includeSignature, corruptDescriptor: true), "zip", "Medium");
        Assert.Contains("local-header-only", result.Reason);
    }

    [Fact]
    public void FixedLengthParquetLeavesRequireTypeLength()
    {
        AssertParity(FixedLengthParquet(includeTypeLength: true), "parquet", "High");
        AssertNotDetectedAs(FixedLengthParquet(includeTypeLength: false), "parquet");
    }

    [Fact]
    public void CompactVarintsRejectOverflowInTheTenthByte()
        => AssertNotDetectedAs(ParquetWithOverflowingVersion(), "parquet");

    [Fact]
    public void FinalJpeg2000TilePartMayExtendToTheEndOfTheCodestream()
    {
        byte[] bytes = TestHelpers.CreateMinimalJpeg2000();
        int sot = Find(bytes, new byte[] { 0xFF, 0x90, 0x00, 0x0A });
        Assert.True(sot >= 0);
        Array.Clear(bytes, sot + 6, 4);
        AssertParity(bytes, "jp2", "High");
    }

    [Fact]
    public void JpegTrailingBytesCannotReceiveHighConfidence()
    {
        ContentTypeDetectionResult result = AssertParity(
            TestHelpers.CreateMinimalJpeg().Concat(new byte[] { 1, 2, 3 }).ToArray(), "jpg", "Medium");
        Assert.Contains("sampled", result.Reason);
    }

    [Fact]
    public void SfntTableTagsMustBeStrictlyAscending()
    {
        byte[] bytes = CompleteTrueType();
        byte[] first = bytes.AsSpan(12, 16).ToArray();
        bytes.AsSpan(28, 16).CopyTo(bytes.AsSpan(12, 16));
        first.CopyTo(bytes, 28);
        AssertNotDetectedAs(bytes, "ttf");
    }

    [Fact]
    public void PngDimensionsCannotExceedSignedThirtyOneBitLimits()
    {
        byte[] bytes = TestHelpers.CreateMinimalPng();
        TestHelpers.WriteUInt32BigEndian(bytes, 16, 0x80000000);
        TestHelpers.WriteUInt32BigEndian(bytes, 29, Crc32(bytes.AsSpan(12, 17)));
        AssertNotDetectedAs(bytes, "png");
    }

    [Fact]
    public void DebianArOddMembersRequireANewlinePaddingByte()
    {
        byte[] valid = AppendArMember(TestHelpers.CreateMinimalDeb(), validPadding: true);
        AssertParity(valid, "deb", "High");
        AssertNotDetectedAs(AppendArMember(TestHelpers.CreateMinimalDeb(), validPadding: false), "deb");
    }

    private static byte[] MinimalCab()
    {
        const int dataOffset = 66;
        var bytes = new byte[dataOffset + 11];
        Encoding.ASCII.GetBytes("MSCF").CopyTo(bytes, 0);
        TestHelpers.WriteUInt32LittleEndian(bytes, 8, (uint)bytes.Length);
        TestHelpers.WriteUInt32LittleEndian(bytes, 16, 48);
        bytes[24] = 3;
        bytes[25] = 1;
        TestHelpers.WriteUInt16LittleEndian(bytes, 26, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, 28, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, 30, 4);
        bytes[39] = 2;
        TestHelpers.WriteUInt32LittleEndian(bytes, 40, dataOffset);
        TestHelpers.WriteUInt16LittleEndian(bytes, 44, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 48, 1);
        bytes[64] = (byte)'a';
        TestHelpers.WriteUInt16LittleEndian(bytes, dataOffset + 4, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, dataOffset + 6, 1);
        bytes[bytes.Length - 1] = 0x41;
        return bytes;
    }

    private static byte[] ZipWithDataDescriptor(bool includeSignature, bool corruptDescriptor)
    {
        byte[] name = Encoding.ASCII.GetBytes("a");
        const uint crc = 0xD3D99E8B;
        int descriptorLength = includeSignature ? 16 : 12;
        int centralOffset = 30 + name.Length + 1 + descriptorLength;
        int totalLength = centralOffset + 46 + name.Length + 22;
        var bytes = new byte[totalLength];

        TestHelpers.WriteUInt32LittleEndian(bytes, 0, 0x04034B50);
        TestHelpers.WriteUInt16LittleEndian(bytes, 4, 20);
        TestHelpers.WriteUInt16LittleEndian(bytes, 6, 8);
        TestHelpers.WriteUInt16LittleEndian(bytes, 26, (ushort)name.Length);
        name.CopyTo(bytes, 30);
        bytes[31] = (byte)'A';
        int descriptor = 32;
        if (includeSignature)
        {
            TestHelpers.WriteUInt32LittleEndian(bytes, descriptor, 0x08074B50);
            descriptor += 4;
        }
        TestHelpers.WriteUInt32LittleEndian(bytes, descriptor, corruptDescriptor ? crc ^ 1u : crc);
        TestHelpers.WriteUInt32LittleEndian(bytes, descriptor + 4, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, descriptor + 8, 1);

        TestHelpers.WriteUInt32LittleEndian(bytes, centralOffset, 0x02014B50);
        TestHelpers.WriteUInt16LittleEndian(bytes, centralOffset + 4, 20);
        TestHelpers.WriteUInt16LittleEndian(bytes, centralOffset + 6, 20);
        TestHelpers.WriteUInt16LittleEndian(bytes, centralOffset + 8, 8);
        TestHelpers.WriteUInt32LittleEndian(bytes, centralOffset + 16, crc);
        TestHelpers.WriteUInt32LittleEndian(bytes, centralOffset + 20, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, centralOffset + 24, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, centralOffset + 28, (ushort)name.Length);
        name.CopyTo(bytes, centralOffset + 46);

        int eocd = centralOffset + 46 + name.Length;
        TestHelpers.WriteUInt32LittleEndian(bytes, eocd, 0x06054B50);
        TestHelpers.WriteUInt16LittleEndian(bytes, eocd + 8, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, eocd + 10, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, eocd + 12, (uint)(46 + name.Length));
        TestHelpers.WriteUInt32LittleEndian(bytes, eocd + 16, (uint)centralOffset);
        return bytes;
    }

    private static byte[] FixedLengthParquet(bool includeTypeLength)
    {
        var metadata = new List<byte>
        {
            0x15, 0x02,
            0x19, 0x2C,
            0x48, 0x04, (byte)'r', (byte)'o', (byte)'o', (byte)'t', 0x15, 0x02, 0x00,
            0x15, 0x0E
        };
        if (includeTypeLength) metadata.AddRange(new byte[] { 0x15, 0x08, 0x15, 0x00 });
        else metadata.AddRange(new byte[] { 0x25, 0x00 });
        metadata.AddRange(new byte[] { 0x18, 0x01, (byte)'x', 0x00, 0x16, 0x00, 0x19, 0x0C, 0x00 });
        return WrapParquet(metadata);
    }

    private static byte[] ParquetWithOverflowingVersion()
    {
        var metadata = new List<byte> { 0x15, 0x82 };
        metadata.AddRange(Enumerable.Repeat((byte)0x80, 8));
        metadata.Add(0x02);
        metadata.AddRange(new byte[]
        {
            0x19, 0x1C, 0x48, 0x04, (byte)'r', (byte)'o', (byte)'o', (byte)'t', 0x15, 0x00, 0x00,
            0x16, 0x00, 0x19, 0x0C, 0x00
        });
        return WrapParquet(metadata);
    }

    private static byte[] WrapParquet(List<byte> metadata)
    {
        var bytes = new byte[4 + metadata.Count + 8];
        Encoding.ASCII.GetBytes("PAR1").CopyTo(bytes, 0);
        metadata.CopyTo(bytes, 4);
        TestHelpers.WriteUInt32LittleEndian(bytes, bytes.Length - 8, (uint)metadata.Count);
        Encoding.ASCII.GetBytes("PAR1").CopyTo(bytes, bytes.Length - 4);
        return bytes;
    }

    private static byte[] CompleteTrueType()
    {
        string[] tags = { "OS/2", "cmap", "glyf", "head", "hhea", "hmtx", "loca", "maxp", "name", "post" };
        int directoryEnd = 12 + tags.Length * 16;
        var bytes = new byte[directoryEnd + tags.Length * 4 + 8];
        TestHelpers.WriteUInt32BigEndian(bytes, 0, 0x00010000);
        TestHelpers.WriteUInt16BigEndian(bytes, 4, (ushort)tags.Length);
        TestHelpers.WriteUInt16BigEndian(bytes, 6, 128);
        TestHelpers.WriteUInt16BigEndian(bytes, 8, 3);
        TestHelpers.WriteUInt16BigEndian(bytes, 10, 32);
        int payload = directoryEnd;
        for (int index = 0; index < tags.Length; index++)
        {
            int record = 12 + index * 16;
            Encoding.ASCII.GetBytes(tags[index]).CopyTo(bytes, record);
            int length = tags[index] == "head" ? 12 : 4;
            TestHelpers.WriteUInt32BigEndian(bytes, record + 8, (uint)payload);
            TestHelpers.WriteUInt32BigEndian(bytes, record + 12, (uint)length);
            payload += length;
        }
        int adjustmentOffset = directoryEnd + 3 * 4 + 8;
        TestHelpers.WriteUInt32BigEndian(bytes, adjustmentOffset,
            unchecked(0xB1B0AFBAu - ComputeSfntChecksum(bytes)));
        return bytes;
    }

    private static uint ComputeSfntChecksum(byte[] bytes)
    {
        uint sum = 0;
        for (int offset = 0; offset < bytes.Length; offset += 4)
        {
            uint word = 0;
            for (int index = 0; index < 4; index++)
                word = word << 8 | (uint)(offset + index < bytes.Length ? bytes[offset + index] : 0);
            unchecked { sum += word; }
        }
        return sum;
    }

    private static byte[] AppendArMember(byte[] deb, bool validPadding)
    {
        using var stream = new MemoryStream();
        stream.Write(deb);
        string header = "note/".PadRight(16) + "0".PadRight(12) + "0".PadRight(6) + "0".PadRight(6) +
                        "100644".PadRight(8) + "1".PadRight(10) + "`\n";
        stream.Write(Encoding.ASCII.GetBytes(header));
        stream.WriteByte(1);
        stream.WriteByte(validPadding ? (byte)'\n' : (byte)0);
        return stream.ToArray();
    }

    private static uint Crc32(ReadOnlySpan<byte> data)
    {
        uint crc = uint.MaxValue;
        foreach (byte value in data)
        {
            crc ^= value;
            for (int bit = 0; bit < 8; bit++) crc = (crc & 1) != 0 ? 0xEDB88320u ^ crc >> 1 : crc >> 1;
        }
        return ~crc;
    }

    private static int Find(byte[] bytes, byte[] pattern)
    {
        for (int offset = 0; offset <= bytes.Length - pattern.Length; offset++)
            if (bytes.AsSpan(offset, pattern.Length).SequenceEqual(pattern)) return offset;
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
        Assert.Equal(3, stream.Position);
        return fromBytes!;
    }

    private static void AssertNotDetectedAs(byte[] bytes, string extension)
    {
        Assert.NotEqual(extension, FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false) { Position = Math.Min(3, bytes.Length) };
        Assert.NotEqual(extension, FileInspector.Detect(stream)?.Extension);
        Assert.Equal(Math.Min(3, bytes.Length), stream.Position);
    }
}
