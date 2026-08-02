using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class FortySixthReviewRegressionTests
{
    [Fact]
    public void NetCdfDimensionCountsAreBoundedBeforeAllocation()
    {
        var bytes = new byte[16];
        Encoding.ASCII.GetBytes("CDF").CopyTo(bytes, 0);
        bytes[3] = 1;
        TestHelpers.WriteUInt32BigEndian(bytes, 8, 10);
        TestHelpers.WriteUInt32BigEndian(bytes, 12, 1_000_000);
        AssertNotDetectedAs(bytes, "nc");
    }

    [Fact]
    public void NetCdfVariableOffsetsMustBeFourByteAligned()
    {
        AssertParity(NetCdfVariable(80), "nc", "High");
        AssertNotDetectedAs(NetCdfVariable(81), "nc");
    }

    [Fact]
    public void UnknownDdsFourCcRetainsIdentityWithoutGuessingItsPayloadSize()
    {
        ContentTypeDetectionResult result = AssertParity(UnknownFourCcDds(includePayload: true), "dds", "Medium");
        Assert.Contains("encoding-size-not-validated", result.Reason);
        AssertNotDetectedAs(UnknownFourCcDds(includePayload: false), "dds");
    }

    [Fact]
    public void CompleteBmpWithTrailingBytesDoesNotReceiveHighConfidence()
    {
        byte[] exact = MinimalBmp();
        AssertParity(exact, "bmp", "High");
        ContentTypeDetectionResult result = AssertParity(exact.Concat(new byte[] { 0 }).ToArray(), "bmp", "Medium");
        Assert.Contains("trailing-data-not-validated", result.Reason);
    }

    [Fact]
    public void ParquetNonRootSchemaElementsRequireARepetitionType()
    {
        AssertParity(ParquetWithLeaf(includeRepetition: true), "parquet", "High");
        AssertNotDetectedAs(ParquetWithLeaf(includeRepetition: false), "parquet");
    }

    [Theory]
    [InlineData(1, 4)]
    [InlineData(2, 8)]
    [InlineData(3, 24)]
    [InlineData(6, 8)]
    public void IconDibCompressionMustMatchItsBitDepth(uint compression, ushort bitDepth)
        => AssertNotDetectedAs(DibIcon(compression, bitDepth), "ico");

    [Fact]
    public void DifferencingVhdWithoutValidatedParentLocatorsStaysAtMediumConfidence()
    {
        ContentTypeDetectionResult result = AssertParity(DifferencingVhd(), "vhd", "Medium");
        Assert.Contains("parent-locators-not-validated", result.Reason);
    }

    [Theory]
    [InlineData(0x52)]
    [InlineData(0x5C)]
    public void Jpeg2000MainHeaderRequiresCodAndQcd(byte missingMarker)
    {
        byte[] bytes = TestHelpers.CreateMinimalJpeg2000();
        int marker = FindMarker(bytes, missingMarker);
        Assert.True(marker >= 0);
        bytes[marker + 1] = 0x53;
        AssertNotHigh(bytes, "jp2");
    }

    private static byte[] NetCdfVariable(uint begin)
    {
        var bytes = new byte[checked((int)begin + 4)];
        Encoding.ASCII.GetBytes("CDF").CopyTo(bytes, 0);
        bytes[3] = 1;
        TestHelpers.WriteUInt32BigEndian(bytes, 8, 10);
        TestHelpers.WriteUInt32BigEndian(bytes, 12, 1);
        TestHelpers.WriteUInt32BigEndian(bytes, 16, 1);
        bytes[20] = (byte)'x';
        TestHelpers.WriteUInt32BigEndian(bytes, 24, 1);
        TestHelpers.WriteUInt32BigEndian(bytes, 36, 11);
        TestHelpers.WriteUInt32BigEndian(bytes, 40, 1);
        TestHelpers.WriteUInt32BigEndian(bytes, 44, 1);
        bytes[48] = (byte)'v';
        TestHelpers.WriteUInt32BigEndian(bytes, 52, 1);
        TestHelpers.WriteUInt32BigEndian(bytes, 68, 4);
        TestHelpers.WriteUInt32BigEndian(bytes, 72, 4);
        TestHelpers.WriteUInt32BigEndian(bytes, 76, begin);
        return bytes;
    }

    private static byte[] UnknownFourCcDds(bool includePayload)
    {
        var bytes = new byte[128 + (includePayload ? 1 : 0)];
        Encoding.ASCII.GetBytes("DDS ").CopyTo(bytes, 0);
        TestHelpers.WriteUInt32LittleEndian(bytes, 4, 124);
        TestHelpers.WriteUInt32LittleEndian(bytes, 8, 0x1007);
        TestHelpers.WriteUInt32LittleEndian(bytes, 12, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 16, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 76, 32);
        TestHelpers.WriteUInt32LittleEndian(bytes, 80, 4);
        Encoding.ASCII.GetBytes("ZZZZ").CopyTo(bytes, 84);
        TestHelpers.WriteUInt32LittleEndian(bytes, 108, 0x1000);
        return bytes;
    }

    private static byte[] MinimalBmp()
    {
        var bytes = new byte[30];
        bytes[0] = (byte)'B'; bytes[1] = (byte)'M';
        TestHelpers.WriteUInt32LittleEndian(bytes, 2, 30);
        TestHelpers.WriteUInt32LittleEndian(bytes, 10, 26);
        TestHelpers.WriteUInt32LittleEndian(bytes, 14, 12);
        TestHelpers.WriteUInt16LittleEndian(bytes, 18, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, 20, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, 22, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, 24, 24);
        return bytes;
    }

    private static byte[] ParquetWithLeaf(bool includeRepetition)
    {
        var metadata = new List<byte>
        {
            0x15, 0x02,
            0x19, 0x2C,
            0x48, 0x04, (byte)'r', (byte)'o', (byte)'o', (byte)'t', 0x15, 0x02, 0x00,
            0x15, 0x00
        };
        if (includeRepetition) metadata.AddRange(new byte[] { 0x25, 0x00 });
        metadata.AddRange(new byte[] { 0x18, 0x01, (byte)'x', 0x00, 0x16, 0x00, 0x19, 0x0C, 0x00 });
        var bytes = new byte[4 + metadata.Count + 8];
        Encoding.ASCII.GetBytes("PAR1").CopyTo(bytes, 0);
        metadata.CopyTo(bytes, 4);
        TestHelpers.WriteUInt32LittleEndian(bytes, bytes.Length - 8, (uint)metadata.Count);
        Encoding.ASCII.GetBytes("PAR1").CopyTo(bytes, bytes.Length - 4);
        return bytes;
    }

    private static byte[] DibIcon(uint compression, ushort bitDepth)
    {
        const int payloadLength = 128;
        var bytes = new byte[22 + payloadLength];
        TestHelpers.WriteUInt16LittleEndian(bytes, 2, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, 4, 1);
        bytes[6] = 1;
        bytes[7] = 1;
        TestHelpers.WriteUInt16LittleEndian(bytes, 10, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, 12, bitDepth);
        TestHelpers.WriteUInt32LittleEndian(bytes, 14, payloadLength);
        TestHelpers.WriteUInt32LittleEndian(bytes, 18, 22);
        TestHelpers.WriteUInt32LittleEndian(bytes, 22, 40);
        TestHelpers.WriteUInt32LittleEndian(bytes, 26, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 30, 2);
        TestHelpers.WriteUInt16LittleEndian(bytes, 34, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, 36, bitDepth);
        TestHelpers.WriteUInt32LittleEndian(bytes, 38, compression);
        TestHelpers.WriteUInt32LittleEndian(bytes, 42, 4);
        return bytes;
    }

    private static byte[] DifferencingVhd()
    {
        var bytes = new byte[2560];
        const int header = 512;
        const int table = 1536;
        const int footer = 2048;
        Encoding.ASCII.GetBytes("cxsparse").CopyTo(bytes, header);
        TestHelpers.WriteUInt64BigEndian(bytes, header + 8, ulong.MaxValue);
        TestHelpers.WriteUInt64BigEndian(bytes, header + 16, table);
        TestHelpers.WriteUInt32BigEndian(bytes, header + 24, 0x00010000);
        TestHelpers.WriteUInt32BigEndian(bytes, header + 28, 1);
        TestHelpers.WriteUInt32BigEndian(bytes, header + 32, 512 * 1024);
        bytes[header + 40] = 1;
        FinalizeChecksum(bytes, header, 1024, 36);
        TestHelpers.WriteUInt32BigEndian(bytes, table, uint.MaxValue);

        Encoding.ASCII.GetBytes("conectix").CopyTo(bytes, footer);
        TestHelpers.WriteUInt32BigEndian(bytes, footer + 8, 2);
        TestHelpers.WriteUInt32BigEndian(bytes, footer + 12, 0x00010000);
        TestHelpers.WriteUInt64BigEndian(bytes, footer + 16, header);
        TestHelpers.WriteUInt64BigEndian(bytes, footer + 40, 512 * 1024);
        TestHelpers.WriteUInt64BigEndian(bytes, footer + 48, 512 * 1024);
        TestHelpers.WriteUInt32BigEndian(bytes, footer + 56, 0x00010101);
        TestHelpers.WriteUInt32BigEndian(bytes, footer + 60, 4);
        bytes[footer + 68] = 1;
        FinalizeChecksum(bytes, footer, 512, 64);
        bytes.AsSpan(footer, 512).CopyTo(bytes);
        return bytes;
    }

    private static void FinalizeChecksum(byte[] bytes, int offset, int length, int checksumOffset)
    {
        uint sum = 0;
        for (int index = 0; index < length; index++)
            if (index < checksumOffset || index >= checksumOffset + 4) sum += bytes[offset + index];
        TestHelpers.WriteUInt32BigEndian(bytes, offset + checksumOffset, ~sum);
    }

    private static int FindMarker(byte[] bytes, byte marker)
    {
        for (int index = 0; index + 1 < bytes.Length; index++)
            if (bytes[index] == 0xFF && bytes[index + 1] == marker) return index;
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
        using var stream = new MemoryStream(bytes, writable: false) { Position = Math.Min(2, bytes.Length) };
        Assert.NotEqual(extension, FileInspector.Detect(stream)?.Extension);
        Assert.Equal(Math.Min(2, bytes.Length), stream.Position);
    }

    private static void AssertNotHigh(byte[] bytes, string extension)
    {
        ContentTypeDetectionResult? fromBytes = FileInspector.Detect(bytes);
        using var stream = new MemoryStream(bytes, writable: false) { Position = Math.Min(2, bytes.Length) };
        ContentTypeDetectionResult? fromStream = FileInspector.Detect(stream);
        Assert.True(fromBytes?.Extension != extension || fromBytes.Confidence != "High");
        Assert.True(fromStream?.Extension != extension || fromStream.Confidence != "High");
        Assert.Equal(Math.Min(2, bytes.Length), stream.Position);
    }
}
