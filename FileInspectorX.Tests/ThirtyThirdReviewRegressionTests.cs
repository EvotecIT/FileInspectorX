using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class ThirtyThirdReviewRegressionTests
{
    [Fact]
    public void PlanarDdsCountsEveryDeclaredPlaneAndRow()
    {
        AssertParity(DdsP208(32), "dds", "High");
        AssertNotDetectedAs(DdsP208(4), "dds");
    }

    [Fact]
    public void MatroskaConsumesRootElementsAfterAKnownLengthSegment()
    {
        AssertParity(TestHelpers.CreateMinimalMatroska(), "matroska", "Medium");
        byte[] valid = TestHelpers.CreateMinimalMatroska();
        var trailingGarbage = new byte[valid.Length + 1];
        valid.CopyTo(trailingGarbage, 0);
        AssertNotDetectedAs(trailingGarbage, "matroska");
    }

    [Fact]
    public void ParquetRowGroupsRequireColumnsAndMatchingRowCounts()
    {
        AssertParity(ParquetWithRowGroup(rowGroupRows: 1), "parquet", "High");
        AssertNotDetectedAs(ParquetWithRowGroup(rowGroupRows: 2), "parquet");
        byte[] emptyGroups = TestHelpers.CreateMinimalParquet();
        int rows = Array.IndexOf(emptyGroups, (byte)0x16, 4);
        emptyGroups[rows + 1] = 2;
        AssertNotDetectedAs(emptyGroups, "parquet");
    }

    [Fact]
    public void ParquetColumnChunksRequireAnInRangeFileOffset()
    {
        AssertNotDetectedAs(ParquetWithRowGroup(1, encodedFileOffset: null), "parquet");
        AssertNotDetectedAs(ParquetWithRowGroup(1, encodedFileOffset: 0x7E), "parquet");
    }

    [Fact]
    public void Jp2RejectsDuplicateHeaderBoxesAcrossByteAndStreamPaths()
    {
        byte[] valid = TestHelpers.CreateMinimalJpeg2000();
        AssertParity(valid, "jp2", "High");
        var duplicate = new byte[valid.Length + 30];
        valid.AsSpan(0, 62).CopyTo(duplicate);
        valid.AsSpan(32, 30).CopyTo(duplicate.AsSpan(62));
        valid.AsSpan(62).CopyTo(duplicate.AsSpan(92));
        AssertNotDetectedAs(duplicate, "jp2");
    }

    [Fact]
    public void RegistryHiveWalksEveryDeclaredBinAndValidatesTheRootCell()
    {
        byte[] valid = RegistryHive(twoValidBins: true);
        AssertParity(valid, "hive", "Medium");
        AssertNotDetectedAs(RegistryHive(twoValidBins: false), "hive");
        valid[4096 + 0x24] = (byte)'x';
        AssertNotDetectedAs(valid, "hive");
    }

    [Fact]
    public void Woff2WithoutBrotliDecodingUsesReducedConfidence()
        => AssertParity(MinimalWoff2(), "woff2", "Medium");

    private static byte[] DdsP208(int payloadLength)
    {
        var bytes = new byte[148 + payloadLength];
        Encoding.ASCII.GetBytes("DDS ").CopyTo(bytes, 0);
        TestHelpers.WriteUInt32LittleEndian(bytes, 4, 124);
        TestHelpers.WriteUInt32LittleEndian(bytes, 8, 0x100F);
        TestHelpers.WriteUInt32LittleEndian(bytes, 12, 4);
        TestHelpers.WriteUInt32LittleEndian(bytes, 16, 4);
        TestHelpers.WriteUInt32LittleEndian(bytes, 20, 4);
        TestHelpers.WriteUInt32LittleEndian(bytes, 76, 32);
        TestHelpers.WriteUInt32LittleEndian(bytes, 80, 4);
        Encoding.ASCII.GetBytes("DX10").CopyTo(bytes, 84);
        TestHelpers.WriteUInt32LittleEndian(bytes, 108, 0x1000);
        TestHelpers.WriteUInt32LittleEndian(bytes, 128, 130);
        TestHelpers.WriteUInt32LittleEndian(bytes, 132, 3);
        TestHelpers.WriteUInt32LittleEndian(bytes, 140, 1);
        return bytes;
    }

    private static byte[] ParquetWithRowGroup(long rowGroupRows, byte? encodedFileOffset = 0x08)
    {
        byte encodedRows = checked((byte)(rowGroupRows * 2));
        var metadata = new List<byte>
        {
            0x15, 0x02,
            0x19, 0x2C,
                0x48, 0x04, (byte)'r', (byte)'o', (byte)'o', (byte)'t', 0x15, 0x02, 0x00,
                0x15, 0x00, 0x25, 0x00, 0x18, 0x01, (byte)'x', 0x00,
            0x16, 0x02,
            0x19, 0x1C,
                0x19, 0x1C, 0x18, 0x01, (byte)'x'
        };
        if (encodedFileOffset.HasValue)
        {
            metadata.Add(0x16);
            metadata.Add(encodedFileOffset.Value);
        }
        metadata.Add(0x00);
        metadata.Add(0x16);
        metadata.Add(0x02);
        metadata.Add(0x16);
        metadata.Add(encodedRows);
        metadata.Add(0x00);
        metadata.Add(0x00);
        var bytes = new byte[5 + metadata.Count + 8];
        Encoding.ASCII.GetBytes("PAR1").CopyTo(bytes, 0);
        bytes[4] = 0x2A;
        metadata.CopyTo(bytes, 5);
        TestHelpers.WriteUInt32LittleEndian(bytes, bytes.Length - 8, (uint)metadata.Count);
        Encoding.ASCII.GetBytes("PAR1").CopyTo(bytes, bytes.Length - 4);
        return bytes;
    }

    private static byte[] RegistryHive(bool twoValidBins)
    {
        var bytes = new byte[4096 + 8192];
        Encoding.ASCII.GetBytes("regf").CopyTo(bytes, 0);
        TestHelpers.WriteUInt32LittleEndian(bytes, 4, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 8, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 20, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 24, 5);
        TestHelpers.WriteUInt32LittleEndian(bytes, 32, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 36, 0x20);
        TestHelpers.WriteUInt32LittleEndian(bytes, 40, 0x2000);
        TestHelpers.WriteUInt32LittleEndian(bytes, 44, 1);
        Encoding.ASCII.GetBytes("hbin").CopyTo(bytes, 4096);
        TestHelpers.WriteUInt32LittleEndian(bytes, 4100, 0);
        TestHelpers.WriteUInt32LittleEndian(bytes, 4104, 0x1000);
        TestHelpers.WriteUInt32LittleEndian(bytes, 4096 + 0x20, 0xFFFFFFB0);
        Encoding.ASCII.GetBytes("nk").CopyTo(bytes, 4096 + 0x24);
        if (twoValidBins)
        {
            Encoding.ASCII.GetBytes("hbin").CopyTo(bytes, 8192);
            TestHelpers.WriteUInt32LittleEndian(bytes, 8196, 0x1000);
            TestHelpers.WriteUInt32LittleEndian(bytes, 8200, 0x1000);
        }
        uint checksum = 0;
        for (int offset = 0; offset < 0x1FC; offset += 4)
            checksum ^= (uint)(bytes[offset] | bytes[offset + 1] << 8 | bytes[offset + 2] << 16 | bytes[offset + 3] << 24);
        TestHelpers.WriteUInt32LittleEndian(bytes, 0x1FC, checksum);
        return bytes;
    }

    private static byte[] MinimalWoff2()
    {
        var bytes = new byte[52];
        Encoding.ASCII.GetBytes("wOF2OTTO").CopyTo(bytes, 0);
        TestHelpers.WriteUInt32BigEndian(bytes, 8, (uint)bytes.Length);
        TestHelpers.WriteUInt16BigEndian(bytes, 12, 1);
        TestHelpers.WriteUInt32BigEndian(bytes, 16, 32);
        TestHelpers.WriteUInt32BigEndian(bytes, 20, 2);
        bytes[48] = 0;
        bytes[49] = 1;
        return bytes;
    }

    private static void AssertParity(byte[] bytes, string extension, string confidence)
    {
        var fromBytes = FileInspector.Detect(bytes);
        using var stream = new MemoryStream(bytes, writable: false) { Position = Math.Min(3, bytes.Length) };
        var fromStream = FileInspector.Detect(stream);
        Assert.Equal(extension, fromBytes?.Extension);
        Assert.Equal(extension, fromStream?.Extension);
        Assert.Equal(confidence, fromBytes?.Confidence);
        Assert.Equal(confidence, fromStream?.Confidence);
        Assert.Equal(Math.Min(3, bytes.Length), stream.Position);
    }

    private static void AssertNotDetectedAs(byte[] bytes, string extension)
    {
        Assert.NotEqual(extension, FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false);
        Assert.NotEqual(extension, FileInspector.Detect(stream)?.Extension);
    }
}
