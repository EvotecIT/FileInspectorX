using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class FiftyFirstReviewRegressionTests
{
    [Fact]
    public void JpegRestartMarkersAreRejectedOutsideEntropyData()
    {
        byte[] bytes = TestHelpers.CreateMinimalJpeg().Take(26)
            .Concat(new byte[] { 0xFF, 0xFE, 0x00, 0x02, 0xFF, 0xD0, 0xFF, 0xD9 }).ToArray();
        AssertNotDetectedAs(bytes, "jpg");
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void ZipExtraFieldsMustUseCompleteSubfieldFraming(bool malformedLocal, bool malformedCentral)
    {
        AssertParity(StoredZipWithExtraFields(false, false), "zip", "High");
        AssertParity(StoredZipWithExtraFields(malformedLocal, malformedCentral), "zip", "Medium");
    }

    [Fact]
    public void CabFolderDataRangesCannotOverlap()
    {
        AssertParity(CabWithTwoFolders(overlap: false), "cab", "High");
        AssertNotDetectedAs(CabWithTwoFolders(overlap: true), "cab");
    }

    [Fact]
    public void ParquetColumnChunksRequireReadableMetadata()
    {
        AssertParity(ParquetWithColumnMetadata(includeMetadata: true), "parquet", "High");
        AssertParity(ParquetWithColumnMetadata(includeMetadata: true, encrypted: true), "parquet", "Medium");
        AssertNotDetectedAs(ParquetWithColumnMetadata(includeMetadata: false), "parquet");
    }

    [Fact]
    public void IndexedBmpRequiresAColorTableBeforePixels()
    {
        AssertParity(IndexedBmp(colorsUsed: 1, includePalette: true), "bmp", "High");
        AssertNotDetectedAs(IndexedBmp(colorsUsed: 0, includePalette: false), "bmp");
    }

    [Fact]
    public void NetCdfRecordsRequireAnUnlimitedDimension()
    {
        AssertParity(FixedDimensionNetCdf(recordCount: 0), "nc", "High");
        AssertNotDetectedAs(FixedDimensionNetCdf(recordCount: 1), "nc");
    }

    private static byte[] StoredZipWithExtraFields(bool malformedLocal, bool malformedCentral)
    {
        byte[] name = Encoding.ASCII.GetBytes("a");
        byte[] localExtra = ZipExtraField(malformedLocal);
        byte[] centralExtra = ZipExtraField(malformedCentral);
        int centralOffset = 30 + name.Length + localExtra.Length;
        int centralLength = 46 + name.Length + centralExtra.Length;
        var bytes = new byte[centralOffset + centralLength + 22];
        TestHelpers.WriteUInt32LittleEndian(bytes, 0, 0x04034B50);
        TestHelpers.WriteUInt16LittleEndian(bytes, 4, 20);
        TestHelpers.WriteUInt16LittleEndian(bytes, 26, (ushort)name.Length);
        TestHelpers.WriteUInt16LittleEndian(bytes, 28, (ushort)localExtra.Length);
        name.CopyTo(bytes, 30);
        localExtra.CopyTo(bytes, 30 + name.Length);

        TestHelpers.WriteUInt32LittleEndian(bytes, centralOffset, 0x02014B50);
        TestHelpers.WriteUInt16LittleEndian(bytes, centralOffset + 4, 20);
        TestHelpers.WriteUInt16LittleEndian(bytes, centralOffset + 6, 20);
        TestHelpers.WriteUInt16LittleEndian(bytes, centralOffset + 28, (ushort)name.Length);
        TestHelpers.WriteUInt16LittleEndian(bytes, centralOffset + 30, (ushort)centralExtra.Length);
        name.CopyTo(bytes, centralOffset + 46);
        centralExtra.CopyTo(bytes, centralOffset + 46 + name.Length);

        int eocd = centralOffset + centralLength;
        TestHelpers.WriteUInt32LittleEndian(bytes, eocd, 0x06054B50);
        TestHelpers.WriteUInt16LittleEndian(bytes, eocd + 8, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, eocd + 10, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, eocd + 12, (uint)centralLength);
        TestHelpers.WriteUInt32LittleEndian(bytes, eocd + 16, (uint)centralOffset);
        return bytes;
    }

    private static byte[] ZipExtraField(bool malformed)
        => new byte[] { 1, 0, malformed ? (byte)3 : (byte)2, 0, 0xAA, 0xBB };

    private static byte[] CabWithTwoFolders(bool overlap)
    {
        const int filesOffset = 52;
        const int dataOffset = 88;
        int secondDataOffset = overlap ? dataOffset : dataOffset + 9;
        int cabinetSize = secondDataOffset + 9;
        var bytes = new byte[cabinetSize];
        Encoding.ASCII.GetBytes("MSCF").CopyTo(bytes, 0);
        TestHelpers.WriteUInt32LittleEndian(bytes, 8, (uint)cabinetSize);
        TestHelpers.WriteUInt32LittleEndian(bytes, 16, filesOffset);
        bytes[24] = 3;
        bytes[25] = 1;
        TestHelpers.WriteUInt16LittleEndian(bytes, 26, 2);
        TestHelpers.WriteUInt16LittleEndian(bytes, 28, 2);
        TestHelpers.WriteUInt32LittleEndian(bytes, 36, dataOffset);
        TestHelpers.WriteUInt16LittleEndian(bytes, 40, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 44, (uint)secondDataOffset);
        TestHelpers.WriteUInt16LittleEndian(bytes, 48, 1);
        WriteCabFile(bytes, filesOffset, 0, (byte)'a');
        WriteCabFile(bytes, filesOffset + 18, 1, (byte)'b');
        WriteCabData(bytes, dataOffset);
        WriteCabData(bytes, secondDataOffset);
        return bytes;
    }

    private static void WriteCabFile(byte[] bytes, int offset, ushort folder, byte name)
    {
        TestHelpers.WriteUInt32LittleEndian(bytes, offset, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, offset + 8, folder);
        bytes[offset + 16] = name;
    }

    private static void WriteCabData(byte[] bytes, int offset)
    {
        TestHelpers.WriteUInt16LittleEndian(bytes, offset + 4, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, offset + 6, 1);
        bytes[offset + 8] = 1;
    }

    private static byte[] ParquetWithColumnMetadata(bool includeMetadata, bool encrypted = false)
    {
        var metadata = new List<byte>
        {
            0x15, 0x02,
            0x19, 0x2C,
            0x48, 0x04, (byte)'r', (byte)'o', (byte)'o', (byte)'t', 0x15, 0x02, 0x00,
            0x15, 0x00, 0x25, 0x00, 0x18, 0x01, (byte)'x', 0x00,
            0x16, 0x02,
            0x19, 0x1C,
            0x19, 0x1C, 0x18, 0x01, (byte)'x', 0x16, 0x08
        };
        if (includeMetadata)
        {
            if (encrypted)
            {
                metadata.AddRange(new byte[] { 0x6C, 0x1C, 0x00, 0x00, 0x18, 0x01, 0xAA });
            }
            else metadata.AddRange(new byte[]
            {
                0x1C,
                0x15, 0x00,
                0x19, 0x15, 0x00,
                0x19, 0x18, 0x01, (byte)'x',
                0x15, 0x00,
                0x16, 0x02,
                0x16, 0x02,
                0x16, 0x02,
                0x26, 0x08,
                0x00
            });
        }
        metadata.AddRange(new byte[] { 0x00, 0x16, 0x02, 0x16, 0x02, 0x00, 0x00 });
        var bytes = new byte[5 + metadata.Count + 8];
        Encoding.ASCII.GetBytes("PAR1").CopyTo(bytes, 0);
        bytes[4] = 0x2A;
        metadata.CopyTo(bytes, 5);
        TestHelpers.WriteUInt32LittleEndian(bytes, bytes.Length - 8, (uint)metadata.Count);
        Encoding.ASCII.GetBytes("PAR1").CopyTo(bytes, bytes.Length - 4);
        return bytes;
    }

    private static byte[] IndexedBmp(uint colorsUsed, bool includePalette)
    {
        int paletteLength = includePalette ? 4 : 0;
        int pixelOffset = 54 + paletteLength;
        var bytes = new byte[pixelOffset + 4];
        Encoding.ASCII.GetBytes("BM").CopyTo(bytes, 0);
        TestHelpers.WriteUInt32LittleEndian(bytes, 2, (uint)bytes.Length);
        TestHelpers.WriteUInt32LittleEndian(bytes, 10, (uint)pixelOffset);
        TestHelpers.WriteUInt32LittleEndian(bytes, 14, 40);
        TestHelpers.WriteUInt32LittleEndian(bytes, 18, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 22, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, 26, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, 28, 8);
        TestHelpers.WriteUInt32LittleEndian(bytes, 34, 4);
        TestHelpers.WriteUInt32LittleEndian(bytes, 46, colorsUsed);
        return bytes;
    }

    private static byte[] FixedDimensionNetCdf(uint recordCount)
    {
        var bytes = new byte[44];
        Encoding.ASCII.GetBytes("CDF").CopyTo(bytes, 0);
        bytes[3] = 1;
        TestHelpers.WriteUInt32BigEndian(bytes, 4, recordCount);
        TestHelpers.WriteUInt32BigEndian(bytes, 8, 10);
        TestHelpers.WriteUInt32BigEndian(bytes, 12, 1);
        TestHelpers.WriteUInt32BigEndian(bytes, 16, 1);
        bytes[20] = (byte)'x';
        TestHelpers.WriteUInt32BigEndian(bytes, 24, 1);
        return bytes;
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
}
