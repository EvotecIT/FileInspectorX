using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class TwentyFifthReviewRegressionTests
{
    [Fact]
    public void PeHeadersCoverTheAlignedSectionTable()
    {
        byte[] bytes = TestHelpers.CreateMinimalPe();
        TestHelpers.WriteUInt32LittleEndian(bytes, 0xD4, 0x100);
        AssertNotDetectedAs(bytes, "exe");
    }

    [Fact]
    public void OpenExrRejectsDuplicateChunkOffsets()
    {
        byte[] bytes = TestHelpers.CreateMinimalMultipartOpenExr();
        bool changed = false;
        for (int offset = 8; offset + 16 <= bytes.Length; offset++)
        {
            ulong first = ReadUInt64LittleEndian(bytes, offset);
            ulong second = ReadUInt64LittleEndian(bytes, offset + 8);
            if (first >= (ulong)(offset + 16) && second > first && second < (ulong)bytes.Length)
            {
                TestHelpers.WriteUInt64LittleEndian(bytes, offset + 8, first);
                changed = true;
                break;
            }
        }
        Assert.True(changed);
        AssertNotDetectedAs(bytes, "exr");
    }

    [Fact]
    public void FatMachOSliceSubtypeMatchesItsDirectory()
    {
        byte[] bytes = FatMachO();
        Assert.Equal("macho", FileInspector.Detect(bytes)?.Extension);
        TestHelpers.WriteUInt32LittleEndian(bytes, 72, 4);
        AssertNotDetectedAs(bytes, "macho");
    }

    [Fact]
    public void WoffOptionalBlocksFollowFontDataWithoutOverlap()
    {
        byte[] bytes = WoffWithMetadata();
        Assert.Equal("woff", FileInspector.Detect(bytes)?.Extension);
        TestHelpers.WriteUInt32BigEndian(bytes, 24, 64);
        AssertNotDetectedAs(bytes, "woff");
    }

    [Fact]
    public void ParquetSchemaListsContainStructures()
    {
        byte[] bytes = TestHelpers.CreateMinimalParquet();
        bytes[7] = 0x18;
        AssertNotDetectedAs(bytes, "parquet");
    }

    [Fact]
    public void SfntRejectsDuplicateTableTags()
        => AssertNotDetectedAs(SfntWithDuplicateTables(), "ttf");

    [Fact]
    public void TiffValidatesEntryTypesValueRangesAndLinkedDirectories()
    {
        byte[] bytes = Tiff();
        Assert.Equal("tif", FileInspector.Detect(bytes)?.Extension);
        byte[] badType = (byte[])bytes.Clone();
        TestHelpers.WriteUInt16LittleEndian(badType, 12, 99);
        AssertNotDetectedAs(badType, "tif");
        TestHelpers.WriteUInt32LittleEndian(bytes, 22, 200);
        AssertNotDetectedAs(bytes, "tif");
    }

    [Fact]
    public void CabContinuationIndicesAgreeWithCabinetFlags()
    {
        byte[] bytes = Cab();
        TestHelpers.WriteUInt16LittleEndian(bytes, 56, 0xFFFF);
        AssertNotDetectedAs(bytes, "cab");
    }

    [Fact]
    public void Qcow2MetadataRegionsDoNotOverlap()
    {
        byte[] bytes = Qcow2();
        TestHelpers.WriteUInt64BigEndian(bytes, 48, 512);
        AssertNotDetectedAs(bytes, "qcow2");
    }

    [Fact]
    public void DdsDx10TextureDimensionsAgreeWithTheLegacyHeader()
    {
        byte[] bytes = DdsDx10();
        TestHelpers.WriteUInt32LittleEndian(bytes, 132, 2);
        TestHelpers.WriteUInt32LittleEndian(bytes, 12, 2);
        AssertNotDetectedAs(bytes, "dds");
    }

    [Fact]
    public void MatroskaRejectsUnsupportedEbmlHeaderValues()
        => AssertNotDetectedAs(MatroskaWithEbmlVersion(2), "matroska");

    [Fact]
    public void Jpeg2000ValidatesHeaderAndCodestreamPayloads()
    {
        byte[] header = TestHelpers.CreateMinimalJpeg2000();
        TestHelpers.WriteUInt32BigEndian(header, 48, 0);
        AssertNotDetectedAs(header, "jp2");
        byte[] codestream = TestHelpers.CreateMinimalJpeg2000();
        codestream[codestream.Length - 4] = 0;
        AssertNotDetectedAs(codestream, "jp2");
    }

    [Fact]
    public void FtypWithTrailingJunkDoesNotReceiveHighConfidence()
    {
        var bytes = new byte[28];
        TestHelpers.WriteUInt32BigEndian(bytes, 0, 20);
        Encoding.ASCII.GetBytes("ftypmp42").CopyTo(bytes, 4);
        Encoding.ASCII.GetBytes("mp42").CopyTo(bytes, 16);
        Encoding.ASCII.GetBytes("junkjunk").CopyTo(bytes, 20);
        var result = FileInspector.Detect(bytes);
        Assert.Equal("mp4", result?.Extension);
        Assert.Equal("Medium", result?.Confidence);
    }

    [Fact]
    public void ShellLinkValidatesShowCommandAndReservedFields()
    {
        byte[] bytes = ShellLink();
        TestHelpers.WriteUInt32LittleEndian(bytes, 60, 2);
        AssertNotDetectedAs(bytes, "lnk");
        bytes = ShellLink();
        TestHelpers.WriteUInt32LittleEndian(bytes, 68, 1);
        AssertNotDetectedAs(bytes, "lnk");
    }

    [Fact]
    public void PcapNgRejectsNegativeDefinedSectionLengths()
    {
        byte[] bytes = PcapNg();
        for (int index = 16; index < 24; index++) bytes[index] = 0xFF;
        bytes[16] = 0xFE;
        AssertNotDetectedAs(bytes, "pcapng");
    }

    [Fact]
    public void BmpValidatesDibFieldsAndPixelPayload()
    {
        byte[] bytes = Bmp();
        TestHelpers.WriteUInt16LittleEndian(bytes, 22, 2);
        AssertNotDetectedAs(bytes, "bmp");
        Array.Resize(ref bytes, 29);
        TestHelpers.WriteUInt32LittleEndian(bytes, 2, 29);
        AssertNotDetectedAs(bytes, "bmp");
    }

    private static void AssertNotDetectedAs(byte[] bytes, string extension)
    {
        Assert.NotEqual(extension, FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false);
        Assert.NotEqual(extension, FileInspector.Detect(stream)?.Extension);
    }

    private static byte[] FatMachO()
    {
        var bytes = new byte[96];
        TestHelpers.WriteUInt32BigEndian(bytes, 0, 0xCAFEBABF);
        TestHelpers.WriteUInt32BigEndian(bytes, 4, 1);
        TestHelpers.WriteUInt32BigEndian(bytes, 8, 0x01000007);
        TestHelpers.WriteUInt32BigEndian(bytes, 12, 3);
        TestHelpers.WriteUInt64BigEndian(bytes, 16, 64);
        TestHelpers.WriteUInt64BigEndian(bytes, 24, 32);
        TestHelpers.WriteUInt32BigEndian(bytes, 32, 6);
        new byte[] { 0xCF, 0xFA, 0xED, 0xFE }.CopyTo(bytes, 64);
        TestHelpers.WriteUInt32LittleEndian(bytes, 68, 0x01000007);
        TestHelpers.WriteUInt32LittleEndian(bytes, 72, 3);
        TestHelpers.WriteUInt32LittleEndian(bytes, 76, 1);
        return bytes;
    }

    private static byte[] WoffWithMetadata()
    {
        var bytes = new byte[72];
        Encoding.ASCII.GetBytes("wOFFtrue").CopyTo(bytes, 0);
        TestHelpers.WriteUInt32BigEndian(bytes, 8, 72);
        TestHelpers.WriteUInt16BigEndian(bytes, 12, 1);
        TestHelpers.WriteUInt32BigEndian(bytes, 16, 32);
        TestHelpers.WriteUInt32BigEndian(bytes, 24, 68);
        TestHelpers.WriteUInt32BigEndian(bytes, 28, 4);
        TestHelpers.WriteUInt32BigEndian(bytes, 32, 4);
        Encoding.ASCII.GetBytes("head").CopyTo(bytes, 44);
        TestHelpers.WriteUInt32BigEndian(bytes, 48, 64);
        TestHelpers.WriteUInt32BigEndian(bytes, 52, 4);
        TestHelpers.WriteUInt32BigEndian(bytes, 56, 4);
        return bytes;
    }

    private static byte[] SfntWithDuplicateTables()
    {
        var bytes = new byte[52];
        TestHelpers.WriteUInt32BigEndian(bytes, 0, 0x00010000);
        TestHelpers.WriteUInt16BigEndian(bytes, 4, 2);
        TestHelpers.WriteUInt16BigEndian(bytes, 6, 32);
        TestHelpers.WriteUInt16BigEndian(bytes, 8, 1);
        Encoding.ASCII.GetBytes("head").CopyTo(bytes, 12);
        Encoding.ASCII.GetBytes("head").CopyTo(bytes, 28);
        TestHelpers.WriteUInt32BigEndian(bytes, 20, 44);
        TestHelpers.WriteUInt32BigEndian(bytes, 24, 4);
        TestHelpers.WriteUInt32BigEndian(bytes, 36, 48);
        TestHelpers.WriteUInt32BigEndian(bytes, 40, 4);
        return bytes;
    }

    private static byte[] Tiff()
    {
        var bytes = new byte[40];
        Encoding.ASCII.GetBytes("II").CopyTo(bytes, 0);
        TestHelpers.WriteUInt16LittleEndian(bytes, 2, 42);
        TestHelpers.WriteUInt32LittleEndian(bytes, 4, 8);
        TestHelpers.WriteUInt16LittleEndian(bytes, 8, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, 10, 256);
        TestHelpers.WriteUInt16LittleEndian(bytes, 12, 4);
        TestHelpers.WriteUInt32LittleEndian(bytes, 14, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 18, 1);
        return bytes;
    }

    private static byte[] Cab()
    {
        const int dataOffset = 66;
        var bytes = new byte[75];
        Encoding.ASCII.GetBytes("MSCF").CopyTo(bytes, 0);
        TestHelpers.WriteUInt32LittleEndian(bytes, 8, (uint)bytes.Length);
        TestHelpers.WriteUInt32LittleEndian(bytes, 16, 48);
        bytes[24] = 3; bytes[25] = 1;
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

    private static byte[] Qcow2()
    {
        var bytes = new byte[2048];
        new byte[] { (byte)'Q', (byte)'F', (byte)'I', 0xFB }.CopyTo(bytes, 0);
        TestHelpers.WriteUInt32BigEndian(bytes, 4, 3);
        TestHelpers.WriteUInt32BigEndian(bytes, 20, 9);
        TestHelpers.WriteUInt64BigEndian(bytes, 24, 1024 * 1024);
        TestHelpers.WriteUInt32BigEndian(bytes, 36, 4);
        TestHelpers.WriteUInt64BigEndian(bytes, 40, 512);
        TestHelpers.WriteUInt64BigEndian(bytes, 48, 1024);
        TestHelpers.WriteUInt32BigEndian(bytes, 56, 1);
        TestHelpers.WriteUInt32BigEndian(bytes, 100, 104);
        return bytes;
    }

    private static byte[] DdsDx10()
    {
        var bytes = new byte[148];
        Encoding.ASCII.GetBytes("DDS ").CopyTo(bytes, 0);
        TestHelpers.WriteUInt32LittleEndian(bytes, 4, 124);
        TestHelpers.WriteUInt32LittleEndian(bytes, 8, 0x1007);
        TestHelpers.WriteUInt32LittleEndian(bytes, 12, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 16, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 76, 32);
        TestHelpers.WriteUInt32LittleEndian(bytes, 80, 4);
        Encoding.ASCII.GetBytes("DX10").CopyTo(bytes, 84);
        TestHelpers.WriteUInt32LittleEndian(bytes, 108, 0x1000);
        TestHelpers.WriteUInt32LittleEndian(bytes, 128, 28);
        TestHelpers.WriteUInt32LittleEndian(bytes, 132, 3);
        TestHelpers.WriteUInt32LittleEndian(bytes, 140, 1);
        return bytes;
    }

    private static byte[] MatroskaWithEbmlVersion(byte version)
    {
        byte[] documentType = Encoding.ASCII.GetBytes("matroska");
        var bytes = new byte[4 + 1 + 4 + 3 + documentType.Length + 5];
        new byte[] { 0x1A, 0x45, 0xDF, 0xA3, (byte)(0x80 | (7 + documentType.Length)), 0x42, 0x86, 0x81, version, 0x42, 0x82,
            (byte)(0x80 | documentType.Length) }.CopyTo(bytes, 0);
        documentType.CopyTo(bytes, 12);
        new byte[] { 0x18, 0x53, 0x80, 0x67, 0x80 }.CopyTo(bytes, 12 + documentType.Length);
        return bytes;
    }

    private static byte[] ShellLink()
    {
        var bytes = new byte[80];
        bytes[0] = 0x4C;
        new byte[] { 0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46 }.CopyTo(bytes, 4);
        TestHelpers.WriteUInt32LittleEndian(bytes, 60, 1);
        return bytes;
    }

    private static byte[] PcapNg()
    {
        var bytes = new byte[28];
        new byte[] { 0x0A, 0x0D, 0x0D, 0x0A }.CopyTo(bytes, 0);
        TestHelpers.WriteUInt32LittleEndian(bytes, 4, 28);
        new byte[] { 0x4D, 0x3C, 0x2B, 0x1A }.CopyTo(bytes, 8);
        TestHelpers.WriteUInt16LittleEndian(bytes, 12, 1);
        for (int index = 16; index < 24; index++) bytes[index] = 0xFF;
        TestHelpers.WriteUInt32LittleEndian(bytes, 24, 28);
        return bytes;
    }

    private static byte[] Bmp()
    {
        var bytes = new byte[30];
        Encoding.ASCII.GetBytes("BM").CopyTo(bytes, 0);
        TestHelpers.WriteUInt32LittleEndian(bytes, 2, 30);
        TestHelpers.WriteUInt32LittleEndian(bytes, 10, 26);
        TestHelpers.WriteUInt32LittleEndian(bytes, 14, 12);
        TestHelpers.WriteUInt16LittleEndian(bytes, 18, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, 20, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, 22, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, 24, 24);
        return bytes;
    }

    private static ulong ReadUInt64LittleEndian(byte[] bytes, int offset)
    {
        ulong value = 0;
        for (int index = 0; index < 8; index++) value |= (ulong)bytes[offset + index] << (index * 8);
        return value;
    }
}
