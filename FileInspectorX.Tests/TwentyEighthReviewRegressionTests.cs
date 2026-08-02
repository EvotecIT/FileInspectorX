using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class TwentyEighthReviewRegressionTests
{
    [Theory]
    [InlineData("jp2 ", "jp2")]
    [InlineData("jpx ", "jpx")]
    public void Jpeg2000VariableComponentDepthsRequireValidBpcc(string brand, string extension)
    {
        AssertParity(Jpeg2000WithBpcc(brand, componentDepth: 7), extension);

        byte[] missing = TestHelpers.CreateMinimalJpeg2000(brand);
        missing[58] = 0xFF;
        AssertNotDetectedAs(missing, extension);
        AssertNotDetectedAs(Jpeg2000WithBpcc(brand, componentDepth: 0x7F), extension);
        byte[] unexpected = Jpeg2000WithBpcc(brand, componentDepth: 7);
        unexpected[58] = 7;
        AssertNotDetectedAs(unexpected, extension);
    }

    [Fact]
    public void WoffDirectoriesRejectDuplicateTableTags()
    {
        AssertParity(Woff1(duplicate: false), "woff");
        AssertNotDetectedAs(Woff1(duplicate: true), "woff");
        AssertParity(Woff2(duplicate: false), "woff2");
        AssertNotDetectedAs(Woff2(duplicate: true), "woff2");
    }

    [Fact]
    public void ClassicTiffRejectsBigTiffOnlyFieldTypes()
    {
        AssertParity(ClassicTiff(fieldType: 4), "tif");
        AssertNotDetectedAs(ClassicTiff(fieldType: 16), "tif");
        AssertNotDetectedAs(ClassicTiff(fieldType: 17), "tif");
        AssertNotDetectedAs(ClassicTiff(fieldType: 18), "tif");
    }

    [Fact]
    public void MultipartOpenExrUsesEachPartsChunkLayout()
    {
        byte[] mixed = TestHelpers.CreateMinimalMultipartOpenExr(secondPartTiled: true);
        AssertParity(mixed, "exr");

        byte[] wrongPart = (byte[])mixed.Clone();
        Array.Clear(wrongPart, wrongPart.Length - 28, 4);
        AssertNotDetectedAs(wrongPart, "exr");
    }

    [Fact]
    public void FatMachOSlicesRequireCompleteThinHeadersAndLoadCommands()
    {
        AssertParity(FatMachO(invalidFileType: false, invalidCommand: false), "macho");
        AssertNotDetectedAs(FatMachO(invalidFileType: true, invalidCommand: false), "macho");
        AssertNotDetectedAs(FatMachO(invalidFileType: false, invalidCommand: true), "macho");
    }

    [Fact]
    public void Qcow2VersionThreeRejectsUnsupportedRefcountOrder()
    {
        AssertParity(Qcow2(refcountOrder: 6), "qcow2");
        AssertNotDetectedAs(Qcow2(refcountOrder: 7), "qcow2");
    }

    [Fact]
    public void ParquetRejectsNegativeRowCounts()
    {
        byte[] valid = TestHelpers.CreateMinimalParquet();
        int rowValue = Find(valid, new byte[] { 0x16, 0x00 }) + 1;
        Assert.True(rowValue > 0);
        AssertParity(valid, "parquet");

        byte[] negative = (byte[])valid.Clone();
        negative[rowValue] = 0x01;
        AssertNotDetectedAs(negative, "parquet");
    }

    [Fact]
    public void NetCdfRejectsDuplicateVariableNames()
    {
        AssertParity(NetCdfWithTwoVariables(duplicate: false), "nc");
        AssertNotDetectedAs(NetCdfWithTwoVariables(duplicate: true), "nc");
        AssertParity(NetCdfWithTwoDimensions(duplicate: false), "nc");
        AssertNotDetectedAs(NetCdfWithTwoDimensions(duplicate: true), "nc");
        AssertParity(NetCdfWithTwoGlobalAttributes(duplicate: false), "nc");
        AssertNotDetectedAs(NetCdfWithTwoGlobalAttributes(duplicate: true), "nc");
    }

    private static byte[] Jpeg2000WithBpcc(string brand, byte componentDepth)
    {
        byte[] original = TestHelpers.CreateMinimalJpeg2000(brand);
        const int insertion = 62;
        var bytes = new byte[original.Length + 9];
        Array.Copy(original, 0, bytes, 0, insertion);
        Array.Copy(original, insertion, bytes, insertion + 9, original.Length - insertion);
        TestHelpers.WriteUInt32BigEndian(bytes, 32, 39);
        bytes[58] = 0xFF;
        TestHelpers.WriteUInt32BigEndian(bytes, insertion, 9);
        Encoding.ASCII.GetBytes("bpcc").CopyTo(bytes, insertion + 4);
        bytes[insertion + 8] = componentDepth;
        return bytes;
    }

    private static byte[] Woff1(bool duplicate)
    {
        var bytes = new byte[92];
        Encoding.ASCII.GetBytes("wOFF").CopyTo(bytes, 0);
        TestHelpers.WriteUInt32BigEndian(bytes, 4, 0x00010000);
        TestHelpers.WriteUInt32BigEndian(bytes, 8, (uint)bytes.Length);
        TestHelpers.WriteUInt16BigEndian(bytes, 12, 2);
        TestHelpers.WriteUInt32BigEndian(bytes, 16, 44);
        WriteWoff1Record(bytes, 44, "head", 84);
        WriteWoff1Record(bytes, 64, duplicate ? "head" : "name", 88);
        return bytes;
    }

    private static void WriteWoff1Record(byte[] bytes, int offset, string tag, uint tableOffset)
    {
        Encoding.ASCII.GetBytes(tag).CopyTo(bytes, offset);
        TestHelpers.WriteUInt32BigEndian(bytes, offset + 4, tableOffset);
        TestHelpers.WriteUInt32BigEndian(bytes, offset + 8, 4);
        TestHelpers.WriteUInt32BigEndian(bytes, offset + 12, 4);
    }

    private static byte[] Woff2(bool duplicate)
    {
        var bytes = new byte[53];
        Encoding.ASCII.GetBytes("wOF2").CopyTo(bytes, 0);
        TestHelpers.WriteUInt32BigEndian(bytes, 4, 0x00010000);
        TestHelpers.WriteUInt32BigEndian(bytes, 8, (uint)bytes.Length);
        TestHelpers.WriteUInt16BigEndian(bytes, 12, 2);
        TestHelpers.WriteUInt32BigEndian(bytes, 16, 44);
        TestHelpers.WriteUInt32BigEndian(bytes, 20, 1);
        bytes[48] = 1;
        bytes[49] = 1;
        bytes[50] = duplicate ? (byte)1 : (byte)5;
        bytes[51] = 1;
        bytes[52] = 0x80;
        return bytes;
    }

    private static byte[] ClassicTiff(ushort fieldType)
    {
        var bytes = new byte[40];
        Encoding.ASCII.GetBytes("II").CopyTo(bytes, 0);
        TestHelpers.WriteUInt16LittleEndian(bytes, 2, 42);
        TestHelpers.WriteUInt32LittleEndian(bytes, 4, 8);
        TestHelpers.WriteUInt16LittleEndian(bytes, 8, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, 10, 256);
        TestHelpers.WriteUInt16LittleEndian(bytes, 12, fieldType);
        TestHelpers.WriteUInt32LittleEndian(bytes, 14, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 18, 24);
        return bytes;
    }

    private static byte[] FatMachO(bool invalidFileType, bool invalidCommand)
    {
        const int sliceOffset = 4096;
        const int sliceSize = 36;
        var bytes = new byte[sliceOffset + sliceSize];
        TestHelpers.WriteUInt32BigEndian(bytes, 0, 0xCAFEBABE);
        TestHelpers.WriteUInt32BigEndian(bytes, 4, 1);
        TestHelpers.WriteUInt32BigEndian(bytes, 8, 7);
        TestHelpers.WriteUInt32BigEndian(bytes, 12, 3);
        TestHelpers.WriteUInt32BigEndian(bytes, 16, sliceOffset);
        TestHelpers.WriteUInt32BigEndian(bytes, 20, sliceSize);
        TestHelpers.WriteUInt32BigEndian(bytes, 24, 12);
        TestHelpers.WriteUInt32BigEndian(bytes, sliceOffset, 0xFEEDFACE);
        TestHelpers.WriteUInt32BigEndian(bytes, sliceOffset + 4, 7);
        TestHelpers.WriteUInt32BigEndian(bytes, sliceOffset + 8, 3);
        TestHelpers.WriteUInt32BigEndian(bytes, sliceOffset + 12, invalidFileType ? 0u : 1u);
        TestHelpers.WriteUInt32BigEndian(bytes, sliceOffset + 16, 1);
        TestHelpers.WriteUInt32BigEndian(bytes, sliceOffset + 20, 8);
        TestHelpers.WriteUInt32BigEndian(bytes, sliceOffset + 28, invalidCommand ? 0u : 1u);
        TestHelpers.WriteUInt32BigEndian(bytes, sliceOffset + 32, 8);
        return bytes;
    }

    private static byte[] Qcow2(uint refcountOrder)
    {
        var bytes = new byte[2048];
        new byte[] { (byte)'Q', (byte)'F', (byte)'I', 0xFB }.CopyTo(bytes, 0);
        TestHelpers.WriteUInt32BigEndian(bytes, 4, 3);
        TestHelpers.WriteUInt32BigEndian(bytes, 20, 9);
        TestHelpers.WriteUInt64BigEndian(bytes, 24, 32768);
        TestHelpers.WriteUInt32BigEndian(bytes, 36, 1);
        TestHelpers.WriteUInt64BigEndian(bytes, 40, 512);
        TestHelpers.WriteUInt64BigEndian(bytes, 48, 1024);
        TestHelpers.WriteUInt32BigEndian(bytes, 56, 1);
        TestHelpers.WriteUInt32BigEndian(bytes, 96, refcountOrder);
        TestHelpers.WriteUInt32BigEndian(bytes, 100, 104);
        return bytes;
    }

    private static byte[] NetCdfWithTwoVariables(bool duplicate)
    {
        var bytes = new byte[128];
        Encoding.ASCII.GetBytes("CDF").CopyTo(bytes, 0);
        bytes[3] = 1;
        TestHelpers.WriteUInt32BigEndian(bytes, 8, 10);
        TestHelpers.WriteUInt32BigEndian(bytes, 12, 1);
        TestHelpers.WriteUInt32BigEndian(bytes, 16, 1);
        bytes[20] = (byte)'x';
        TestHelpers.WriteUInt32BigEndian(bytes, 24, 1);
        TestHelpers.WriteUInt32BigEndian(bytes, 36, 11);
        TestHelpers.WriteUInt32BigEndian(bytes, 40, 2);
        WriteNetCdfVariable(bytes, 44, (byte)'a', 120);
        WriteNetCdfVariable(bytes, 80, duplicate ? (byte)'a' : (byte)'b', 124);
        return bytes;
    }

    private static byte[] NetCdfWithTwoDimensions(bool duplicate)
    {
        var bytes = new byte[56];
        Encoding.ASCII.GetBytes("CDF").CopyTo(bytes, 0);
        bytes[3] = 1;
        TestHelpers.WriteUInt32BigEndian(bytes, 8, 10);
        TestHelpers.WriteUInt32BigEndian(bytes, 12, 2);
        WriteNetCdfName(bytes, 16, (byte)'x');
        TestHelpers.WriteUInt32BigEndian(bytes, 24, 1);
        WriteNetCdfName(bytes, 28, duplicate ? (byte)'x' : (byte)'y');
        TestHelpers.WriteUInt32BigEndian(bytes, 36, 1);
        return bytes;
    }

    private static byte[] NetCdfWithTwoGlobalAttributes(bool duplicate)
    {
        var bytes = new byte[72];
        Encoding.ASCII.GetBytes("CDF").CopyTo(bytes, 0);
        bytes[3] = 1;
        TestHelpers.WriteUInt32BigEndian(bytes, 16, 12);
        TestHelpers.WriteUInt32BigEndian(bytes, 20, 2);
        WriteNetCdfAttribute(bytes, 24, (byte)'a');
        WriteNetCdfAttribute(bytes, 44, duplicate ? (byte)'a' : (byte)'b');
        return bytes;
    }

    private static void WriteNetCdfAttribute(byte[] bytes, int offset, byte name)
    {
        WriteNetCdfName(bytes, offset, name);
        TestHelpers.WriteUInt32BigEndian(bytes, offset + 8, 1);
        TestHelpers.WriteUInt32BigEndian(bytes, offset + 12, 1);
        bytes[offset + 16] = 1;
    }

    private static void WriteNetCdfName(byte[] bytes, int offset, byte name)
    {
        TestHelpers.WriteUInt32BigEndian(bytes, offset, 1);
        bytes[offset + 4] = name;
    }

    private static void WriteNetCdfVariable(byte[] bytes, int offset, byte name, uint begin)
    {
        TestHelpers.WriteUInt32BigEndian(bytes, offset, 1);
        bytes[offset + 4] = name;
        TestHelpers.WriteUInt32BigEndian(bytes, offset + 8, 1);
        TestHelpers.WriteUInt32BigEndian(bytes, offset + 24, 4);
        TestHelpers.WriteUInt32BigEndian(bytes, offset + 28, 4);
        TestHelpers.WriteUInt32BigEndian(bytes, offset + 32, begin);
    }

    private static int Find(byte[] haystack, byte[] needle)
    {
        for (int offset = 0; offset <= haystack.Length - needle.Length; offset++)
        {
            bool match = true;
            for (int index = 0; index < needle.Length; index++) match &= haystack[offset + index] == needle[index];
            if (match) return offset;
        }
        return -1;
    }

    private static void AssertParity(byte[] bytes, string extension)
    {
        Assert.Equal(extension, FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false) { Position = Math.Min(3, bytes.Length) };
        Assert.Equal(extension, FileInspector.Detect(stream)?.Extension);
        Assert.Equal(Math.Min(3, bytes.Length), stream.Position);
    }

    private static void AssertNotDetectedAs(byte[] bytes, string extension)
    {
        Assert.NotEqual(extension, FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false);
        Assert.NotEqual(extension, FileInspector.Detect(stream)?.Extension);
    }
}
