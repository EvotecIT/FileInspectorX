using System;
using System.IO;
using System.Linq;
using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class ThirteenthReviewRegressionTests
{
    [Fact]
    public void PeRequiresTheDeclaredSectionTableToFitTheCompleteFile()
    {
        var valid = TestHelpers.CreateMinimalPe();
        Assert.Equal("exe", FileInspector.Detect(valid)?.Extension);

        var truncated = valid.Take(415).ToArray();
        Assert.NotEqual("exe", FileInspector.Detect(truncated)?.Extension);
    }

    [Fact]
    public void ElfRequiresDeclaredProgramAndSectionTablesToFitTheCompleteFile()
    {
        var bytes = MinimalElf64();
        Assert.Equal("elf", FileInspector.Detect(bytes)?.Extension);

        TestHelpers.WriteUInt16LittleEndian(bytes, 56, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 32, 64);
        Assert.NotEqual("elf", FileInspector.Detect(bytes)?.Extension);
    }

    [Fact]
    public void OpenExrValidatesMandatoryAttributeTypesAndValues()
    {
        var valid = TestHelpers.CreateMinimalOpenExr();
        Assert.Equal("exr", FileInspector.Detect(valid)?.Extension);

        var invalid = (byte[])valid.Clone();
        int type = IndexOf(invalid, Encoding.ASCII.GetBytes("chlist"));
        Assert.True(type > 0);
        invalid[type] = (byte)'x';
        Assert.NotEqual("exr", FileInspector.Detect(invalid)?.Extension);
    }

    [Fact]
    public void VhdxRequiresChecksummedHeaderAndRegionStructures()
    {
        var valid = TestHelpers.CreateMinimalVhdx();
        Assert.Equal("vhdx", FileInspector.Detect(valid)?.Extension);

        var invalid = (byte[])valid.Clone();
        invalid[64 * 1024 + 80] ^= 1;
        Assert.NotEqual("vhdx", FileInspector.Detect(invalid)?.Extension);
    }

    [Fact]
    public void PhotoshopRequiresAllLengthPrefixedSectionsAndCompression()
    {
        var valid = TestHelpers.CreateMinimalPhotoshop();
        Assert.Equal("psd", FileInspector.Detect(valid)?.Extension);
        Assert.NotEqual("psd", FileInspector.Detect(valid.Take(26).ToArray())?.Extension);
    }

    [Fact]
    public void ParquetRequiresCompactProtocolFileMetadata()
    {
        var valid = TestHelpers.CreateMinimalParquet();
        Assert.Equal("parquet", FileInspector.Detect(valid)?.Extension);

        var invalid = (byte[])valid.Clone();
        invalid[4] = 0;
        Assert.NotEqual("parquet", FileInspector.Detect(invalid)?.Extension);
    }

    [Fact]
    public void ArrowRequiresAValidFooterTableAndSchema()
    {
        var valid = TestHelpers.CreateMinimalArrow();
        Assert.Equal("arrow", FileInspector.Detect(valid)?.Extension);

        var invalid = (byte[])valid.Clone();
        invalid[8 + 16] = 0;
        Assert.NotEqual("arrow", FileInspector.Detect(invalid)?.Extension);
    }

    [Fact]
    public void OutlookNdbRequiresTheCompleteHeaderAndBothCrcs()
    {
        var valid = TestHelpers.CreateMinimalOutlookNdb();
        Assert.Equal("ndb", FileInspector.Detect(valid)?.Extension);
        Assert.NotEqual("ndb", FileInspector.Detect(valid.Take(24).ToArray())?.Extension);

        var invalid = (byte[])valid.Clone();
        invalid[100] ^= 1;
        Assert.NotEqual("ndb", FileInspector.Detect(invalid)?.Extension);
    }

    [Fact]
    public void Jpeg2000RequiresBrandSpecificHeaderAndDataBoxes()
    {
        var valid = TestHelpers.CreateMinimalJpeg2000();
        Assert.Equal("jp2", FileInspector.Detect(valid)?.Extension);
        Assert.NotEqual("jp2", FileInspector.Detect(valid.Take(32).ToArray())?.Extension);
    }

    [Fact]
    public void DexRequiresItsSignatureAndChecksumForCompleteInputs()
    {
        var valid = TestHelpers.CreateMinimalDex();
        Assert.Equal("dex", FileInspector.Detect(valid)?.Extension);

        var invalid = (byte[])valid.Clone();
        invalid[50] ^= 1;
        Assert.NotEqual("dex", FileInspector.Detect(invalid)?.Extension);
        using var stream = new MemoryStream(invalid, writable: false);
        Assert.NotEqual("dex", FileInspector.Detect(stream)?.Extension);
    }

    private static byte[] MinimalElf64()
    {
        var bytes = new byte[64];
        new byte[] { 0x7F, (byte)'E', (byte)'L', (byte)'F', 2, 1, 1 }.CopyTo(bytes, 0);
        TestHelpers.WriteUInt16LittleEndian(bytes, 16, 2);
        TestHelpers.WriteUInt16LittleEndian(bytes, 18, 62);
        TestHelpers.WriteUInt32LittleEndian(bytes, 20, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, 52, 64);
        TestHelpers.WriteUInt16LittleEndian(bytes, 54, 56);
        TestHelpers.WriteUInt16LittleEndian(bytes, 58, 64);
        return bytes;
    }

    private static int IndexOf(byte[] source, byte[] value)
    {
        for (int offset = 0; offset <= source.Length - value.Length; offset++)
            if (source.Skip(offset).Take(value.Length).SequenceEqual(value)) return offset;
        return -1;
    }
}
