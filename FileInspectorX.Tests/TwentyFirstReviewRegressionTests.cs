using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

[Collection(nameof(DetectionSettingsCollection))]
public sealed class TwentyFirstReviewRegressionTests
{
    [Fact]
    public void PhotoshopZlibHeaderAloneNeverClaimsCompleteImageValidation()
    {
        byte[] bytes = PhotoshopWithZlibHeaderOnly();
        var result = FileInspector.Detect(bytes);

        Assert.Equal("psd", result?.Extension);
        Assert.Equal("Medium", result?.Confidence);
        Assert.Contains("sampled-image-data", result?.Reason);
        using var stream = new MemoryStream(bytes, writable: false);
        var fromStream = FileInspector.Detect(stream);
        Assert.Equal("psd", fromStream?.Extension);
        Assert.Equal("Medium", fromStream?.Confidence);
    }

    [Theory]
    [InlineData(56)]
    [InlineData(60)]
    [InlineData(80)]
    [InlineData(84)]
    public void PeRequiresMandatoryOptionalHeaderLayoutFields(int fieldOffset)
    {
        Assert.Equal("exe", FileInspector.Detect(TestHelpers.CreateMinimalPe())?.Extension);
        byte[] invalid = TestHelpers.CreateMinimalPe();
        WriteUInt32LittleEndian(invalid, 0x80 + fieldOffset, 0);
        Assert.NotEqual("exe", FileInspector.Detect(invalid)?.Extension);
    }

    [Fact]
    public void SeekableDicomContinuesPastTheConfiguredHeaderPrefix()
    {
        byte[] bytes = TestHelpers.CreateMinimalDicom(metaLength: 5000, totalLength: 6000);
        Assert.Equal("dcm", FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false) { Position = 7 };

        var result = FileInspector.Detect(stream);

        Assert.Equal("dcm", result?.Extension);
        Assert.Equal("Medium", result?.Confidence);
        Assert.Equal(7, stream.Position);
    }

    [Fact]
    public void NetCdfRejectsOverlappingFixedVariableRanges()
    {
        Assert.Equal("nc", FileInspector.Detect(NetCdfWithTwoFixedVariables(overlap: false))?.Extension);
        Assert.NotEqual("nc", FileInspector.Detect(NetCdfWithTwoFixedVariables(overlap: true))?.Extension);
    }

    [Fact]
    public void OpenExrRequiresChunkFramingBeforeCompleteIdentity()
    {
        byte[] valid = TestHelpers.CreateMinimalOpenExr();
        Assert.Equal("Medium", FileInspector.Detect(valid)?.Confidence);
        Assert.Contains("chunk-payloads-not-validated", FileInspector.Detect(valid)?.Reason);
        byte[] headerOnly = valid.Take(valid.Length - 20).ToArray();
        Assert.NotEqual("High", FileInspector.Detect(headerOnly)?.Confidence);
    }

    [Fact]
    public void SeekableJpeg2000BoxWalkHonorsTheReadBudget()
    {
        byte[] bytes = Jpeg2000WithManyBoxes(100);
        Assert.Equal("High", FileInspector.Detect(bytes)?.Confidence);
        int originalBudget = Settings.DetectionReadBudgetBytes;
        try
        {
            Settings.DetectionReadBudgetBytes = 64;
            using var stream = new MemoryStream(bytes, writable: false) { Position = 3 };

            var result = FileInspector.Detect(stream);

            Assert.Equal("jp2", result?.Extension);
            Assert.Equal("Medium", result?.Confidence);
            Assert.Contains("box-budget", result?.Reason);
            Assert.Equal(3, stream.Position);
        }
        finally
        {
            Settings.DetectionReadBudgetBytes = originalBudget;
        }
    }

    [Fact]
    public void Crx3AcceptsTheSpecifiedRsaAndEcdsaProofFieldsOnly()
    {
        Assert.Equal("crx", FileInspector.Detect(TestHelpers.CreateMinimalCrx3())?.Extension);
        byte[] ecdsa = TestHelpers.CreateMinimalCrx3();
        ecdsa[12] = 0x1A;
        Assert.Equal("crx", FileInspector.Detect(ecdsa)?.Extension);
        byte[] obsoleteField = TestHelpers.CreateMinimalCrx3();
        obsoleteField[12] = 0x0A;
        Assert.NotEqual("crx", FileInspector.Detect(obsoleteField)?.Extension);
    }

    [Theory]
    [InlineData(0x40000u)]
    [InlineData(0x80000u)]
    public void DdsAcceptsDefinedLegacyBumpPixelFormats(uint pixelFormatFlag)
    {
        byte[] valid = LegacyBumpDds(pixelFormatFlag);
        Assert.Equal("dds", FileInspector.Detect(valid)?.Extension);
        valid[96] = valid[92];
        Assert.NotEqual("dds", FileInspector.Detect(valid)?.Extension);
    }

    [Fact]
    public void M4bMajorBrandPreservesAudiobookIdentity()
    {
        var bytes = new byte[16];
        WriteUInt32BigEndian(bytes, 0, 16);
        Encoding.ASCII.GetBytes("ftypM4B ").CopyTo(bytes, 4);

        var result = FileInspector.Detect(bytes);

        Assert.Equal("m4b", result?.Extension);
        Assert.Equal("audio/mp4", result?.MimeType);
        Assert.False(FileInspector.CompareDeclared("m4b", result).Mismatch);
    }

    private static byte[] PhotoshopWithZlibHeaderOnly()
    {
        var bytes = new byte[42];
        Encoding.ASCII.GetBytes("8BPS").CopyTo(bytes, 0);
        WriteUInt16BigEndian(bytes, 4, 1);
        WriteUInt16BigEndian(bytes, 12, 3);
        WriteUInt32BigEndian(bytes, 14, 1);
        WriteUInt32BigEndian(bytes, 18, 1);
        WriteUInt16BigEndian(bytes, 22, 8);
        WriteUInt16BigEndian(bytes, 24, 3);
        WriteUInt16BigEndian(bytes, 38, 2);
        bytes[40] = 0x78;
        bytes[41] = 0x9C;
        return bytes;
    }

    private static byte[] NetCdfWithTwoFixedVariables(bool overlap)
    {
        var bytes = new byte[132];
        Encoding.ASCII.GetBytes("CDF").CopyTo(bytes, 0);
        bytes[3] = 1;
        WriteUInt32BigEndian(bytes, 8, 10);
        WriteUInt32BigEndian(bytes, 12, 1);
        WriteUInt32BigEndian(bytes, 16, 1);
        bytes[20] = (byte)'x';
        WriteUInt32BigEndian(bytes, 24, 1);
        WriteUInt32BigEndian(bytes, 36, 11);
        WriteUInt32BigEndian(bytes, 40, 2);
        WriteNetCdfVariable(bytes, 44, (byte)'a', 120);
        WriteNetCdfVariable(bytes, 80, (byte)'b', overlap ? 120u : 124u);
        return bytes;
    }

    private static void WriteNetCdfVariable(byte[] bytes, int offset, byte name, uint begin)
    {
        WriteUInt32BigEndian(bytes, offset, 1);
        bytes[offset + 4] = name;
        WriteUInt32BigEndian(bytes, offset + 8, 1);
        WriteUInt32BigEndian(bytes, offset + 12, 0);
        WriteUInt32BigEndian(bytes, offset + 24, 4);
        WriteUInt32BigEndian(bytes, offset + 28, 4);
        WriteUInt32BigEndian(bytes, offset + 32, begin);
    }

    private static byte[] Jpeg2000WithManyBoxes(int count)
    {
        byte[] minimal = TestHelpers.CreateMinimalJpeg2000();
        var bytes = new byte[minimal.Length + count * 8];
        Array.Copy(minimal, bytes, minimal.Length);
        for (int index = 0; index < count; index++)
        {
            int offset = minimal.Length + index * 8;
            WriteUInt32BigEndian(bytes, offset, 8);
            Encoding.ASCII.GetBytes("free").CopyTo(bytes, offset + 4);
        }
        return bytes;
    }

    private static byte[] LegacyBumpDds(uint pixelFormatFlag)
    {
        var bytes = new byte[132];
        Encoding.ASCII.GetBytes("DDS ").CopyTo(bytes, 0);
        WriteUInt32LittleEndian(bytes, 4, 124);
        WriteUInt32LittleEndian(bytes, 8, 0x1007);
        WriteUInt32LittleEndian(bytes, 12, 1);
        WriteUInt32LittleEndian(bytes, 16, 1);
        WriteUInt32LittleEndian(bytes, 76, 32);
        WriteUInt32LittleEndian(bytes, 80, pixelFormatFlag);
        WriteUInt32LittleEndian(bytes, 88, pixelFormatFlag == 0x40000 ? 24u : 16u);
        WriteUInt32LittleEndian(bytes, 92, 0x00FF);
        WriteUInt32LittleEndian(bytes, 96, 0xFF00);
        if (pixelFormatFlag == 0x40000) WriteUInt32LittleEndian(bytes, 100, 0xFF0000);
        WriteUInt32LittleEndian(bytes, 108, 0x1000);
        return bytes;
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

    private static void WriteUInt32LittleEndian(byte[] bytes, int offset, uint value)
    {
        bytes[offset] = (byte)value;
        bytes[offset + 1] = (byte)(value >> 8);
        bytes[offset + 2] = (byte)(value >> 16);
        bytes[offset + 3] = (byte)(value >> 24);
    }
}
