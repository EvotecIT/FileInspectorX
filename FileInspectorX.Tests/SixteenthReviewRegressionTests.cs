using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

[Collection(nameof(DetectionSettingsCollection))]
public sealed class SixteenthReviewRegressionTests
{
    [Fact]
    public void OpenExrValidatesEveryMultipartHeaderAndModernCompressionValues()
    {
        var valid = TestHelpers.CreateMinimalMultipartOpenExr();
        Assert.Equal("exr", FileInspector.Detect(valid)?.Extension);

        var invalid = (byte[])valid.Clone();
        byte[] compression = Encoding.ASCII.GetBytes("compression\0compression\0");
        int second = NthIndexOf(invalid, compression, 2);
        Assert.True(second > 0);
        invalid[second + compression.Length + 4] = 0xFF;
        Assert.NotEqual("exr", FileInspector.Detect(invalid)?.Extension);
    }

    [Fact]
    public void OversizedParquetAndArrowFootersRetainFramedIdentityAtMediumConfidence()
    {
        int originalBudget = Settings.DetectionReadBudgetBytes;
        try
        {
            Settings.DetectionReadBudgetBytes = 256;
            AssertBudgetedFooter(FramedParquet(300), "parquet", "parquet:framed;footer-budget");
            AssertBudgetedFooter(FramedArrow(300), "arrow", "arrow-ipc:framed;footer-budget");
        }
        finally
        {
            Settings.DetectionReadBudgetBytes = originalBudget;
        }
    }

    [Fact]
    public void SeekablePhotoshopAndJpeg2000WalkStructuresBeyondThePrefix()
    {
        AssertSeekableParity(LargePhotoshop(), "psd");
        AssertSeekableParity(LargeJpeg2000(), "jp2");
    }

    [Fact]
    public void SingleRecordVariableMayUseItsUnpaddedNetCdfSize()
        => Assert.Equal("nc", FileInspector.Detect(SingleUnpaddedRecordVariable())?.Extension);

    [Fact]
    public void ShellLinkRequiresItsTerminalExtraDataBlock()
    {
        var valid = MinimalShellLink();
        Assert.Equal("lnk", FileInspector.Detect(valid)?.Extension);
        Assert.NotEqual("lnk", FileInspector.Detect(valid.Take(76).ToArray())?.Extension);
    }

    [Fact]
    public void FtypOnlyFileRetainsIdentityAtReducedConfidence()
    {
        var bytes = new byte[16];
        WriteUInt32BigEndian(bytes, 0, 16);
        Encoding.ASCII.GetBytes("ftypmp42").CopyTo(bytes, 4);

        var result = FileInspector.Detect(bytes);
        Assert.Equal("mp4", result?.Extension);
        Assert.Equal("Medium", result?.Confidence);
        Assert.Contains("ftyp-only", result?.Reason);
    }

    [Fact]
    public void FatMachORequiresMatchingThinSliceHeaders()
    {
        var valid = FatMachO();
        Assert.Equal("macho", FileInspector.Detect(valid)?.Extension);

        var invalid = (byte[])valid.Clone();
        WriteUInt32LittleEndian(invalid, 68, 0x0100000C);
        Assert.NotEqual("macho", FileInspector.Detect(invalid)?.Extension);
    }

    [Fact]
    public void Woff2AcceptsTheSpecifiedZeroLengthLocaTransform()
        => Assert.Equal("woff2", FileInspector.Detect(Woff2WithZeroLengthLoca())?.Extension);

    [Fact]
    public void Crx3RequiresProofsAndSignedHeaderData()
    {
        var valid = TestHelpers.CreateMinimalCrx3();
        Assert.Equal("crx", FileInspector.Detect(valid)?.Extension);

        var invalid = (byte[])valid.Clone();
        invalid[17] = 0x1A;
        Assert.NotEqual("crx", FileInspector.Detect(invalid)?.Extension);
    }

    [Fact]
    public void PngRequiresValidChunkCrcsAndTheIendSequence()
    {
        var valid = TestHelpers.CreateMinimalPng();
        Assert.Equal("png", FileInspector.Detect(valid)?.Extension);

        var badCrc = (byte[])valid.Clone();
        badCrc[41] ^= 1;
        Assert.NotEqual("png", FileInspector.Detect(badCrc)?.Extension);
        Assert.NotEqual("png", FileInspector.Detect(valid.Take(valid.Length - 12).ToArray())?.Extension);
    }

    [Fact]
    public void PeRejectsUnknownMachineValues()
    {
        var bytes = TestHelpers.CreateMinimalPe();
        WriteUInt16LittleEndian(bytes, 0x84, 0);
        Assert.NotEqual("exe", FileInspector.Detect(bytes)?.Extension);
    }

    private static void AssertBudgetedFooter(byte[] bytes, string extension, string reason)
    {
        using var stream = new MemoryStream(bytes, writable: false);
        var result = FileInspector.Detect(stream);
        Assert.Equal(extension, result?.Extension);
        Assert.Equal("Medium", result?.Confidence);
        Assert.Equal(reason, result?.Reason);
    }

    private static void AssertSeekableParity(byte[] bytes, string extension)
    {
        Assert.True(bytes.Length > Settings.HeaderReadBytes);
        using var stream = new MemoryStream(bytes, writable: false);
        Assert.Equal(extension, FileInspector.Detect(stream)?.Extension);
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".bin");
        try
        {
            File.WriteAllBytes(path, bytes);
            Assert.Equal(extension, FileInspector.Detect(path)?.Extension);
        }
        finally
        {
            TestHelpers.SafeDelete(path);
        }
    }

    private static byte[] FramedParquet(int footerLength)
    {
        var bytes = new byte[4 + footerLength + 8];
        Encoding.ASCII.GetBytes("PAR1").CopyTo(bytes, 0);
        WriteUInt32LittleEndian(bytes, bytes.Length - 8, (uint)footerLength);
        Encoding.ASCII.GetBytes("PAR1").CopyTo(bytes, bytes.Length - 4);
        return bytes;
    }

    private static byte[] FramedArrow(int footerLength)
    {
        var bytes = new byte[8 + footerLength + 10];
        Encoding.ASCII.GetBytes("ARROW1").CopyTo(bytes, 0);
        WriteUInt32LittleEndian(bytes, bytes.Length - 10, (uint)footerLength);
        Encoding.ASCII.GetBytes("ARROW1").CopyTo(bytes, bytes.Length - 6);
        return bytes;
    }

    private static byte[] LargePhotoshop()
    {
        const int colorModeDataLength = 5000;
        var bytes = new byte[26 + 4 + colorModeDataLength + 4 + 4 + 2 + 3];
        Encoding.ASCII.GetBytes("8BPS").CopyTo(bytes, 0);
        WriteUInt16BigEndian(bytes, 4, 1);
        WriteUInt16BigEndian(bytes, 12, 3);
        WriteUInt32BigEndian(bytes, 14, 1);
        WriteUInt32BigEndian(bytes, 18, 1);
        WriteUInt16BigEndian(bytes, 22, 8);
        WriteUInt16BigEndian(bytes, 24, 3);
        WriteUInt32BigEndian(bytes, 26, colorModeDataLength);
        return bytes;
    }

    private static byte[] LargeJpeg2000()
    {
        const int freeLength = 5000;
        byte[] minimal = TestHelpers.CreateMinimalJpeg2000();
        var bytes = new byte[minimal.Length + freeLength];
        Array.Copy(minimal, 0, bytes, 0, 32);
        WriteUInt32BigEndian(bytes, 32, freeLength);
        Encoding.ASCII.GetBytes("free").CopyTo(bytes, 36);
        Array.Copy(minimal, 32, bytes, 32 + freeLength, minimal.Length - 32);
        return bytes;
    }

    private static byte[] SingleUnpaddedRecordVariable()
    {
        var bytes = new byte[82];
        Encoding.ASCII.GetBytes("CDF").CopyTo(bytes, 0);
        bytes[3] = 1;
        WriteUInt32BigEndian(bytes, 4, 2);
        WriteUInt32BigEndian(bytes, 8, 10);
        WriteUInt32BigEndian(bytes, 12, 1);
        WriteUInt32BigEndian(bytes, 16, 1);
        bytes[20] = (byte)'x';
        WriteUInt32BigEndian(bytes, 24, 0);
        WriteUInt32BigEndian(bytes, 36, 11);
        WriteUInt32BigEndian(bytes, 40, 1);
        WriteUInt32BigEndian(bytes, 44, 1);
        bytes[48] = (byte)'v';
        WriteUInt32BigEndian(bytes, 52, 1);
        WriteUInt32BigEndian(bytes, 56, 0);
        WriteUInt32BigEndian(bytes, 68, 1);
        WriteUInt32BigEndian(bytes, 72, 1);
        WriteUInt32BigEndian(bytes, 76, 80);
        return bytes;
    }

    private static byte[] MinimalShellLink()
    {
        var bytes = new byte[80];
        bytes[0] = 0x4C;
        new byte[] { 0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46 }.CopyTo(bytes, 4);
        WriteUInt32LittleEndian(bytes, 60, 1);
        return bytes;
    }

    private static byte[] FatMachO()
    {
        var bytes = new byte[96];
        new byte[] { 0xCA, 0xFE, 0xBA, 0xBF }.CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 4, 1);
        WriteUInt32BigEndian(bytes, 8, 0x01000007);
        WriteUInt64BigEndian(bytes, 16, 64);
        WriteUInt64BigEndian(bytes, 24, 32);
        WriteUInt32BigEndian(bytes, 32, 6);
        new byte[] { 0xCF, 0xFA, 0xED, 0xFE }.CopyTo(bytes, 64);
        WriteUInt32LittleEndian(bytes, 68, 0x01000007);
        WriteUInt32LittleEndian(bytes, 72, 0);
        WriteUInt32LittleEndian(bytes, 76, 1);
        return bytes;
    }

    private static byte[] Woff2WithZeroLengthLoca()
    {
        var bytes = new byte[58];
        Encoding.ASCII.GetBytes("wOF2OTTO").CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 8, (uint)bytes.Length);
        WriteUInt16BigEndian(bytes, 12, 2);
        WriteUInt32BigEndian(bytes, 16, 44);
        WriteUInt32BigEndian(bytes, 20, 4);
        bytes[48] = 0x0A; bytes[49] = 4; bytes[50] = 4;
        bytes[51] = 0x0B; bytes[52] = 4; bytes[53] = 0;
        return bytes;
    }

    private static int NthIndexOf(byte[] source, byte[] value, int occurrence)
    {
        int found = 0;
        for (int offset = 0; offset <= source.Length - value.Length; offset++)
        {
            bool equal = true;
            for (int index = 0; index < value.Length; index++) equal &= source[offset + index] == value[index];
            if (equal && ++found == occurrence) return offset;
        }
        return -1;
    }

    private static void WriteUInt16LittleEndian(byte[] bytes, int offset, ushort value)
    {
        bytes[offset] = (byte)value;
        bytes[offset + 1] = (byte)(value >> 8);
    }

    private static void WriteUInt16BigEndian(byte[] bytes, int offset, ushort value)
    {
        bytes[offset] = (byte)(value >> 8);
        bytes[offset + 1] = (byte)value;
    }

    private static void WriteUInt32LittleEndian(byte[] bytes, int offset, uint value)
    {
        for (int index = 0; index < 4; index++) bytes[offset + index] = (byte)(value >> (8 * index));
    }

    private static void WriteUInt32BigEndian(byte[] bytes, int offset, uint value)
    {
        for (int index = 0; index < 4; index++) bytes[offset + index] = (byte)(value >> (8 * (3 - index)));
    }

    private static void WriteUInt64BigEndian(byte[] bytes, int offset, ulong value)
    {
        for (int index = 0; index < 8; index++) bytes[offset + index] = (byte)(value >> (8 * (7 - index)));
    }
}
