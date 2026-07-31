using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class FourthReviewRegressionTests
{
    [Theory]
    [InlineData((byte)0)]
    [InlineData((byte)1)]
    public void LegacyHdf5WithSixteenByteOffsetsKeepsApiParity(byte version)
        => AssertParity(LegacyHdf5WithSixteenByteOffsets(version), "h5");

    [Fact]
    public void NonCanonicalWoff2ReservedFieldIsRecognizedAtReducedConfidence()
    {
        var bytes = Woff2();
        WriteUInt16BigEndian(bytes, 14, 1);

        AssertNonCanonicalWoff2(FileInspector.Detect(bytes));
        using var stream = new MemoryStream(bytes, writable: false);
        AssertNonCanonicalWoff2(FileInspector.Detect(stream));

        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".woff2");
        try
        {
            File.WriteAllBytes(path, bytes);
            AssertNonCanonicalWoff2(FileInspector.Detect(path));
        }
        finally
        {
            TestHelpers.SafeDelete(path);
        }
    }

    [Theory]
    [InlineData(0x10B, 95)]
    [InlineData(0x20B, 111)]
    public void PeImagesRequireCompleteStandardAndWindowsSpecificOptionalHeaders(int magic, int optionalHeaderSize)
    {
        var bytes = TestHelpers.CreateMinimalPe();
        int peOffset = (int)ReadUInt32LittleEndian(bytes, 0x3C);
        WriteUInt16LittleEndian(bytes, peOffset + 20, (ushort)optionalHeaderSize);
        WriteUInt16LittleEndian(bytes, peOffset + 24, (ushort)magic);

        AssertNotDetectedAcrossApis(bytes, "exe");
    }

    [Fact]
    public void ThinMachOLoadCommandsMustFitInsideTheCompleteFile()
        => AssertNotDetectedAcrossApis(TruncatedThinMachO(), "macho");

    private static void AssertParity(byte[] bytes, string extension)
    {
        Assert.Equal(extension, FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false);
        long position = Math.Min(7, stream.Length);
        stream.Position = position;
        Assert.Equal(extension, FileInspector.Detect(stream)?.Extension);
        Assert.Equal(position, stream.Position);

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

    private static void AssertNonCanonicalWoff2(ContentTypeDetectionResult? result)
    {
        Assert.Equal("woff2", result?.Extension);
        Assert.Equal("Medium", result?.Confidence);
        Assert.Equal("font:woff2;reserved-nonzero", result?.Reason);
    }

    private static void AssertNotDetectedAcrossApis(byte[] bytes, string extension)
    {
        Assert.NotEqual(extension, FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false);
        Assert.NotEqual(extension, FileInspector.Detect(stream)?.Extension);

        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".bin");
        try
        {
            File.WriteAllBytes(path, bytes);
            Assert.NotEqual(extension, FileInspector.Detect(path)?.Extension);
        }
        finally
        {
            TestHelpers.SafeDelete(path);
        }
    }

    private static byte[] LegacyHdf5WithSixteenByteOffsets(byte version)
    {
        const int userBlock = 4096;
        const int hdfLength = 200;
        var bytes = new byte[userBlock + hdfLength];
        new byte[] { 0x89, (byte)'H', (byte)'D', (byte)'F', 0x0D, 0x0A, 0x1A, 0x0A }.CopyTo(bytes, userBlock);
        bytes[userBlock + 8] = version;
        bytes[userBlock + 13] = 16;
        bytes[userBlock + 14] = 8;
        WriteUInt16LittleEndian(bytes, userBlock + 16, 4);
        WriteUInt16LittleEndian(bytes, userBlock + 18, 16);
        int cursor = userBlock + 24;
        if (version == 1)
        {
            WriteUInt16LittleEndian(bytes, userBlock + 24, 32);
            cursor = userBlock + 28;
        }
        WriteHdfAddress(bytes, cursor, userBlock);
        FillUndefinedHdfAddress(bytes, cursor + 16);
        WriteHdfAddress(bytes, cursor + 32, hdfLength);
        FillUndefinedHdfAddress(bytes, cursor + 48);
        WriteHdfAddress(bytes, cursor + 80, 176);
        return bytes;
    }

    private static byte[] Woff2()
    {
        var bytes = new byte[52];
        Encoding.ASCII.GetBytes("wOF2OTTO").CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 8, (uint)bytes.Length);
        WriteUInt16BigEndian(bytes, 12, 1);
        WriteUInt32BigEndian(bytes, 16, 32);
        WriteUInt32BigEndian(bytes, 20, 2);
        bytes[48] = 0;
        bytes[49] = 1;
        return bytes;
    }

    private static byte[] TruncatedThinMachO()
    {
        var bytes = new byte[28];
        new byte[] { 0xCE, 0xFA, 0xED, 0xFE }.CopyTo(bytes, 0);
        WriteUInt32LittleEndian(bytes, 4, 7);
        WriteUInt32LittleEndian(bytes, 12, 2);
        WriteUInt32LittleEndian(bytes, 16, 1);
        WriteUInt32LittleEndian(bytes, 20, 8);
        return bytes;
    }

    private static void WriteHdfAddress(byte[] bytes, int offset, ulong value)
    {
        for (int i = 0; i < 8; i++) bytes[offset + i] = (byte)(value >> (i * 8));
    }

    private static void FillUndefinedHdfAddress(byte[] bytes, int offset)
    {
        for (int i = 0; i < 16; i++) bytes[offset + i] = 0xFF;
    }

    private static uint ReadUInt32LittleEndian(byte[] bytes, int offset)
        => (uint)(bytes[offset] | bytes[offset + 1] << 8 | bytes[offset + 2] << 16 | bytes[offset + 3] << 24);

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
        bytes[offset] = (byte)value;
        bytes[offset + 1] = (byte)(value >> 8);
        bytes[offset + 2] = (byte)(value >> 16);
        bytes[offset + 3] = (byte)(value >> 24);
    }

    private static void WriteUInt32BigEndian(byte[] bytes, int offset, uint value)
    {
        bytes[offset] = (byte)(value >> 24);
        bytes[offset + 1] = (byte)(value >> 16);
        bytes[offset + 2] = (byte)(value >> 8);
        bytes[offset + 3] = (byte)value;
    }
}
