using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class FormatCompatibilityRegressionTests
{
    [Fact]
    public void PeHeaderBeyondDetectionPrefixKeepsApiParity()
    {
        const int peOffset = 5000;
        var bytes = new byte[0x1600];
        bytes[0] = (byte)'M';
        bytes[1] = (byte)'Z';
        WriteUInt32LittleEndian(bytes, 0x3C, peOffset);
        Encoding.ASCII.GetBytes("PE\0\0").CopyTo(bytes, peOffset);
        WriteUInt16LittleEndian(bytes, peOffset + 4, 0x014C);
        WriteUInt16LittleEndian(bytes, peOffset + 6, 1);
        WriteUInt16LittleEndian(bytes, peOffset + 20, 0xE0);
        WriteUInt16LittleEndian(bytes, peOffset + 22, 0x0102);
        WriteUInt16LittleEndian(bytes, peOffset + 24, 0x010B);
        WriteUInt32LittleEndian(bytes, peOffset + 56, 0x1000);
        WriteUInt32LittleEndian(bytes, peOffset + 60, 0x0200);
        WriteUInt32LittleEndian(bytes, peOffset + 80, 0x2000);
        WriteUInt32LittleEndian(bytes, peOffset + 84, 0x1600);

        AssertParity(bytes, "exe", "High");
    }

    [Fact]
    public void GifLogicalScreenSortFlagIsAccepted()
    {
        var bytes = new byte[19];
        Encoding.ASCII.GetBytes("GIF89a").CopyTo(bytes, 0);
        WriteUInt16LittleEndian(bytes, 6, 1);
        WriteUInt16LittleEndian(bytes, 8, 1);
        bytes[10] = 0x88; // Global color table present, sorted, two entries.

        AssertParity(bytes, "gif", "High");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void TiffIfdBeyondDetectionPrefixKeepsApiParity(bool bigTiff)
    {
        const int ifdOffset = 5000;
        var bytes = new byte[ifdOffset + (bigTiff ? 16 : 6)];
        bytes[0] = (byte)'I';
        bytes[1] = (byte)'I';
        WriteUInt16LittleEndian(bytes, 2, bigTiff ? (ushort)43 : (ushort)42);
        if (bigTiff)
        {
            WriteUInt16LittleEndian(bytes, 4, 8);
            WriteUInt64LittleEndian(bytes, 8, ifdOffset);
        }
        else
        {
            WriteUInt32LittleEndian(bytes, 4, ifdOffset);
        }

        AssertParity(bytes, "tif", "Medium");
    }

    [Fact]
    public void JpegFillBytesBeforeFirstMarkerAreAccepted()
    {
        byte[] original = TestHelpers.CreateMinimalJpeg();
        var bytes = new byte[original.Length + 1];
        original.AsSpan(0, 2).CopyTo(bytes);
        bytes[2] = 0xFF;
        original.AsSpan(2).CopyTo(bytes.AsSpan(3));
        AssertParity(bytes, "jpg", "High");
    }

    [Fact]
    public void DirtyRegistryHiveRemainsRecognizableWithRecoveryMetadata()
    {
        var result = AssertParity(RegistryHive(primarySequence: 2, secondarySequence: 1), "hive", "Medium");

        Assert.Equal("registry-hive:base-block:dirty", result.Reason);
        Assert.Contains("recovery-may-be-required", result.ReasonDetails);
        Assert.Equal("High", FileInspector.Detect(RegistryHive(primarySequence: 2, secondarySequence: 2))?.Confidence);
    }

    [Fact]
    public void TtcMayShareATableStoredBeforeALaterDirectory()
        => AssertParity(SharedTableCollection(), "ttc", "High");

    [Fact]
    public void TtcDirectoryBeyondDetectionPrefixKeepsApiParity()
        => AssertParity(LargeDirectoryCollection(), "ttc", "High");

    [Fact]
    public void AppleTrueTypeFlavorIsAcceptedStandaloneAndInWoff()
    {
        AssertParity(AppleTrueType(), "ttf", "High");
        AssertParity(AppleTrueTypeWoff(), "woff", "Medium");
    }

    [Fact]
    public void BinaryGltfVersionOneIsStructurallyDetected()
    {
        var bytes = new byte[24];
        Encoding.ASCII.GetBytes("glTF").CopyTo(bytes, 0);
        WriteUInt32LittleEndian(bytes, 4, 1);
        WriteUInt32LittleEndian(bytes, 8, (uint)bytes.Length);
        WriteUInt32LittleEndian(bytes, 12, 4);
        WriteUInt32LittleEndian(bytes, 16, 0);
        Encoding.ASCII.GetBytes("{}  ").CopyTo(bytes, 20);

        AssertParity(bytes, "glb", "Medium");
    }

    [Theory]
    [InlineData("avc1", null)]
    [InlineData("zzzz", "avc1")]
    [InlineData("av01", null)]
    [InlineData("M4V ", null)]
    public void RegisteredVideoBrandsAreClassifiedAsMp4(string majorBrand, string? compatibleBrand)
    {
        int fileTypeLength = compatibleBrand == null ? 16 : 20;
        var bytes = new byte[fileTypeLength + 8];
        WriteUInt32BigEndian(bytes, 0, (uint)fileTypeLength);
        Encoding.ASCII.GetBytes("ftyp").CopyTo(bytes, 4);
        Encoding.ASCII.GetBytes(majorBrand).CopyTo(bytes, 8);
        if (compatibleBrand != null) Encoding.ASCII.GetBytes(compatibleBrand).CopyTo(bytes, 16);
        WriteUInt32BigEndian(bytes, fileTypeLength, 8);
        Encoding.ASCII.GetBytes("free").CopyTo(bytes, fileTypeLength + 4);

        AssertParity(bytes, "mp4", "Medium");
    }

    [Fact]
    public void ReferencedStructuresUseCompleteLengthAcrossDetectionApis()
    {
        AssertParity(LargeMinidump(), "dmp", "High");
        AssertParity(LargeRpmSignatureHeader(), "rpm", "Medium");
        AssertParity(LargeFtypBox(), "mp4", "Medium");
    }

    [Fact]
    public void PcapNgSectionTrailerBeyondDetectionPrefixKeepsApiParity()
    {
        const int blockLength = 5000;
        var bytes = new byte[blockLength];
        new byte[] { 0x0A, 0x0D, 0x0D, 0x0A, 0x88, 0x13, 0, 0, 0x4D, 0x3C, 0x2B, 0x1A, 1, 0, 0, 0 }
            .CopyTo(bytes, 0);
        WriteUInt32LittleEndian(bytes, blockLength - 4, blockLength);

        AssertParity(bytes, "pcapng", "High");
    }

    [Fact]
    public void MatroskaHeaderAtDetectionBoundaryKeepsApiParity()
    {
        var bytes = new byte[4119];
        new byte[] { 0x1A, 0x45, 0xDF, 0xA3, 0x4F, 0xFA, 0x42, 0x82, 0x88 }
            .CopyTo(bytes, 0);
        Encoding.ASCII.GetBytes("matroska").CopyTo(bytes, 9);
        bytes[17] = 0xEC; // Void element fills the rest of the 4090-byte EBML header.
        bytes[18] = 0x4F;
        bytes[19] = 0xEC;
        new byte[] { 0x18, 0x53, 0x80, 0x67 }.CopyTo(bytes, 4096);
        bytes[4100] = 0x92;
        new byte[] {
            0x15, 0x49, 0xA9, 0x66, 0x85, 0x2A, 0xD7, 0xB1, 0x81, 0x01,
            0x16, 0x54, 0xAE, 0x6B, 0x83, 0xAE, 0x81, 0x00
        }.CopyTo(bytes, 4101);

        AssertParity(bytes, "matroska", "Medium");
    }

    private static ContentTypeDetectionResult AssertParity(byte[] bytes, string extension, string confidence)
    {
        var fromBytes = FileInspector.Detect(bytes);
        using var stream = new MemoryStream(bytes, writable: false);
        stream.Position = Math.Min(7, stream.Length);
        long originalPosition = stream.Position;
        var fromStream = FileInspector.Detect(stream);
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".bin");
        try
        {
            File.WriteAllBytes(path, bytes);
            var fromPath = FileInspector.Detect(path);
            Assert.Equal(extension, fromBytes?.Extension);
            Assert.Equal(extension, fromStream?.Extension);
            Assert.Equal(extension, fromPath?.Extension);
            Assert.Equal(confidence, fromBytes?.Confidence);
            Assert.Equal(confidence, fromStream?.Confidence);
            Assert.Equal(confidence, fromPath?.Confidence);
            Assert.Equal(originalPosition, stream.Position);
            return fromBytes!;
        }
        finally
        {
            TestHelpers.SafeDelete(path);
        }
    }

    private static byte[] RegistryHive(uint primarySequence, uint secondarySequence)
    {
        var bytes = new byte[8192];
        Encoding.ASCII.GetBytes("regf").CopyTo(bytes, 0);
        WriteUInt32LittleEndian(bytes, 4, primarySequence);
        WriteUInt32LittleEndian(bytes, 8, secondarySequence);
        WriteUInt32LittleEndian(bytes, 20, 1);
        WriteUInt32LittleEndian(bytes, 24, 5);
        WriteUInt32LittleEndian(bytes, 32, 1);
        WriteUInt32LittleEndian(bytes, 36, 0x20);
        WriteUInt32LittleEndian(bytes, 40, 0x1000);
        WriteUInt32LittleEndian(bytes, 44, 1);
        Encoding.ASCII.GetBytes("hbin").CopyTo(bytes, 4096);
        WriteUInt32LittleEndian(bytes, 4100, 0);
        WriteUInt32LittleEndian(bytes, 4104, 0x1000);
        WriteUInt32LittleEndian(bytes, 4096 + 0x20, 0xFFFFFFB0);
        Encoding.ASCII.GetBytes("nk").CopyTo(bytes, 4096 + 0x24);
        uint checksum = 0;
        for (int offset = 0; offset < 0x1FC; offset += 4) checksum ^= ReadUInt32LittleEndian(bytes, offset);
        WriteUInt32LittleEndian(bytes, 0x1FC, checksum);
        return bytes;
    }

    private static byte[] SharedTableCollection()
    {
        var bytes = new byte[80];
        Encoding.ASCII.GetBytes("ttcf").CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 4, 0x00010000);
        WriteUInt32BigEndian(bytes, 8, 2);
        WriteUInt32BigEndian(bytes, 12, 20);
        WriteUInt32BigEndian(bytes, 16, 52);
        WriteSfntDirectory(bytes, 20, 48);
        Encoding.ASCII.GetBytes("data").CopyTo(bytes, 48);
        WriteSfntDirectory(bytes, 52, 48);
        return bytes;
    }

    private static byte[] LargeDirectoryCollection()
    {
        const int secondDirectoryOffset = 5000;
        var bytes = new byte[secondDirectoryOffset + 28];
        Encoding.ASCII.GetBytes("ttcf").CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 4, 0x00010000);
        WriteUInt32BigEndian(bytes, 8, 2);
        WriteUInt32BigEndian(bytes, 12, 20);
        WriteUInt32BigEndian(bytes, 16, secondDirectoryOffset);
        WriteSfntDirectory(bytes, 20, 48);
        Encoding.ASCII.GetBytes("data").CopyTo(bytes, 48);
        WriteSfntDirectory(bytes, secondDirectoryOffset, 48);
        return bytes;
    }

    private static byte[] AppleTrueType()
    {
        var bytes = new byte[32];
        WriteSfntDirectory(bytes, 0, 28, 0x74727565);
        Encoding.ASCII.GetBytes("data").CopyTo(bytes, 28);
        return bytes;
    }

    private static byte[] AppleTrueTypeWoff()
    {
        var bytes = new byte[68];
        Encoding.ASCII.GetBytes("wOFF").CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 4, 0x74727565);
        WriteUInt32BigEndian(bytes, 8, (uint)bytes.Length);
        WriteUInt16BigEndian(bytes, 12, 1);
        WriteUInt32BigEndian(bytes, 16, 32);
        Encoding.ASCII.GetBytes("head").CopyTo(bytes, 44);
        WriteUInt32BigEndian(bytes, 48, 64);
        WriteUInt32BigEndian(bytes, 52, 4);
        WriteUInt32BigEndian(bytes, 56, 4);
        Encoding.ASCII.GetBytes("data").CopyTo(bytes, 64);
        return bytes;
    }

    private static void WriteSfntDirectory(byte[] bytes, int offset, int tableOffset, uint flavor = 0x00010000)
    {
        WriteUInt32BigEndian(bytes, offset, flavor);
        WriteUInt16BigEndian(bytes, offset + 4, 1);
        WriteUInt16BigEndian(bytes, offset + 6, 16);
        Encoding.ASCII.GetBytes("head").CopyTo(bytes, offset + 12);
        WriteUInt32BigEndian(bytes, offset + 16, 0x64617461);
        WriteUInt32BigEndian(bytes, offset + 20, (uint)tableOffset);
        WriteUInt32BigEndian(bytes, offset + 24, 4);
    }

    private static byte[] LargeMinidump()
    {
        const int directoryOffset = 5000;
        var bytes = new byte[directoryOffset + 12];
        Encoding.ASCII.GetBytes("MDMP").CopyTo(bytes, 0);
        WriteUInt32LittleEndian(bytes, 4, 0xA793);
        WriteUInt32LittleEndian(bytes, 8, 1);
        WriteUInt32LittleEndian(bytes, 12, directoryOffset);
        return bytes;
    }

    private static byte[] LargeRpmSignatureHeader()
    {
        const int dataLength = 5000;
        const int mainOffset = 112 + 16 + dataLength;
        var bytes = new byte[mainOffset + 16 + 16 + 1 + 5];
        new byte[] { 0xED, 0xAB, 0xEE, 0xDB, 3, 0 }.CopyTo(bytes, 0);
        WriteUInt16BigEndian(bytes, 78, 5);
        new byte[] { 0x8E, 0xAD, 0xE8, 1 }.CopyTo(bytes, 96);
        WriteUInt32BigEndian(bytes, 104, 1);
        WriteUInt32BigEndian(bytes, 108, dataLength);
        WriteUInt32BigEndian(bytes, 112, 1000);
        WriteUInt32BigEndian(bytes, 116, 7);
        WriteUInt32BigEndian(bytes, 124, dataLength);
        new byte[] { 0x8E, 0xAD, 0xE8, 1 }.CopyTo(bytes, mainOffset);
        WriteUInt32BigEndian(bytes, mainOffset + 8, 1);
        WriteUInt32BigEndian(bytes, mainOffset + 12, 1);
        WriteUInt32BigEndian(bytes, mainOffset + 16, 1000);
        WriteUInt32BigEndian(bytes, mainOffset + 20, 7);
        WriteUInt32BigEndian(bytes, mainOffset + 28, 1);
        new byte[] { 0x1F, 0x8B, 8, 0, 0 }.CopyTo(bytes, mainOffset + 33);
        return bytes;
    }

    private static byte[] LargeFtypBox()
    {
        var bytes = new byte[5008];
        WriteUInt32BigEndian(bytes, 0, 5000);
        Encoding.ASCII.GetBytes("ftypavc1").CopyTo(bytes, 4);
        WriteUInt32BigEndian(bytes, 5000, 8);
        Encoding.ASCII.GetBytes("free").CopyTo(bytes, 5004);
        return bytes;
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

    private static void WriteUInt64LittleEndian(byte[] bytes, int offset, ulong value)
    {
        for (int i = 0; i < 8; i++) bytes[offset + i] = (byte)(value >> (i * 8));
    }
}
