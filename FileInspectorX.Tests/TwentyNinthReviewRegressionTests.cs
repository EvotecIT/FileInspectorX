using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class TwentyNinthReviewRegressionTests
{
    [Fact]
    public void WoffRejectsOverlappingTablePayloads()
    {
        byte[] valid = Woff(overlap: false);
        AssertParity(valid, "woff");
        AssertNotDetectedAs(Woff(overlap: true), "woff");
    }

    [Fact]
    public void MotionJpeg2000RequiresMovieHierarchyAndMediaPayload()
    {
        AssertParity(TestHelpers.CreateMinimalJpeg2000("mjp2"), "mj2");
        var emptyBoxes = new byte[48];
        TestHelpers.CreateMinimalJpeg2000("mjp2").AsSpan(0, 32).CopyTo(emptyBoxes);
        TestHelpers.WriteUInt32BigEndian(emptyBoxes, 32, 8);
        Encoding.ASCII.GetBytes("moov").CopyTo(emptyBoxes, 36);
        TestHelpers.WriteUInt32BigEndian(emptyBoxes, 40, 8);
        Encoding.ASCII.GetBytes("mdat").CopyTo(emptyBoxes, 44);
        AssertNotDetectedAs(emptyBoxes, "mj2");
    }

    [Fact]
    public void ParquetRequiresASupportedPositiveMetadataVersion()
    {
        byte[] valid = TestHelpers.CreateMinimalParquet();
        AssertParity(valid, "parquet");
        valid[5] = 0;
        AssertNotDetectedAs(valid, "parquet");
    }

    [Fact]
    public void PcapWalksEveryPacketRecord()
    {
        byte[] valid = Pcap(includedLength: 4, originalLength: 4, payloadLength: 4);
        AssertParity(valid, "pcap");
        AssertNotDetectedAs(Pcap(includedLength: 5, originalLength: 4, payloadLength: 5), "pcap");
        AssertNotDetectedAs(Pcap(includedLength: 5, originalLength: 5, payloadLength: 4), "pcap");
    }

    [Fact]
    public void DdsRequiresEnoughImagePayload()
    {
        byte[] valid = Dds(includePayload: true);
        AssertParity(valid, "dds");
        AssertNotDetectedAs(Dds(includePayload: false), "dds");
    }

    [Fact]
    public void GlbRequiresACompleteJsonDocument()
    {
        AssertParity(Glb("{}  "), "glb");
        AssertNotDetectedAs(Glb("{]  "), "glb");
    }

    [Fact]
    public void TiffRequiresStrictlyAscendingTags()
    {
        AssertParity(Tiff(firstTag: 256, secondTag: 257), "tif");
        AssertNotDetectedAs(Tiff(firstTag: 257, secondTag: 256), "tif");
    }

    [Fact]
    public void MatroskaRequiresInfoAndTracksInACompleteSegment()
    {
        AssertParity(TestHelpers.CreateMinimalMatroska(), "matroska");
        byte[] empty = TestHelpers.CreateMinimalMatroska().Take(21).ToArray();
        empty[20] = 0x80;
        AssertNotDetectedAs(empty, "matroska");
    }

    [Fact]
    public void IconRequiresAValidEmbeddedImageAndDirectoryFields()
    {
        byte[] valid = Icon(TestHelpers.CreateMinimalPng());
        AssertParity(valid, "ico");
        AssertNotDetectedAs(Icon(new byte[68]), "ico");
        valid[10] = 0;
        valid[11] = 0;
        AssertNotDetectedAs(valid, "ico");
    }

    [Fact]
    public void RpmRequiresValidIndexesAndACompressedPayload()
    {
        byte[] valid = Rpm();
        AssertParity(valid, "rpm");
        byte[] invalidIndex = (byte[])valid.Clone();
        invalidIndex[112] = 0;
        invalidIndex[113] = 0;
        invalidIndex[114] = 0;
        invalidIndex[115] = 0;
        AssertNotDetectedAs(invalidIndex, "rpm");
        byte[] invalidPayload = (byte[])valid.Clone();
        invalidPayload[169] = 0;
        AssertNotDetectedAs(invalidPayload, "rpm");
    }

    private static byte[] Woff(bool overlap)
    {
        var bytes = new byte[92];
        Encoding.ASCII.GetBytes("wOFF").CopyTo(bytes, 0);
        TestHelpers.WriteUInt32BigEndian(bytes, 4, 0x00010000);
        TestHelpers.WriteUInt32BigEndian(bytes, 8, (uint)bytes.Length);
        TestHelpers.WriteUInt16BigEndian(bytes, 12, 2);
        TestHelpers.WriteUInt32BigEndian(bytes, 16, 44);
        Encoding.ASCII.GetBytes("head").CopyTo(bytes, 44);
        TestHelpers.WriteUInt32BigEndian(bytes, 48, 84);
        TestHelpers.WriteUInt32BigEndian(bytes, 52, 4);
        TestHelpers.WriteUInt32BigEndian(bytes, 56, 4);
        Encoding.ASCII.GetBytes("name").CopyTo(bytes, 64);
        TestHelpers.WriteUInt32BigEndian(bytes, 68, overlap ? 84u : 88u);
        TestHelpers.WriteUInt32BigEndian(bytes, 72, 4);
        TestHelpers.WriteUInt32BigEndian(bytes, 76, 4);
        return bytes;
    }

    private static byte[] Pcap(uint includedLength, uint originalLength, int payloadLength)
    {
        var bytes = new byte[40 + payloadLength];
        new byte[] { 0xD4, 0xC3, 0xB2, 0xA1 }.CopyTo(bytes, 0);
        TestHelpers.WriteUInt16LittleEndian(bytes, 4, 2);
        TestHelpers.WriteUInt16LittleEndian(bytes, 6, 4);
        TestHelpers.WriteUInt32LittleEndian(bytes, 16, 65535);
        TestHelpers.WriteUInt32LittleEndian(bytes, 28, 500000);
        TestHelpers.WriteUInt32LittleEndian(bytes, 32, includedLength);
        TestHelpers.WriteUInt32LittleEndian(bytes, 36, originalLength);
        return bytes;
    }

    private static byte[] Dds(bool includePayload)
    {
        var bytes = new byte[includePayload ? 132 : 128];
        Encoding.ASCII.GetBytes("DDS ").CopyTo(bytes, 0);
        TestHelpers.WriteUInt32LittleEndian(bytes, 4, 124);
        TestHelpers.WriteUInt32LittleEndian(bytes, 8, 0x1007);
        TestHelpers.WriteUInt32LittleEndian(bytes, 12, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 16, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 76, 32);
        TestHelpers.WriteUInt32LittleEndian(bytes, 80, 0x41);
        TestHelpers.WriteUInt32LittleEndian(bytes, 88, 32);
        TestHelpers.WriteUInt32LittleEndian(bytes, 92, 0x00FF0000);
        TestHelpers.WriteUInt32LittleEndian(bytes, 96, 0x0000FF00);
        TestHelpers.WriteUInt32LittleEndian(bytes, 100, 0x000000FF);
        TestHelpers.WriteUInt32LittleEndian(bytes, 104, 0xFF000000);
        TestHelpers.WriteUInt32LittleEndian(bytes, 108, 0x1000);
        return bytes;
    }

    private static byte[] Glb(string json)
    {
        byte[] content = Encoding.UTF8.GetBytes(json);
        var bytes = new byte[20 + content.Length];
        Encoding.ASCII.GetBytes("glTF").CopyTo(bytes, 0);
        TestHelpers.WriteUInt32LittleEndian(bytes, 4, 2);
        TestHelpers.WriteUInt32LittleEndian(bytes, 8, (uint)bytes.Length);
        TestHelpers.WriteUInt32LittleEndian(bytes, 12, (uint)content.Length);
        TestHelpers.WriteUInt32LittleEndian(bytes, 16, 0x4E4F534A);
        content.CopyTo(bytes, 20);
        return bytes;
    }

    private static byte[] Tiff(ushort firstTag, ushort secondTag)
    {
        var bytes = new byte[38];
        bytes[0] = bytes[1] = (byte)'I';
        TestHelpers.WriteUInt16LittleEndian(bytes, 2, 42);
        TestHelpers.WriteUInt32LittleEndian(bytes, 4, 8);
        TestHelpers.WriteUInt16LittleEndian(bytes, 8, 2);
        TestHelpers.WriteUInt16LittleEndian(bytes, 10, firstTag);
        TestHelpers.WriteUInt16LittleEndian(bytes, 12, 3);
        TestHelpers.WriteUInt32LittleEndian(bytes, 14, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, 22, secondTag);
        TestHelpers.WriteUInt16LittleEndian(bytes, 24, 3);
        TestHelpers.WriteUInt32LittleEndian(bytes, 26, 1);
        return bytes;
    }

    private static byte[] Icon(byte[] payload)
    {
        var bytes = new byte[22 + payload.Length];
        TestHelpers.WriteUInt16LittleEndian(bytes, 2, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, 4, 1);
        bytes[6] = bytes[7] = 1;
        TestHelpers.WriteUInt16LittleEndian(bytes, 10, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, 12, 32);
        TestHelpers.WriteUInt32LittleEndian(bytes, 14, (uint)payload.Length);
        TestHelpers.WriteUInt32LittleEndian(bytes, 18, 22);
        payload.CopyTo(bytes, 22);
        return bytes;
    }

    private static byte[] Rpm()
    {
        var bytes = new byte[174];
        new byte[] { 0xED, 0xAB, 0xEE, 0xDB, 3, 0 }.CopyTo(bytes, 0);
        TestHelpers.WriteUInt16BigEndian(bytes, 78, 5);
        WriteRpmHeader(bytes, 96);
        WriteRpmHeader(bytes, 136);
        new byte[] { 0x1F, 0x8B, 8, 0, 0 }.CopyTo(bytes, 169);
        return bytes;
    }

    private static void WriteRpmHeader(byte[] bytes, int offset)
    {
        new byte[] { 0x8E, 0xAD, 0xE8, 1 }.CopyTo(bytes, offset);
        TestHelpers.WriteUInt32BigEndian(bytes, offset + 8, 1);
        TestHelpers.WriteUInt32BigEndian(bytes, offset + 12, 1);
        TestHelpers.WriteUInt32BigEndian(bytes, offset + 16, 1000);
        TestHelpers.WriteUInt32BigEndian(bytes, offset + 20, 7);
        TestHelpers.WriteUInt32BigEndian(bytes, offset + 28, 1);
    }

    private static void AssertParity(byte[] bytes, string extension)
    {
        Assert.Equal(extension, FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false) { Position = Math.Min(7, bytes.Length) };
        Assert.Equal(extension, FileInspector.Detect(stream)?.Extension);
        Assert.Equal(Math.Min(7, bytes.Length), stream.Position);
    }

    private static void AssertNotDetectedAs(byte[] bytes, string extension)
    {
        Assert.NotEqual(extension, FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false);
        Assert.NotEqual(extension, FileInspector.Detect(stream)?.Extension);
    }
}
