using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class ThirtySixthReviewRegressionTests
{
    [Fact]
    public void Mj2RequiresSampleTableResolutionForHighConfidence()
        => AssertMediumParity(TestHelpers.CreateMinimalJpeg2000("mjp2"), "mj2", "sample-table-not-validated");

    [Fact]
    public void RpmCompressionPrefixDoesNotEstablishPayloadIntegrity()
        => AssertMediumParity(RpmWithTruncatedGzip(), "rpm", "payload-not-validated");

    [Fact]
    public void BrandedIsoBmffRequiresBrandSpecificContentsForHighConfidence()
        => AssertMediumParity(FtypWithFreeBox("avif"), "avif", "brand-contents-not-validated");

    [Fact]
    public void GlbRequiresAssetMetadataForHighConfidence()
        => AssertMediumParity(Glb("{}  "), "glb", "asset-metadata-not-validated");

    [Fact]
    public void EvtxChunkSignaturesDoNotEstablishChunkIntegrity()
        => AssertMediumParity(TestHelpers.CreateMinimalEvtx(), "evtx", "chunk-integrity-not-validated");

    private static byte[] RpmWithTruncatedGzip()
    {
        var bytes = new byte[171];
        new byte[] { 0xED, 0xAB, 0xEE, 0xDB, 3, 0 }.CopyTo(bytes, 0);
        TestHelpers.WriteUInt16BigEndian(bytes, 78, 5);
        WriteRpmHeader(bytes, 96);
        WriteRpmHeader(bytes, 136);
        bytes[169] = 0x1F;
        bytes[170] = 0x8B;
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

    private static byte[] FtypWithFreeBox(string brand)
    {
        var bytes = new byte[24];
        TestHelpers.WriteUInt32BigEndian(bytes, 0, 16);
        Encoding.ASCII.GetBytes("ftyp").CopyTo(bytes, 4);
        Encoding.ASCII.GetBytes(brand).CopyTo(bytes, 8);
        TestHelpers.WriteUInt32BigEndian(bytes, 16, 8);
        Encoding.ASCII.GetBytes("free").CopyTo(bytes, 20);
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

    private static void AssertMediumParity(byte[] bytes, string extension, string reasonFragment)
    {
        ContentTypeDetectionResult? fromBytes = FileInspector.Detect(bytes);
        using var stream = new MemoryStream(bytes, writable: false) { Position = Math.Min(3, bytes.Length) };
        ContentTypeDetectionResult? fromStream = FileInspector.Detect(stream);
        Assert.Equal(extension, fromBytes?.Extension);
        Assert.Equal(extension, fromStream?.Extension);
        Assert.Equal("Medium", fromBytes?.Confidence);
        Assert.Equal("Medium", fromStream?.Confidence);
        Assert.Contains(reasonFragment, fromBytes?.Reason);
        Assert.Contains(reasonFragment, fromStream?.Reason);
        Assert.Equal(Math.Min(3, bytes.Length), stream.Position);
    }
}
