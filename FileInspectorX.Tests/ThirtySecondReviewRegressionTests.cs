using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class ThirtySecondReviewRegressionTests
{
    [Fact]
    public void CompleteJpegRequiresBoundedSegmentsScanAndEndMarker()
    {
        AssertParity(TestHelpers.CreateMinimalJpeg(), "jpg", "High");
        AssertNotDetectedAs(new byte[] { 0xFF, 0xD8, 0xFF, 0xE0, 0xFF, 0xFF }, "jpg");
    }

    [Fact]
    public void GzipWalksFlagSelectedHeaderFieldsAndUsesReducedConfidence()
    {
        AssertParity(GzipWithExtraField(), "gz", "Medium");
        AssertNotDetectedAs(new byte[] { 0x1F, 0x8B, 8, 4, 0, 0, 0, 0, 0, 255 }, "gz");
    }

    [Fact]
    public void PrefixOnlyBzip2IdentityIsNotHighConfidence()
        => AssertParity(new byte[] { 0x42, 0x5A, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59 }, "bz2", "Medium");

    [Fact]
    public void OggPageLacingPayloadAndChecksumMustBeComplete()
    {
        AssertParity(TestHelpers.CreateMinimalOgg(), "ogg", "High");
        var missingPayload = new byte[28];
        Encoding.ASCII.GetBytes("OggS").CopyTo(missingPayload, 0);
        missingPayload[26] = 1;
        missingPayload[27] = 255;
        AssertNotDetectedAs(missingPayload, "ogg");
    }

    [Fact]
    public void Mp3BoundsTheId3TagAndRequiresAnAudioFrame()
    {
        AssertParity(TestHelpers.CreateMinimalMp3(), "mp3", "Medium");
        var truncated = new byte[10];
        Encoding.ASCII.GetBytes("ID3").CopyTo(truncated, 0);
        truncated[3] = 4;
        truncated[9] = 1;
        AssertNotDetectedAs(truncated, "mp3");
    }

    [Fact]
    public void DynamicVhdValidatesEveryBatEntry()
    {
        AssertParity(DynamicVhd(uint.MaxValue), "vhd", "Medium");
        AssertNotDetectedAs(DynamicVhd(0), "vhd");
    }

    [Fact]
    public void DebianPackageRejectsMalformedTrailingMembers()
    {
        AssertParity(TestHelpers.CreateMinimalDeb(), "deb", "High");
        byte[] valid = TestHelpers.CreateMinimalDeb();
        var malformed = new byte[valid.Length + 60];
        valid.CopyTo(malformed, 0);
        AssertNotDetectedAs(malformed, "deb");
    }

    [Fact]
    public void ParquetRequiresARealRootSchemaElement()
    {
        AssertParity(TestHelpers.CreateMinimalParquet(), "parquet", "High");
        AssertNotDetectedAs(ParquetWithEmptySchemaElement(), "parquet");
    }

    private static byte[] GzipWithExtraField()
    {
        byte[] original = TestHelpers.CreateMinimalGzip();
        var bytes = new byte[original.Length + 3];
        original.AsSpan(0, 10).CopyTo(bytes);
        bytes[3] = 4;
        bytes[10] = 1;
        bytes[12] = 0x42;
        original.AsSpan(10).CopyTo(bytes.AsSpan(13));
        return bytes;
    }

    private static byte[] DynamicVhd(uint batEntry)
    {
        var bytes = new byte[2560];
        int header = 512;
        int table = 1536;
        int footer = 2048;
        Encoding.ASCII.GetBytes("cxsparse").CopyTo(bytes, header);
        TestHelpers.WriteUInt64BigEndian(bytes, header + 8, ulong.MaxValue);
        TestHelpers.WriteUInt64BigEndian(bytes, header + 16, (ulong)table);
        TestHelpers.WriteUInt32BigEndian(bytes, header + 24, 0x00010000);
        TestHelpers.WriteUInt32BigEndian(bytes, header + 28, 1);
        TestHelpers.WriteUInt32BigEndian(bytes, header + 32, 512 * 1024);
        FinalizeVhdChecksum(bytes, header, 1024, 36);
        TestHelpers.WriteUInt32BigEndian(bytes, table, batEntry);

        Encoding.ASCII.GetBytes("conectix").CopyTo(bytes, footer);
        TestHelpers.WriteUInt32BigEndian(bytes, footer + 8, 2);
        TestHelpers.WriteUInt32BigEndian(bytes, footer + 12, 0x00010000);
        TestHelpers.WriteUInt64BigEndian(bytes, footer + 16, (ulong)header);
        TestHelpers.WriteUInt64BigEndian(bytes, footer + 40, 512 * 1024);
        TestHelpers.WriteUInt64BigEndian(bytes, footer + 48, 512 * 1024);
        TestHelpers.WriteUInt32BigEndian(bytes, footer + 56, 0x00010101);
        TestHelpers.WriteUInt32BigEndian(bytes, footer + 60, 3);
        bytes[footer + 68] = 1;
        FinalizeVhdChecksum(bytes, footer, 512, 64);
        return bytes;
    }

    private static void FinalizeVhdChecksum(byte[] bytes, int offset, int length, int checksumOffset)
    {
        uint sum = 0;
        for (int index = 0; index < length; index++)
            if (index < checksumOffset || index >= checksumOffset + 4) sum += bytes[offset + index];
        TestHelpers.WriteUInt32BigEndian(bytes, offset + checksumOffset, ~sum);
    }

    private static byte[] ParquetWithEmptySchemaElement()
    {
        byte[] metadata = { 0x15, 0x02, 0x19, 0x1C, 0x00, 0x16, 0x00, 0x19, 0x0C, 0x00 };
        var bytes = new byte[4 + metadata.Length + 8];
        Encoding.ASCII.GetBytes("PAR1").CopyTo(bytes, 0);
        metadata.CopyTo(bytes, 4);
        TestHelpers.WriteUInt32LittleEndian(bytes, bytes.Length - 8, (uint)metadata.Length);
        Encoding.ASCII.GetBytes("PAR1").CopyTo(bytes, bytes.Length - 4);
        return bytes;
    }

    private static void AssertParity(byte[] bytes, string extension, string confidence)
    {
        var fromBytes = FileInspector.Detect(bytes);
        using var stream = new MemoryStream(bytes, writable: false) { Position = Math.Min(3, bytes.Length) };
        var fromStream = FileInspector.Detect(stream);
        Assert.Equal(extension, fromBytes?.Extension);
        Assert.Equal(extension, fromStream?.Extension);
        Assert.Equal(confidence, fromBytes?.Confidence);
        Assert.Equal(confidence, fromStream?.Confidence);
        Assert.Equal(Math.Min(3, bytes.Length), stream.Position);
    }

    private static void AssertNotDetectedAs(byte[] bytes, string extension)
    {
        Assert.NotEqual(extension, FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false);
        Assert.NotEqual(extension, FileInspector.Detect(stream)?.Extension);
    }
}
