using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class FortySecondReviewRegressionTests
{
    [Fact]
    public void DebianControlArchiveRequiresTheControlMetadataFile()
    {
        byte[] valid = TestHelpers.CreateMinimalDeb();
        AssertParity(valid, "deb", "High", null);

        int controlArchive = IndexOf(valid, Encoding.ASCII.GetBytes("control.tar/"));
        Assert.True(controlArchive >= 0);
        int tarHeader = controlArchive + 60;
        Array.Clear(valid, tarHeader, 100);
        Encoding.ASCII.GetBytes("payload").CopyTo(valid, tarHeader);
        RecomputeTarChecksum(valid, tarHeader);
        AssertNotDetectedAs(valid, "deb");
    }

    [Fact]
    public void ArrowFooterWithoutFieldSemanticsStaysAtMediumConfidence()
        => AssertParity(TestHelpers.CreateMinimalArrow(), "arrow", "Medium", "field-semantics-not-validated");

    [Fact]
    public void IntegrityCheckedDexWithoutReferencedItemValidationStaysAtMediumConfidence()
        => AssertParity(TestHelpers.CreateMinimalDex(), "dex", "Medium", "table-references-not-validated");

    [Fact]
    public void LegacyUncompressedDdsHonorsDeclaredRowPitch()
    {
        AssertParity(LegacyDds(payloadLength: 8), "dds", "High", null);
        AssertNotDetectedAs(LegacyDds(payloadLength: 6), "dds");
    }

    [Fact]
    public void NonemptyMinidumpWithRangeOnlyEvidenceStaysAtMediumConfidence()
        => AssertParity(MinidumpWithTruncatedSystemInfo(), "dmp", "Medium", "stream-layouts-not-validated");

    [Fact]
    public void IconDirectoryMayLeavePlanesAndBitDepthUnspecified()
        => AssertParity(IconWithDerivedDibProperties(), "ico", "High", null);

    private static byte[] LegacyDds(int payloadLength)
    {
        var bytes = new byte[128 + payloadLength];
        Encoding.ASCII.GetBytes("DDS ").CopyTo(bytes, 0);
        TestHelpers.WriteUInt32LittleEndian(bytes, 4, 124);
        TestHelpers.WriteUInt32LittleEndian(bytes, 8, 0x100F);
        TestHelpers.WriteUInt32LittleEndian(bytes, 12, 2);
        TestHelpers.WriteUInt32LittleEndian(bytes, 16, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 20, 4);
        TestHelpers.WriteUInt32LittleEndian(bytes, 76, 32);
        TestHelpers.WriteUInt32LittleEndian(bytes, 80, 0x40);
        TestHelpers.WriteUInt32LittleEndian(bytes, 88, 24);
        TestHelpers.WriteUInt32LittleEndian(bytes, 92, 0x00FF0000);
        TestHelpers.WriteUInt32LittleEndian(bytes, 96, 0x0000FF00);
        TestHelpers.WriteUInt32LittleEndian(bytes, 100, 0x000000FF);
        TestHelpers.WriteUInt32LittleEndian(bytes, 108, 0x1000);
        return bytes;
    }

    private static byte[] MinidumpWithTruncatedSystemInfo()
    {
        var bytes = new byte[45];
        Encoding.ASCII.GetBytes("MDMP").CopyTo(bytes, 0);
        TestHelpers.WriteUInt32LittleEndian(bytes, 4, 0xA793);
        TestHelpers.WriteUInt32LittleEndian(bytes, 8, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 12, 32);
        TestHelpers.WriteUInt32LittleEndian(bytes, 32, 7);
        TestHelpers.WriteUInt32LittleEndian(bytes, 36, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 40, 44);
        return bytes;
    }

    private static byte[] IconWithDerivedDibProperties()
    {
        var bytes = new byte[70];
        TestHelpers.WriteUInt16LittleEndian(bytes, 2, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, 4, 1);
        bytes[6] = 1;
        bytes[7] = 1;
        TestHelpers.WriteUInt32LittleEndian(bytes, 14, 48);
        TestHelpers.WriteUInt32LittleEndian(bytes, 18, 22);
        TestHelpers.WriteUInt32LittleEndian(bytes, 22, 40);
        TestHelpers.WriteUInt32LittleEndian(bytes, 26, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 30, 2);
        TestHelpers.WriteUInt16LittleEndian(bytes, 34, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, 36, 32);
        TestHelpers.WriteUInt32LittleEndian(bytes, 42, 4);
        return bytes;
    }

    private static void RecomputeTarChecksum(byte[] bytes, int header)
    {
        for (int index = 148; index < 156; index++) bytes[header + index] = (byte)' ';
        int checksum = 0;
        for (int index = 0; index < 512; index++) checksum += bytes[header + index];
        Encoding.ASCII.GetBytes(Convert.ToString(checksum, 8)!.PadLeft(6, '0') + "\0 ").CopyTo(bytes, header + 148);
    }

    private static int IndexOf(byte[] bytes, byte[] pattern)
    {
        for (int index = 0; index <= bytes.Length - pattern.Length; index++)
            if (bytes.AsSpan(index, pattern.Length).SequenceEqual(pattern)) return index;
        return -1;
    }

    private static void AssertParity(byte[] bytes, string extension, string confidence, string? reason)
    {
        ContentTypeDetectionResult? fromBytes = FileInspector.Detect(bytes);
        using var stream = new MemoryStream(bytes, writable: false) { Position = Math.Min(3, bytes.Length) };
        ContentTypeDetectionResult? fromStream = FileInspector.Detect(stream);
        Assert.Equal(extension, fromBytes?.Extension);
        Assert.Equal(extension, fromStream?.Extension);
        Assert.Equal(confidence, fromBytes?.Confidence);
        Assert.Equal(confidence, fromStream?.Confidence);
        if (reason != null)
        {
            Assert.Contains(reason, fromBytes?.Reason ?? string.Empty, StringComparison.Ordinal);
            Assert.Contains(reason, fromStream?.Reason ?? string.Empty, StringComparison.Ordinal);
        }
        Assert.Equal(Math.Min(3, bytes.Length), stream.Position);
    }

    private static void AssertNotDetectedAs(byte[] bytes, string extension)
    {
        Assert.NotEqual(extension, FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false);
        Assert.NotEqual(extension, FileInspector.Detect(stream)?.Extension);
    }
}
