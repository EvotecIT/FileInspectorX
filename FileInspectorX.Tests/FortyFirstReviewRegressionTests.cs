using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class FortyFirstReviewRegressionTests
{
    [Fact]
    public void VhdxWithoutBatEntryValidationStaysAtMediumConfidence()
    {
        byte[] bytes = TestHelpers.CreateMinimalVhdx();
        TestHelpers.WriteUInt64LittleEndian(bytes, 1024 * 1024, 0x0000000400000006);
        AssertParity(bytes, "vhdx", "Medium", "bat-entries-not-validated");
    }

    [Theory]
    [InlineData("dos")]
    [InlineData("ne")]
    [InlineData("le")]
    [InlineData("lx")]
    public void StructurallyValidLegacyMzFamiliesRemainDetectable(string family)
        => AssertParity(LegacyExecutable(family), "exe", "Medium", "mz:" + (family == "dos" ? "dos-executable" : family));

    [Fact]
    public void ArbitraryMzPrefixIsNotExecutableEvidence()
        => AssertNotDetectedAs(Encoding.ASCII.GetBytes("MZ" + new string('x', 62)), "exe");

    [Fact]
    public void TrueTypeHighConfidenceRequiresFlavorSpecificMandatoryTables()
    {
        byte[] complete = CompleteTrueType();
        AssertParity(complete, "ttf", "High", "sfnt:truetype");
        complete[CompleteTrueTypeHeadAdjustmentOffset()] ^= 1;
        AssertParity(complete, "ttf", "Medium", "whole-font-checksum-invalid");
        byte[] incomplete = CompleteTrueType();
        Encoding.ASCII.GetBytes("zzzz").CopyTo(incomplete, 12);
        AssertParity(incomplete, "ttf", "Medium", "mandatory-tables-missing");
    }

    private static byte[] LegacyExecutable(string family)
    {
        int secondaryOffset = family == "dos" ? 0 : 0x80;
        var bytes = new byte[family == "dos" ? 64 : family == "ne" ? 0xC8 : 0x200];
        Encoding.ASCII.GetBytes("MZ").CopyTo(bytes, 0);
        TestHelpers.WriteUInt16LittleEndian(bytes, 2, 64);
        TestHelpers.WriteUInt16LittleEndian(bytes, 4, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, 8, 4);
        TestHelpers.WriteUInt16LittleEndian(bytes, 0x18, 0x1C);
        TestHelpers.WriteUInt32LittleEndian(bytes, 0x3C, (uint)secondaryOffset);
        if (family == "dos") return bytes;

        Encoding.ASCII.GetBytes(family.ToUpperInvariant()).CopyTo(bytes, secondaryOffset);
        if (family == "ne")
        {
            TestHelpers.WriteUInt16LittleEndian(bytes, secondaryOffset + 0x1C, 1);
            TestHelpers.WriteUInt16LittleEndian(bytes, secondaryOffset + 0x22, 0x40);
            bytes[secondaryOffset + 0x36] = 2;
            return bytes;
        }

        TestHelpers.WriteUInt16LittleEndian(bytes, secondaryOffset + 8, 2);
        TestHelpers.WriteUInt32LittleEndian(bytes, secondaryOffset + 20, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, secondaryOffset + 40, 4096);
        TestHelpers.WriteUInt32LittleEndian(bytes, secondaryOffset + 64, 0xB0);
        TestHelpers.WriteUInt32LittleEndian(bytes, secondaryOffset + 68, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, secondaryOffset + 72, 0xC8);
        TestHelpers.WriteUInt32LittleEndian(bytes, secondaryOffset + 128, 0x148);
        return bytes;
    }

    private static byte[] CompleteTrueType()
    {
        string[] tags = { "OS/2", "cmap", "glyf", "head", "hhea", "hmtx", "loca", "maxp", "name", "post" };
        int directoryEnd = 12 + tags.Length * 16;
        int payloadLength = tags.Length * 4 + 8;
        var bytes = new byte[directoryEnd + payloadLength];
        TestHelpers.WriteUInt32BigEndian(bytes, 0, 0x00010000);
        TestHelpers.WriteUInt16BigEndian(bytes, 4, (ushort)tags.Length);
        TestHelpers.WriteUInt16BigEndian(bytes, 6, 128);
        TestHelpers.WriteUInt16BigEndian(bytes, 8, 3);
        TestHelpers.WriteUInt16BigEndian(bytes, 10, 32);
        int payload = directoryEnd;
        for (int index = 0; index < tags.Length; index++)
        {
            int record = 12 + index * 16;
            Encoding.ASCII.GetBytes(tags[index]).CopyTo(bytes, record);
            int length = tags[index] == "head" ? 12 : 4;
            TestHelpers.WriteUInt32BigEndian(bytes, record + 8, (uint)payload);
            TestHelpers.WriteUInt32BigEndian(bytes, record + 12, (uint)length);
            payload += length;
        }
        int adjustmentOffset = CompleteTrueTypeHeadAdjustmentOffset();
        TestHelpers.WriteUInt32BigEndian(bytes, adjustmentOffset,
            unchecked(0xB1B0AFBAu - ComputeSfntChecksum(bytes)));
        return bytes;
    }

    private static int CompleteTrueTypeHeadAdjustmentOffset()
    {
        const int tableCount = 10;
        int directoryEnd = 12 + tableCount * 16;
        return directoryEnd + 3 * 4 + 8;
    }

    private static uint ComputeSfntChecksum(byte[] bytes)
    {
        uint sum = 0;
        for (int offset = 0; offset < bytes.Length; offset += 4)
        {
            uint word = 0;
            for (int index = 0; index < 4; index++)
                word = word << 8 | (uint)(offset + index < bytes.Length ? bytes[offset + index] : 0);
            unchecked { sum += word; }
        }
        return sum;
    }

    private static void AssertParity(byte[] bytes, string extension, string confidence, string reason)
    {
        ContentTypeDetectionResult? fromBytes = FileInspector.Detect(bytes);
        using var stream = new MemoryStream(bytes, writable: false) { Position = Math.Min(3, bytes.Length) };
        ContentTypeDetectionResult? fromStream = FileInspector.Detect(stream);
        Assert.Equal(extension, fromBytes?.Extension);
        Assert.Equal(extension, fromStream?.Extension);
        Assert.Equal(confidence, fromBytes?.Confidence);
        Assert.Equal(confidence, fromStream?.Confidence);
        Assert.Contains(reason, fromBytes?.Reason ?? string.Empty, StringComparison.Ordinal);
        Assert.Contains(reason, fromStream?.Reason ?? string.Empty, StringComparison.Ordinal);
        if (extension == "exe")
        {
            Assert.True(fromBytes?.IsDangerous);
            Assert.True(fromStream?.IsDangerous);
        }
        Assert.Equal(Math.Min(3, bytes.Length), stream.Position);

        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".bin");
        try
        {
            File.WriteAllBytes(path, bytes);
            ContentTypeDetectionResult? fromPath = FileInspector.Detect(path);
            Assert.Equal(extension, fromPath?.Extension);
            Assert.Equal(confidence, fromPath?.Confidence);
            Assert.Contains(reason, fromPath?.Reason ?? string.Empty, StringComparison.Ordinal);
            if (extension == "exe") Assert.True(fromPath?.IsDangerous);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    private static void AssertNotDetectedAs(byte[] bytes, string extension)
    {
        Assert.NotEqual(extension, FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false);
        Assert.NotEqual(extension, FileInspector.Detect(stream)?.Extension);
    }
}
