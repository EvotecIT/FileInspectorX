using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class ThirtyFifthReviewRegressionTests
{
    [Fact]
    public void Dex041ValidatesEveryContainerMember()
    {
        byte[] valid = TestHelpers.CreateDex041Container();
        AssertParity(valid, "dex", "High");

        byte[] corruptSecondMember = (byte[])valid.Clone();
        corruptSecondMember[148 + 12] ^= 0x01;
        AssertNotDetectedAs(corruptSecondMember, "dex");
    }

    [Fact]
    public void SfntChecksumsDoNotSubstituteForMandatoryTables()
    {
        byte[] valid = ChecksummedSfnt();
        AssertParity(valid, "ttf", "Medium");

        byte[] corruptName = (byte[])valid.Clone();
        corruptName[56] ^= 0x01;
        AssertNotDetectedAs(corruptName, "ttf");

        byte[] changedAdjustment = (byte[])valid.Clone();
        TestHelpers.WriteUInt32BigEndian(changedAdjustment, 52, 0x87654321);
        AssertParity(changedAdjustment, "ttf", "Medium");
    }

    [Fact]
    public void ShellLinkExtraDataUsesSignatureSpecificFraming()
    {
        AssertParity(ShellLinkExtraData(0xA0000002, 0xCC), "lnk", "High");
        AssertNotDetectedAs(ShellLinkExtraData(0xA0000002, 8), "lnk");
        AssertParity(ShellLinkExtraData(0xA00000FF, 8), "lnk", "Medium");
    }

    private static byte[] ChecksummedSfnt()
    {
        var bytes = new byte[60];
        TestHelpers.WriteUInt32BigEndian(bytes, 0, 0x00010000);
        TestHelpers.WriteUInt16BigEndian(bytes, 4, 2);
        TestHelpers.WriteUInt16BigEndian(bytes, 6, 32);
        TestHelpers.WriteUInt16BigEndian(bytes, 8, 1);

        Encoding.ASCII.GetBytes("head").CopyTo(bytes, 12);
        TestHelpers.WriteUInt32BigEndian(bytes, 20, 44);
        TestHelpers.WriteUInt32BigEndian(bytes, 24, 12);
        TestHelpers.WriteUInt32BigEndian(bytes, 52, 0x12345678);

        Encoding.ASCII.GetBytes("name").CopyTo(bytes, 28);
        TestHelpers.WriteUInt32BigEndian(bytes, 32, 0x74657374);
        TestHelpers.WriteUInt32BigEndian(bytes, 36, 56);
        TestHelpers.WriteUInt32BigEndian(bytes, 40, 4);
        Encoding.ASCII.GetBytes("test").CopyTo(bytes, 56);
        return bytes;
    }

    private static byte[] ShellLinkExtraData(uint signature, int blockSize)
    {
        var bytes = new byte[76 + blockSize + 4];
        bytes[0] = 0x4C;
        new byte[] {
            0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
        }.CopyTo(bytes, 4);
        TestHelpers.WriteUInt32LittleEndian(bytes, 60, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 76, (uint)blockSize);
        TestHelpers.WriteUInt32LittleEndian(bytes, 80, signature);
        return bytes;
    }

    private static void AssertParity(byte[] bytes, string extension, string confidence)
    {
        ContentTypeDetectionResult? fromBytes = FileInspector.Detect(bytes);
        using var stream = new MemoryStream(bytes, writable: false) { Position = Math.Min(3, bytes.Length) };
        ContentTypeDetectionResult? fromStream = FileInspector.Detect(stream);
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
