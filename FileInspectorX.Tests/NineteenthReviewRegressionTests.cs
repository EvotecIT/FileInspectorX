using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class NineteenthReviewRegressionTests
{
    [Fact]
    public void VhdAllowsOriginalAndCurrentSizesToDifferAfterResize()
    {
        var bytes = TestHelpers.CreateMinimalVhd();
        int footer = bytes.Length - 512;
        WriteUInt64BigEndian(bytes, footer + 40, 1024);
        FinalizeVhdFooter(bytes, footer);

        AssertParity(bytes, "vhd");
    }

    [Fact]
    public void TtcVersion2RequiresTheDsigHeaderTriple()
    {
        AssertParity(TtcVersion2(includeDsigFields: true), "ttc");
        AssertNotDetectedAs("ttc", TtcVersion2(includeDsigFields: false));
    }

    [Theory]
    [InlineData(45, 3, true)]
    [InlineData(45, 4, false)]
    [InlineData(55, 0, true)]
    [InlineData(55, 123, false)]
    public void JavaEnforcesDefinedLegacyMinorVersions(ushort major, ushort minor, bool expected)
    {
        var bytes = JavaClass();
        WriteUInt16BigEndian(bytes, 4, minor);
        WriteUInt16BigEndian(bytes, 6, major);
        if (expected) AssertParity(bytes, "class");
        else AssertNotDetectedAs("class", bytes);
    }

    [Fact]
    public void BigTiffRequiresEightByteIfdAlignment()
    {
        AssertParity(BigTiff(24), "tif");
        AssertNotDetectedAs("tif", BigTiff(18));
    }

    private static void AssertParity(byte[] bytes, string extension)
    {
        Assert.Equal(extension, FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false) { Position = Math.Min(2, bytes.Length) };
        Assert.Equal(extension, FileInspector.Detect(stream)?.Extension);
        Assert.Equal(Math.Min(2, bytes.Length), stream.Position);
    }

    private static void AssertNotDetectedAs(string extension, byte[] bytes)
    {
        Assert.NotEqual(extension, FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false);
        Assert.NotEqual(extension, FileInspector.Detect(stream)?.Extension);
    }

    private static byte[] TtcVersion2(bool includeDsigFields)
    {
        int directoryOffset = includeDsigFields ? 28 : 16;
        var bytes = new byte[directoryOffset + 32];
        Encoding.ASCII.GetBytes("ttcf").CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 4, 0x00020000);
        WriteUInt32BigEndian(bytes, 8, 1);
        WriteUInt32BigEndian(bytes, 12, (uint)directoryOffset);
        WriteUInt32BigEndian(bytes, directoryOffset, 0x00010000);
        WriteUInt16BigEndian(bytes, directoryOffset + 4, 1);
        WriteUInt16BigEndian(bytes, directoryOffset + 6, 16);
        Encoding.ASCII.GetBytes("head").CopyTo(bytes, directoryOffset + 12);
        WriteUInt32BigEndian(bytes, directoryOffset + 20, (uint)(directoryOffset + 28));
        WriteUInt32BigEndian(bytes, directoryOffset + 24, 4);
        Encoding.ASCII.GetBytes("data").CopyTo(bytes, directoryOffset + 28);
        return bytes;
    }

    private static byte[] JavaClass() => new byte[]
    {
        0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34, 0x00, 0x05,
        0x01, 0x00, 0x01, 0x41,
        0x07, 0x00, 0x01,
        0x01, 0x00, 0x10, 0x6A, 0x61, 0x76, 0x61, 0x2F, 0x6C, 0x61, 0x6E, 0x67, 0x2F, 0x4F, 0x62, 0x6A, 0x65, 0x63, 0x74,
        0x07, 0x00, 0x03,
        0x00, 0x21, 0x00, 0x02, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    private static byte[] BigTiff(ulong firstIfd)
    {
        var bytes = new byte[checked((int)firstIfd + 16)];
        bytes[0] = (byte)'I'; bytes[1] = (byte)'I';
        TestHelpers.WriteUInt16LittleEndian(bytes, 2, 43);
        TestHelpers.WriteUInt16LittleEndian(bytes, 4, 8);
        WriteUInt64LittleEndian(bytes, 8, firstIfd);
        return bytes;
    }

    private static void FinalizeVhdFooter(byte[] bytes, int footer)
    {
        WriteUInt32BigEndian(bytes, footer + 64, 0);
        uint sum = 0;
        for (int index = 0; index < 512; index++)
            if (index < 64 || index >= 68) sum += bytes[footer + index];
        WriteUInt32BigEndian(bytes, footer + 64, ~sum);
    }

    private static void WriteUInt16BigEndian(byte[] bytes, int offset, ushort value)
    {
        bytes[offset] = (byte)(value >> 8); bytes[offset + 1] = (byte)value;
    }

    private static void WriteUInt32BigEndian(byte[] bytes, int offset, uint value)
    {
        for (int index = 0; index < 4; index++) bytes[offset + 3 - index] = (byte)(value >> (8 * index));
    }

    private static void WriteUInt64BigEndian(byte[] bytes, int offset, ulong value)
    {
        for (int index = 0; index < 8; index++) bytes[offset + 7 - index] = (byte)(value >> (8 * index));
    }

    private static void WriteUInt64LittleEndian(byte[] bytes, int offset, ulong value)
    {
        for (int index = 0; index < 8; index++) bytes[offset + index] = (byte)(value >> (8 * index));
    }
}
