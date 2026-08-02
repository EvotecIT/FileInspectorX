using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class TwentyFourthReviewRegressionTests
{
    [Fact]
    public void Qcow2L1TableMustCoverTheVirtualDisk()
    {
        byte[] valid = Qcow2(l1Size: 32, extendedL2: false);
        AssertParity(valid, "qcow2");

        AssertNotDetectedAs(Qcow2(l1Size: 31, extendedL2: false), "qcow2");
        AssertParity(Qcow2(l1Size: 64, extendedL2: true), "qcow2");
        AssertNotDetectedAs(Qcow2(l1Size: 63, extendedL2: true), "qcow2");
    }

    [Fact]
    public void CabRequiresDeclaredFolderDataBlocksAndKnownCompression()
    {
        byte[] valid = Cab(includeDataBlock: true);
        AssertParity(valid, "cab");

        AssertNotDetectedAs(Cab(includeDataBlock: false), "cab");

        byte[] unknownCompression = (byte[])valid.Clone();
        WriteUInt16LittleEndian(unknownCompression, 46, 4);
        AssertNotDetectedAs(unknownCompression, "cab");
    }

    [Fact]
    public void DdsRejectsReservedDxgiFormat191()
    {
        AssertParity(DdsDx10(dxgiFormat: 190), "dds");
        AssertNotDetectedAs(DdsDx10(dxgiFormat: 191), "dds");
    }

    private static void AssertParity(byte[] bytes, string extension)
    {
        var fromBytes = FileInspector.Detect(bytes);
        Assert.Equal(extension, fromBytes?.Extension);
        Assert.Equal("High", fromBytes?.Confidence);

        using var stream = new MemoryStream(bytes, writable: false) { Position = Math.Min(3, bytes.Length) };
        var fromStream = FileInspector.Detect(stream);
        Assert.Equal(extension, fromStream?.Extension);
        Assert.Equal("High", fromStream?.Confidence);
        Assert.Equal(Math.Min(3, bytes.Length), stream.Position);
    }

    private static void AssertNotDetectedAs(byte[] bytes, string extension)
    {
        Assert.NotEqual(extension, FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false);
        Assert.NotEqual(extension, FileInspector.Detect(stream)?.Extension);
    }

    private static byte[] Qcow2(uint l1Size, bool extendedL2)
    {
        var bytes = new byte[2048];
        new byte[] { (byte)'Q', (byte)'F', (byte)'I', 0xFB }.CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 4, 3);
        WriteUInt32BigEndian(bytes, 20, 9);
        WriteUInt64BigEndian(bytes, 24, 1024 * 1024);
        WriteUInt32BigEndian(bytes, 36, l1Size);
        WriteUInt64BigEndian(bytes, 40, 512);
        WriteUInt64BigEndian(bytes, 48, 1024);
        WriteUInt32BigEndian(bytes, 56, 1);
        if (extendedL2) WriteUInt64BigEndian(bytes, 72, 0x10);
        WriteUInt32BigEndian(bytes, 100, 104);
        return bytes;
    }

    private static byte[] Cab(bool includeDataBlock)
    {
        const int dataOffset = 66;
        const byte dataReserve = 2;
        int length = includeDataBlock ? dataOffset + 8 + dataReserve + 1 : dataOffset;
        var bytes = new byte[length];
        Encoding.ASCII.GetBytes("MSCF").CopyTo(bytes, 0);
        WriteUInt32LittleEndian(bytes, 8, (uint)length);
        WriteUInt32LittleEndian(bytes, 16, 48);
        bytes[24] = 3;
        bytes[25] = 1;
        WriteUInt16LittleEndian(bytes, 26, 1);
        WriteUInt16LittleEndian(bytes, 28, 1);
        WriteUInt16LittleEndian(bytes, 30, 4);
        bytes[39] = dataReserve;
        WriteUInt32LittleEndian(bytes, 40, dataOffset);
        WriteUInt16LittleEndian(bytes, 44, 1);
        WriteUInt32LittleEndian(bytes, 48, 1);
        bytes[64] = (byte)'a';
        if (includeDataBlock)
        {
            WriteUInt16LittleEndian(bytes, dataOffset + 4, 1);
            WriteUInt16LittleEndian(bytes, dataOffset + 6, 1);
            bytes[length - 1] = 0x41;
        }
        return bytes;
    }

    private static byte[] DdsDx10(uint dxgiFormat)
    {
        var bytes = new byte[148];
        Encoding.ASCII.GetBytes("DDS ").CopyTo(bytes, 0);
        WriteUInt32LittleEndian(bytes, 4, 124);
        WriteUInt32LittleEndian(bytes, 8, 0x1007);
        WriteUInt32LittleEndian(bytes, 12, 1);
        WriteUInt32LittleEndian(bytes, 16, 1);
        WriteUInt32LittleEndian(bytes, 76, 32);
        WriteUInt32LittleEndian(bytes, 80, 4);
        Encoding.ASCII.GetBytes("DX10").CopyTo(bytes, 84);
        WriteUInt32LittleEndian(bytes, 108, 0x1000);
        WriteUInt32LittleEndian(bytes, 128, dxgiFormat);
        WriteUInt32LittleEndian(bytes, 132, 3);
        WriteUInt32LittleEndian(bytes, 140, 1);
        return bytes;
    }

    private static void WriteUInt16LittleEndian(byte[] bytes, int offset, ushort value)
    {
        bytes[offset] = (byte)value;
        bytes[offset + 1] = (byte)(value >> 8);
    }

    private static void WriteUInt32LittleEndian(byte[] bytes, int offset, uint value)
    {
        for (int index = 0; index < 4; index++) bytes[offset + index] = (byte)(value >> (index * 8));
    }

    private static void WriteUInt32BigEndian(byte[] bytes, int offset, uint value)
    {
        bytes[offset] = (byte)(value >> 24);
        bytes[offset + 1] = (byte)(value >> 16);
        bytes[offset + 2] = (byte)(value >> 8);
        bytes[offset + 3] = (byte)value;
    }

    private static void WriteUInt64BigEndian(byte[] bytes, int offset, ulong value)
    {
        for (int index = 0; index < 8; index++) bytes[offset + index] = (byte)(value >> ((7 - index) * 8));
    }
}
