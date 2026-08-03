using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class ThirtiethReviewRegressionTests
{
    [Fact]
    public void DdsDx10PitchCoversEveryImageRow()
    {
        Assert.Equal("dds", FileInspector.Detect(DdsDx10(64))?.Extension);
        AssertNotDetectedAs(DdsDx10(16), "dds");
    }

    [Fact]
    public void IconPngDimensionsMustMatchDirectoryEntry()
    {
        Assert.Equal("ico", FileInspector.Detect(Icon(TestHelpers.CreateMinimalPng(), 1, 1))?.Extension);
        AssertNotDetectedAs(Icon(TestHelpers.CreateMinimalPng(), 2, 1), "ico");
    }

    [Fact]
    public void SfntTablePayloadsCannotOverlap()
    {
        Assert.Equal("ttf", FileInspector.Detect(Sfnt(overlap: false))?.Extension);
        AssertNotDetectedAs(Sfnt(overlap: true), "ttf");
    }

    [Fact]
    public void CompleteDexRequiresItsMapList()
    {
        byte[] bytes = TestHelpers.CreateMinimalDex();
        TestHelpers.WriteUInt32LittleEndian(bytes, 52, 0);
        TestHelpers.FinalizeDex(bytes);
        AssertNotDetectedAs(bytes, "dex");
    }

    [Fact]
    public void ShellLinkIdListMustEndWithATerminalItem()
    {
        Assert.Equal("lnk", FileInspector.Detect(ShellLink(validIdList: true))?.Extension);
        AssertNotDetectedAs(ShellLink(validIdList: false), "lnk");
    }

    [Fact]
    public void OpenExrChunkCoordinateMustFitTheDataWindow()
    {
        byte[] bytes = TestHelpers.CreateMinimalOpenExr();
        TestHelpers.WriteUInt32LittleEndian(bytes, bytes.Length - 12, 1);
        AssertNotDetectedAs(bytes, "exr");
    }

    [Fact]
    public void Jpeg2000CodestreamRequiresASizeMarker()
    {
        byte[] bytes = TestHelpers.CreateMinimalJpeg2000();
        int codestream = Find(bytes, new byte[] { 0xFF, 0x4F, 0xFF, 0x51 });
        Assert.True(codestream >= 0);
        bytes[codestream + 3] = 0x52;
        AssertNotDetectedAs(bytes, "jp2");
    }

    [Fact]
    public void Qcow2RejectsUnknownIncompatibleFeatureBits()
    {
        byte[] bytes = Qcow2();
        TestHelpers.WriteUInt64BigEndian(bytes, 72, 0x20);
        AssertNotDetectedAs(bytes, "qcow2");
    }

    [Fact]
    public void DicomFileMetaTagsMustBeStrictlyIncreasing()
    {
        byte[] bytes = TestHelpers.CreateMinimalDicom();
        TestHelpers.WriteUInt16LittleEndian(bytes, 160, 0);
        AssertNotDetectedAs(bytes, "dcm");
    }

    [Fact]
    public void ModernHdf5RequiresARootObjectHeaderSignature()
    {
        byte[] bytes = ModernHdf5();
        Assert.Equal("h5", FileInspector.Detect(bytes)?.Extension);
        bytes[48] = (byte)'X';
        AssertNotDetectedAs(bytes, "h5");
    }

    private static void AssertNotDetectedAs(byte[] bytes, string extension)
    {
        Assert.NotEqual(extension, FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false);
        Assert.NotEqual(extension, FileInspector.Detect(stream)?.Extension);
    }

    private static byte[] DdsDx10(int payloadLength)
    {
        var bytes = new byte[148 + payloadLength];
        Encoding.ASCII.GetBytes("DDS ").CopyTo(bytes, 0);
        TestHelpers.WriteUInt32LittleEndian(bytes, 4, 124);
        TestHelpers.WriteUInt32LittleEndian(bytes, 8, 0x100F);
        TestHelpers.WriteUInt32LittleEndian(bytes, 12, 4);
        TestHelpers.WriteUInt32LittleEndian(bytes, 16, 4);
        TestHelpers.WriteUInt32LittleEndian(bytes, 20, 16);
        TestHelpers.WriteUInt32LittleEndian(bytes, 76, 32);
        TestHelpers.WriteUInt32LittleEndian(bytes, 80, 4);
        Encoding.ASCII.GetBytes("DX10").CopyTo(bytes, 84);
        TestHelpers.WriteUInt32LittleEndian(bytes, 108, 0x1000);
        TestHelpers.WriteUInt32LittleEndian(bytes, 128, 28);
        TestHelpers.WriteUInt32LittleEndian(bytes, 132, 3);
        TestHelpers.WriteUInt32LittleEndian(bytes, 140, 1);
        return bytes;
    }

    private static byte[] Icon(byte[] payload, byte width, byte height)
    {
        var bytes = new byte[22 + payload.Length];
        TestHelpers.WriteUInt16LittleEndian(bytes, 2, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, 4, 1);
        bytes[6] = width; bytes[7] = height;
        TestHelpers.WriteUInt16LittleEndian(bytes, 10, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, 12, 32);
        TestHelpers.WriteUInt32LittleEndian(bytes, 14, (uint)payload.Length);
        TestHelpers.WriteUInt32LittleEndian(bytes, 18, 22);
        payload.CopyTo(bytes, 22);
        return bytes;
    }

    private static byte[] Sfnt(bool overlap)
    {
        var bytes = new byte[64];
        TestHelpers.WriteUInt32BigEndian(bytes, 0, 0x00010000);
        TestHelpers.WriteUInt16BigEndian(bytes, 4, 2);
        TestHelpers.WriteUInt16BigEndian(bytes, 6, 32);
        TestHelpers.WriteUInt16BigEndian(bytes, 8, 1);
        Encoding.ASCII.GetBytes("head").CopyTo(bytes, 12);
        TestHelpers.WriteUInt32BigEndian(bytes, 20, 44);
        TestHelpers.WriteUInt32BigEndian(bytes, 24, 8);
        Encoding.ASCII.GetBytes("name").CopyTo(bytes, 28);
        TestHelpers.WriteUInt32BigEndian(bytes, 36, overlap ? 48u : 52u);
        TestHelpers.WriteUInt32BigEndian(bytes, 40, 8);
        return bytes;
    }

    private static byte[] ShellLink(bool validIdList)
    {
        var bytes = new byte[86];
        bytes[0] = 0x4C;
        new byte[] { 0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46 }.CopyTo(bytes, 4);
        TestHelpers.WriteUInt32LittleEndian(bytes, 20, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 60, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, 76, 4);
        TestHelpers.WriteUInt16LittleEndian(bytes, 78, validIdList ? (ushort)2 : (ushort)4);
        return bytes;
    }

    private static byte[] Qcow2()
    {
        var bytes = new byte[2048];
        new byte[] { (byte)'Q', (byte)'F', (byte)'I', 0xFB }.CopyTo(bytes, 0);
        TestHelpers.WriteUInt32BigEndian(bytes, 4, 3);
        TestHelpers.WriteUInt32BigEndian(bytes, 20, 9);
        TestHelpers.WriteUInt64BigEndian(bytes, 24, 1024 * 1024);
        TestHelpers.WriteUInt32BigEndian(bytes, 36, 4);
        TestHelpers.WriteUInt64BigEndian(bytes, 40, 512);
        TestHelpers.WriteUInt64BigEndian(bytes, 48, 1024);
        TestHelpers.WriteUInt32BigEndian(bytes, 56, 1);
        TestHelpers.WriteUInt32BigEndian(bytes, 100, 104);
        return bytes;
    }

    private static int Find(byte[] bytes, byte[] pattern)
    {
        for (int index = 0; index <= bytes.Length - pattern.Length; index++)
        {
            bool match = true;
            for (int part = 0; part < pattern.Length; part++) if (bytes[index + part] != pattern[part]) { match = false; break; }
            if (match) return index;
        }
        return -1;
    }

    private static byte[] ModernHdf5()
    {
        var bytes = new byte[64];
        new byte[] { 0x89, (byte)'H', (byte)'D', (byte)'F', 0x0D, 0x0A, 0x1A, 0x0A, 2, 8, 8, 0 }.CopyTo(bytes, 0);
        for (int index = 20; index < 28; index++) bytes[index] = 0xFF;
        TestHelpers.WriteUInt64LittleEndian(bytes, 28, 64);
        TestHelpers.WriteUInt64LittleEndian(bytes, 36, 48);
        TestHelpers.WriteUInt32LittleEndian(bytes, 44, Hdf5Checksum(new ReadOnlySpan<byte>(bytes, 0, 44)));
        Encoding.ASCII.GetBytes("OHDR").CopyTo(bytes, 48);
        bytes[52] = 2;
        return bytes;
    }

    private static uint Hdf5Checksum(ReadOnlySpan<byte> src)
    {
        unchecked
        {
            uint a = 0xDEADBEEF + (uint)src.Length, b = a, c = a;
            int cursor = 0, remaining = src.Length;
            while (remaining > 12)
            {
                a += Read32(src, cursor); b += Read32(src, cursor + 4); c += Read32(src, cursor + 8);
                a -= c; a ^= Rotate(c, 4); c += b; b -= a; b ^= Rotate(a, 6); a += c;
                c -= b; c ^= Rotate(b, 8); b += a; a -= c; a ^= Rotate(c, 16); c += b;
                b -= a; b ^= Rotate(a, 19); a += c; c -= b; c ^= Rotate(b, 4); b += a;
                cursor += 12; remaining -= 12;
            }
            for (int index = 0; index < remaining; index++)
            {
                uint value = (uint)src[cursor + index] << ((index % 4) * 8);
                if (index < 4) a += value; else if (index < 8) b += value; else c += value;
            }
            if (remaining == 0) return c;
            c ^= b; c -= Rotate(b, 14); a ^= c; a -= Rotate(c, 11); b ^= a; b -= Rotate(a, 25);
            c ^= b; c -= Rotate(b, 16); a ^= c; a -= Rotate(c, 4); b ^= a; b -= Rotate(a, 14); c ^= b; c -= Rotate(b, 24);
            return c;
        }
    }

    private static uint Read32(ReadOnlySpan<byte> src, int offset)
        => (uint)(src[offset] | src[offset + 1] << 8 | src[offset + 2] << 16 | src[offset + 3] << 24);

    private static uint Rotate(uint value, int count) => value << count | value >> (32 - count);
}
