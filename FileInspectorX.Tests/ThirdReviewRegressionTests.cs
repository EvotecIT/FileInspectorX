using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class ThirdReviewRegressionTests
{
    [Fact]
    public void Woff2DirectoryBeyondSixtyFourBytesKeepsApiParity()
        => AssertParity(Woff2WithLongDirectory(), "woff2");

    [Fact]
    public void NetCdfHeaderLargerThanOneMebibyteKeepsApiParity()
        => AssertParity(NetCdfWithLargeGlobalAttribute(), "nc");

    [Fact]
    public void Qcow2LuksEncryptionRequiresItsHeaderPointerExtension()
    {
        AssertParity(Qcow2Luks(), "qcow2");

        var missingExtension = Qcow2Luks();
        WriteUInt32BigEndian(missingExtension, 104, 0);
        Assert.NotEqual("qcow2", FileInspector.Detect(missingExtension)?.Extension);

        var truncatedEncryptionHeader = Qcow2Luks();
        WriteUInt64BigEndian(truncatedEncryptionHeader, 112, (ulong)truncatedEncryptionHeader.Length);
        Assert.NotEqual("qcow2", FileInspector.Detect(truncatedEncryptionHeader)?.Extension);
    }

    [Fact]
    public void Hdf5UserBlockUsesBaseRelativeEndOfFileAddress()
        => AssertParity(Hdf5WithUserBlock(), "h5");

    [Fact]
    public void DeepTiledOpenExrIsAccepted()
        => AssertParity(new byte[] { 0x76, 0x2F, 0x31, 0x01, 0x02, 0x0A, 0x00, 0x00 }, "exr");

    [Theory]
    [InlineData((ushort)0, "none")]
    [InlineData((ushort)0xFE00, "os-specific")]
    [InlineData((ushort)0xFF00, "processor-specific")]
    public void DefinedElfFileTypesAreAccepted(ushort fileType, string reasonPart)
    {
        var result = FileInspector.Detect(Elf(fileType));

        Assert.Equal("elf", result?.Extension);
        Assert.Contains(reasonPart, result?.Reason);
    }

    [Fact]
    public void ReservedElfFileTypeIsRejected()
        => Assert.NotEqual("elf", FileInspector.Detect(Elf(5))?.Extension);

    [Fact]
    public void ParquetEncryptedFooterUsesPareAtBothEnds()
    {
        AssertParity(Parquet("PARE", "PARE"), "parquet");
        Assert.NotEqual("parquet", FileInspector.Detect(Parquet("PAR1", "PARE"))?.Extension);
    }

    private static void AssertParity(byte[] bytes, string extension)
    {
        Assert.Equal(extension, FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false);
        long position = Math.Min(7, stream.Length);
        stream.Position = position;
        Assert.Equal(extension, FileInspector.Detect(stream)?.Extension);
        Assert.Equal(position, stream.Position);

        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".bin");
        try
        {
            File.WriteAllBytes(path, bytes);
            Assert.Equal(extension, FileInspector.Detect(path)?.Extension);
        }
        finally
        {
            TestHelpers.SafeDelete(path);
        }
    }

    private static byte[] Woff2WithLongDirectory()
    {
        const int tableCount = 9;
        var bytes = new byte[48 + tableCount * 2 + 1];
        Encoding.ASCII.GetBytes("wOF2true").CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 8, (uint)bytes.Length);
        WriteUInt16BigEndian(bytes, 12, tableCount);
        WriteUInt32BigEndian(bytes, 16, 12 + tableCount * 16);
        WriteUInt32BigEndian(bytes, 20, 1);
        for (int table = 0; table < tableCount; table++)
        {
            bytes[48 + table * 2] = (byte)table;
            bytes[49 + table * 2] = 1;
        }
        return bytes;
    }

    private static byte[] NetCdfWithLargeGlobalAttribute()
    {
        const int valueLength = (1 << 20) + 4;
        var bytes = new byte[40 + valueLength + 8];
        Encoding.ASCII.GetBytes("CDF\u0001").CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 16, 12);
        WriteUInt32BigEndian(bytes, 20, 1);
        WriteUInt32BigEndian(bytes, 24, 1);
        bytes[28] = (byte)'a';
        WriteUInt32BigEndian(bytes, 32, 1);
        WriteUInt32BigEndian(bytes, 36, valueLength);
        return bytes;
    }

    private static byte[] Qcow2Luks()
    {
        var bytes = new byte[0x40000];
        new byte[] { (byte)'Q', (byte)'F', (byte)'I', 0xFB }.CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 4, 3);
        WriteUInt32BigEndian(bytes, 20, 16);
        WriteUInt64BigEndian(bytes, 24, 1024 * 1024);
        WriteUInt32BigEndian(bytes, 32, 2);
        WriteUInt32BigEndian(bytes, 36, 1);
        WriteUInt64BigEndian(bytes, 40, 0x10000);
        WriteUInt64BigEndian(bytes, 48, 0x20000);
        WriteUInt32BigEndian(bytes, 56, 1);
        WriteUInt32BigEndian(bytes, 100, 104);
        WriteUInt32BigEndian(bytes, 104, 0x0537BE77);
        WriteUInt32BigEndian(bytes, 108, 16);
        WriteUInt64BigEndian(bytes, 112, 0x30000);
        WriteUInt64BigEndian(bytes, 120, 592);
        return bytes;
    }

    private static byte[] Hdf5WithUserBlock()
    {
        const int userBlock = 4096;
        var bytes = new byte[userBlock + 128];
        new byte[] { 0x89, (byte)'H', (byte)'D', (byte)'F', 0x0D, 0x0A, 0x1A, 0x0A }.CopyTo(bytes, userBlock);
        bytes[userBlock + 8] = 2;
        bytes[userBlock + 9] = 8;
        bytes[userBlock + 10] = 8;
        WriteUInt64LittleEndian(bytes, userBlock + 12, userBlock);
        for (int i = userBlock + 20; i < userBlock + 28; i++) bytes[i] = 0xFF;
        WriteUInt64LittleEndian(bytes, userBlock + 28, 128);
        WriteUInt64LittleEndian(bytes, userBlock + 36, 48);
        WriteUInt32LittleEndian(bytes, userBlock + 44,
            ComputeHdf5SuperblockChecksum(new ReadOnlySpan<byte>(bytes, userBlock, 44)));
        Encoding.ASCII.GetBytes("OHDR").CopyTo(bytes, userBlock + 48);
        return bytes;
    }

    private static byte[] Elf(ushort fileType)
    {
        var bytes = new byte[64];
        new byte[] { 0x7F, (byte)'E', (byte)'L', (byte)'F', 2, 1, 1 }.CopyTo(bytes, 0);
        WriteUInt16LittleEndian(bytes, 16, fileType);
        WriteUInt16LittleEndian(bytes, 18, 62);
        WriteUInt32LittleEndian(bytes, 20, 1);
        WriteUInt16LittleEndian(bytes, 52, 64);
        return bytes;
    }

    private static byte[] Parquet(string start, string end)
    {
        var bytes = new byte[13];
        Encoding.ASCII.GetBytes(start).CopyTo(bytes, 0);
        bytes[4] = 1;
        WriteUInt32LittleEndian(bytes, 5, 1);
        Encoding.ASCII.GetBytes(end).CopyTo(bytes, 9);
        return bytes;
    }

    private static uint ComputeHdf5SuperblockChecksum(ReadOnlySpan<byte> src)
    {
        unchecked
        {
            uint a = 0xDEADBEEF + (uint)src.Length;
            uint b = a;
            uint c = a;
            int cursor = 0;
            int remaining = src.Length;
            while (remaining > 12)
            {
                a += ReadUInt32LittleEndian(src, cursor);
                b += ReadUInt32LittleEndian(src, cursor + 4);
                c += ReadUInt32LittleEndian(src, cursor + 8);
                Mix(ref a, ref b, ref c);
                cursor += 12;
                remaining -= 12;
            }
            switch (remaining)
            {
                case 12: c += (uint)src[cursor + 11] << 24; goto case 11;
                case 11: c += (uint)src[cursor + 10] << 16; goto case 10;
                case 10: c += (uint)src[cursor + 9] << 8; goto case 9;
                case 9: c += src[cursor + 8]; goto case 8;
                case 8: b += (uint)src[cursor + 7] << 24; goto case 7;
                case 7: b += (uint)src[cursor + 6] << 16; goto case 6;
                case 6: b += (uint)src[cursor + 5] << 8; goto case 5;
                case 5: b += src[cursor + 4]; goto case 4;
                case 4: a += (uint)src[cursor + 3] << 24; goto case 3;
                case 3: a += (uint)src[cursor + 2] << 16; goto case 2;
                case 2: a += (uint)src[cursor + 1] << 8; goto case 1;
                case 1: a += src[cursor]; break;
                case 0: return c;
            }
            Final(ref a, ref b, ref c);
            return c;
        }
    }

    private static void Mix(ref uint a, ref uint b, ref uint c)
    {
        unchecked
        {
            a -= c; a ^= Rotate(c, 4); c += b;
            b -= a; b ^= Rotate(a, 6); a += c;
            c -= b; c ^= Rotate(b, 8); b += a;
            a -= c; a ^= Rotate(c, 16); c += b;
            b -= a; b ^= Rotate(a, 19); a += c;
            c -= b; c ^= Rotate(b, 4); b += a;
        }
    }

    private static void Final(ref uint a, ref uint b, ref uint c)
    {
        unchecked
        {
            c ^= b; c -= Rotate(b, 14);
            a ^= c; a -= Rotate(c, 11);
            b ^= a; b -= Rotate(a, 25);
            c ^= b; c -= Rotate(b, 16);
            a ^= c; a -= Rotate(c, 4);
            b ^= a; b -= Rotate(a, 14);
            c ^= b; c -= Rotate(b, 24);
        }
    }

    private static uint Rotate(uint value, int count) => value << count | value >> (32 - count);

    private static uint ReadUInt32LittleEndian(ReadOnlySpan<byte> bytes, int offset)
        => (uint)(bytes[offset] | bytes[offset + 1] << 8 | bytes[offset + 2] << 16 | bytes[offset + 3] << 24);

    private static void WriteUInt16LittleEndian(byte[] bytes, int offset, ushort value)
    {
        bytes[offset] = (byte)value;
        bytes[offset + 1] = (byte)(value >> 8);
    }

    private static void WriteUInt16BigEndian(byte[] bytes, int offset, int value)
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

    private static void WriteUInt32BigEndian(byte[] bytes, int offset, int value)
        => WriteUInt32BigEndian(bytes, offset, (uint)value);

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

    private static void WriteUInt64BigEndian(byte[] bytes, int offset, ulong value)
    {
        for (int i = 0; i < 8; i++) bytes[offset + i] = (byte)(value >> ((7 - i) * 8));
    }
}
