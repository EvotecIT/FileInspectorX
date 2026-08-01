using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace FileInspectorX.Tests;

internal static class TestHelpers
{
    internal static string GetFixturePath(params string[] relativeParts)
    {
        if (relativeParts == null || relativeParts.Length == 0)
            throw new ArgumentException("At least one fixture path part is required.", nameof(relativeParts));

        var parts = new string[relativeParts.Length + 2];
        parts[0] = AppContext.BaseDirectory;
        parts[1] = "Fixtures";
        Array.Copy(relativeParts, 0, parts, 2, relativeParts.Length);
        var path = Path.Combine(parts);
        if (!File.Exists(path))
            throw new FileNotFoundException("Fixture file was not copied to the test output directory.", path);
        return path;
    }

    internal static void SafeDelete(string path)
    {
        try
        {
            if (!string.IsNullOrWhiteSpace(path) && File.Exists(path))
                File.Delete(path);
        }
        catch { }
    }

    internal static byte[] CreateMinimalPe(bool dll = false)
    {
        var bytes = new byte[512];
        bytes[0] = (byte)'M';
        bytes[1] = (byte)'Z';
        WriteUInt32LittleEndian(bytes, 0x3C, 0x80);
        bytes[0x80] = (byte)'P';
        bytes[0x81] = (byte)'E';
        WriteUInt16LittleEndian(bytes, 0x84, 0x014C);
        WriteUInt16LittleEndian(bytes, 0x86, 1);
        WriteUInt16LittleEndian(bytes, 0x94, 0x00E0);
        WriteUInt16LittleEndian(bytes, 0x96, dll ? (ushort)0x2102 : (ushort)0x0102);
        WriteUInt16LittleEndian(bytes, 0x98, 0x010B);
        return bytes;
    }

    internal static byte[] CreateMinimalDex(string version = "035", bool reverseEndian = false, int length = 0x70)
    {
        int headerSize = version == "041" ? 0x78 : 0x70;
        if (length < headerSize) length = headerSize;
        var bytes = new byte[length];
        Encoding.ASCII.GetBytes("dex\n" + version + "\0").CopyTo(bytes, 0);
        WriteUInt32(bytes, 32, (uint)length, !reverseEndian);
        WriteUInt32(bytes, 36, (uint)headerSize, !reverseEndian);
        WriteUInt32(bytes, 40, 0x12345678, !reverseEndian);
        if (version == "041")
        {
            WriteUInt32(bytes, 112, (uint)length, !reverseEndian);
            WriteUInt32(bytes, 116, 0, !reverseEndian);
        }
        FinalizeDex(bytes, !reverseEndian);
        return bytes;
    }

    internal static void FinalizeDex(byte[] bytes, bool littleEndian = true, int dexLength = -1)
    {
        if (dexLength < 0) dexLength = bytes.Length;
        using var sha1 = SHA1.Create();
        sha1.ComputeHash(bytes, 32, dexLength - 32).CopyTo(bytes, 12);
        WriteUInt32(bytes, 8, ComputeAdler32(bytes, 12, dexLength - 12), littleEndian);
    }

    internal static byte[] CreateMinimalPhotoshop(ushort version = 1)
    {
        int layerLengthBytes = version == 2 ? 8 : 4;
        var bytes = new byte[26 + 4 + 4 + layerLengthBytes + 2];
        Encoding.ASCII.GetBytes("8BPS").CopyTo(bytes, 0);
        WriteUInt16BigEndian(bytes, 4, version);
        WriteUInt16BigEndian(bytes, 12, 3);
        WriteUInt32BigEndian(bytes, 14, 100);
        WriteUInt32BigEndian(bytes, 18, 200);
        WriteUInt16BigEndian(bytes, 22, 8);
        WriteUInt16BigEndian(bytes, 24, 3);
        return bytes;
    }

    internal static byte[] CreateMinimalJpeg2000(string brand = "jp2 ")
    {
        string firstRequired = brand == "jpx " ? "jpxh" : brand == "mjp2" ? "moov" : "jp2h";
        string secondRequired = brand == "mjp2" ? "mdat" : "jp2c";
        var bytes = new byte[48];
        new byte[] { 0, 0, 0, 12, (byte)'j', (byte)'P', (byte)' ', (byte)' ', 0x0D, 0x0A, 0x87, 0x0A }.CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 12, 20);
        Encoding.ASCII.GetBytes("ftyp").CopyTo(bytes, 16);
        Encoding.ASCII.GetBytes(brand).CopyTo(bytes, 20);
        Encoding.ASCII.GetBytes(brand).CopyTo(bytes, 28);
        WriteUInt32BigEndian(bytes, 32, 8);
        Encoding.ASCII.GetBytes(firstRequired).CopyTo(bytes, 36);
        WriteUInt32BigEndian(bytes, 40, 8);
        Encoding.ASCII.GetBytes(secondRequired).CopyTo(bytes, 44);
        return bytes;
    }

    internal static byte[] CreateMinimalParquet()
    {
        byte[] metadata = {
            0x15, 0x02,
            0x19, 0x1C, 0x48, 0x04, (byte)'r', (byte)'o', (byte)'o', (byte)'t', 0x00,
            0x16, 0x00,
            0x19, 0x0C,
            0x00
        };
        var bytes = new byte[4 + metadata.Length + 8];
        Encoding.ASCII.GetBytes("PAR1").CopyTo(bytes, 0);
        metadata.CopyTo(bytes, 4);
        WriteUInt32LittleEndian(bytes, bytes.Length - 8, (uint)metadata.Length);
        Encoding.ASCII.GetBytes("PAR1").CopyTo(bytes, bytes.Length - 4);
        return bytes;
    }

    internal static byte[] CreateMinimalArrow()
    {
        var footer = new byte[32];
        WriteUInt32LittleEndian(footer, 0, 12);
        WriteUInt16LittleEndian(footer, 4, 8);
        WriteUInt16LittleEndian(footer, 6, 12);
        WriteUInt16LittleEndian(footer, 8, 4);
        WriteUInt16LittleEndian(footer, 10, 8);
        WriteUInt32LittleEndian(footer, 12, 8);
        WriteUInt16LittleEndian(footer, 16, 4);
        WriteUInt32LittleEndian(footer, 20, 8);
        WriteUInt16LittleEndian(footer, 24, 4);
        WriteUInt16LittleEndian(footer, 26, 4);
        WriteUInt32LittleEndian(footer, 28, 4);

        var bytes = new byte[8 + footer.Length + 10];
        Encoding.ASCII.GetBytes("ARROW1").CopyTo(bytes, 0);
        footer.CopyTo(bytes, 8);
        WriteUInt32LittleEndian(bytes, bytes.Length - 10, (uint)footer.Length);
        Encoding.ASCII.GetBytes("ARROW1").CopyTo(bytes, bytes.Length - 6);
        return bytes;
    }

    internal static byte[] CreateMinimalOutlookNdb(ushort version = 23)
    {
        var bytes = new byte[version < 23 ? 512 : 564];
        Encoding.ASCII.GetBytes("!BDN").CopyTo(bytes, 0);
        Encoding.ASCII.GetBytes("SM").CopyTo(bytes, 8);
        WriteUInt16LittleEndian(bytes, 10, version);
        WriteUInt16LittleEndian(bytes, 12, 19);
        bytes[14] = 1;
        bytes[15] = 1;
        if (version >= 23)
            WriteUInt32LittleEndian(bytes, 524, ComputeCrc32(bytes, 8, 516));
        WriteUInt32LittleEndian(bytes, 4, ComputeCrc32(bytes, 8, 464));
        return bytes;
    }

    internal static byte[] CreateMinimalVhdx()
    {
        var bytes = new byte[3 * 1024 * 1024];
        Encoding.ASCII.GetBytes("vhdxfile").CopyTo(bytes, 0);
        int header = 64 * 1024;
        Encoding.ASCII.GetBytes("head").CopyTo(bytes, header);
        WriteUInt64LittleEndian(bytes, header + 8, 1);
        WriteUInt16LittleEndian(bytes, header + 66, 1);
        WriteUInt32LittleEndian(bytes, header + 4, ComputeCrc32C(bytes, header, 4096, header + 4, 4));

        int region = 192 * 1024;
        Encoding.ASCII.GetBytes("regi").CopyTo(bytes, region);
        WriteUInt32LittleEndian(bytes, region + 8, 2);
        new byte[] { 0x66, 0x77, 0xC2, 0x2D, 0x23, 0xF6, 0x00, 0x42, 0x9D, 0x64, 0x11, 0x5E, 0x9B, 0xFD, 0x4A, 0x08 }.CopyTo(bytes, region + 16);
        WriteUInt64LittleEndian(bytes, region + 32, 1024 * 1024);
        WriteUInt32LittleEndian(bytes, region + 40, 1024 * 1024);
        WriteUInt32LittleEndian(bytes, region + 44, 1);
        new byte[] { 0x06, 0xA2, 0x7C, 0x8B, 0x90, 0x47, 0x9A, 0x4B, 0xB8, 0xFE, 0x57, 0x5F, 0x05, 0x0F, 0x88, 0x6E }.CopyTo(bytes, region + 48);
        WriteUInt64LittleEndian(bytes, region + 64, 2 * 1024 * 1024);
        WriteUInt32LittleEndian(bytes, region + 72, 1024 * 1024);
        WriteUInt32LittleEndian(bytes, region + 76, 1);
        WriteUInt32LittleEndian(bytes, region + 4, ComputeCrc32C(bytes, region, 64 * 1024, region + 4, 4));
        return bytes;
    }

    internal static byte[] CreateMinimalPng()
    {
        var bytes = new byte[33];
        new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }.CopyTo(bytes, 0);
        bytes[11] = 13;
        System.Text.Encoding.ASCII.GetBytes("IHDR").CopyTo(bytes, 12);
        bytes[19] = 1;
        bytes[23] = 1;
        bytes[24] = 8;
        bytes[25] = 6;
        return bytes;
    }

    internal static byte[] CreateEmptyZip()
    {
        using var stream = new MemoryStream();
        using (var archive = new System.IO.Compression.ZipArchive(
                   stream,
                   System.IO.Compression.ZipArchiveMode.Create,
                   leaveOpen: true)) { }
        return stream.ToArray();
    }

    internal static byte[] CreateMinimalMinidump()
    {
        var bytes = new byte[44];
        System.Text.Encoding.ASCII.GetBytes("MDMP").CopyTo(bytes, 0);
        WriteUInt32LittleEndian(bytes, 4, 0xA793);
        WriteUInt32LittleEndian(bytes, 8, 1);
        WriteUInt32LittleEndian(bytes, 12, 32);
        return bytes;
    }

    internal static byte[] CreateMinimalEvtx()
    {
        var bytes = new byte[4096 + 65536];
        new byte[] { (byte)'E', (byte)'l', (byte)'f', (byte)'F', (byte)'i', (byte)'l', (byte)'e', 0 }.CopyTo(bytes, 0);
        WriteUInt32LittleEndian(bytes, 0x20, 128);
        WriteUInt16LittleEndian(bytes, 0x24, 1);
        WriteUInt16LittleEndian(bytes, 0x26, 3);
        WriteUInt16LittleEndian(bytes, 0x28, 4096);
        WriteUInt16LittleEndian(bytes, 0x2A, 1);
        new byte[] { (byte)'E', (byte)'l', (byte)'f', (byte)'C', (byte)'h', (byte)'n', (byte)'k', 0 }.CopyTo(bytes, 4096);
        return bytes;
    }

    internal static byte[] CreateMinimalOpenExr(uint flags = 0)
    {
        using var stream = new MemoryStream();
        stream.Write(new byte[] { 0x76, 0x2F, 0x31, 0x01 }, 0, 4);
        WriteUInt32LittleEndian(stream, 2u | flags);

        var channelList = new byte[19];
        channelList[0] = (byte)'R';
        WriteUInt32LittleEndian(channelList, 2, 2);
        WriteUInt32LittleEndian(channelList, 10, 1);
        WriteUInt32LittleEndian(channelList, 14, 1);
        WriteOpenExrAttribute(stream, "channels", "chlist", channelList);
        WriteOpenExrAttribute(stream, "compression", "compression", new byte[] { 0 });
        WriteOpenExrAttribute(stream, "dataWindow", "box2i", new byte[16]);
        WriteOpenExrAttribute(stream, "displayWindow", "box2i", new byte[16]);
        WriteOpenExrAttribute(stream, "lineOrder", "lineOrder", new byte[] { 0 });
        WriteOpenExrAttribute(stream, "pixelAspectRatio", "float", new byte[] { 0, 0, 0x80, 0x3F });
        WriteOpenExrAttribute(stream, "screenWindowCenter", "v2f", new byte[8]);
        WriteOpenExrAttribute(stream, "screenWindowWidth", "float", new byte[] { 0, 0, 0x80, 0x3F });
        if ((flags & 0x00000200) != 0)
        {
            var tileDescription = new byte[9];
            WriteUInt32LittleEndian(tileDescription, 0, 1);
            WriteUInt32LittleEndian(tileDescription, 4, 1);
            WriteOpenExrAttribute(stream, "tiles", "tiledesc", tileDescription);
        }
        stream.WriteByte(0);
        return stream.ToArray();
    }

    private static void WriteOpenExrAttribute(Stream stream, string name, string type, byte[] value)
    {
        var nameBytes = System.Text.Encoding.ASCII.GetBytes(name);
        stream.Write(nameBytes, 0, nameBytes.Length);
        stream.WriteByte(0);
        var typeBytes = System.Text.Encoding.ASCII.GetBytes(type);
        stream.Write(typeBytes, 0, typeBytes.Length);
        stream.WriteByte(0);
        WriteUInt32LittleEndian(stream, checked((uint)value.Length));
        stream.Write(value, 0, value.Length);
    }

    private static void WriteUInt32LittleEndian(Stream stream, uint value)
    {
        stream.WriteByte((byte)value);
        stream.WriteByte((byte)(value >> 8));
        stream.WriteByte((byte)(value >> 16));
        stream.WriteByte((byte)(value >> 24));
    }

    internal static void WriteUInt16LittleEndian(byte[] bytes, int offset, ushort value)
    {
        bytes[offset] = (byte)value;
        bytes[offset + 1] = (byte)(value >> 8);
    }

    internal static void WriteUInt32LittleEndian(byte[] bytes, int offset, uint value)
    {
        bytes[offset] = (byte)value;
        bytes[offset + 1] = (byte)(value >> 8);
        bytes[offset + 2] = (byte)(value >> 16);
        bytes[offset + 3] = (byte)(value >> 24);
    }

    private static void WriteUInt16BigEndian(byte[] bytes, int offset, ushort value)
    {
        bytes[offset] = (byte)(value >> 8);
        bytes[offset + 1] = (byte)value;
    }

    private static void WriteUInt32BigEndian(byte[] bytes, int offset, uint value)
    {
        bytes[offset] = (byte)(value >> 24);
        bytes[offset + 1] = (byte)(value >> 16);
        bytes[offset + 2] = (byte)(value >> 8);
        bytes[offset + 3] = (byte)value;
    }

    private static void WriteUInt64LittleEndian(byte[] bytes, int offset, ulong value)
    {
        for (int index = 0; index < 8; index++) bytes[offset + index] = (byte)(value >> (8 * index));
    }

    private static void WriteUInt32(byte[] bytes, int offset, uint value, bool littleEndian)
    {
        if (littleEndian) WriteUInt32LittleEndian(bytes, offset, value);
        else WriteUInt32BigEndian(bytes, offset, value);
    }

    private static uint ComputeAdler32(byte[] bytes, int offset, int count)
    {
        const uint modulus = 65521;
        uint a = 1, b = 0;
        for (int index = offset; index < offset + count; index++)
        {
            a = (a + bytes[index]) % modulus;
            b = (b + a) % modulus;
        }
        return (b << 16) | a;
    }

    private static uint ComputeCrc32(byte[] bytes, int offset, int count)
    {
        uint crc = uint.MaxValue;
        for (int index = offset; index < offset + count; index++)
        {
            crc ^= bytes[index];
            for (int bit = 0; bit < 8; bit++) crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320u : crc >> 1;
        }
        return ~crc;
    }

    private static uint ComputeCrc32C(byte[] bytes, int offset, int count, int zeroOffset, int zeroCount)
    {
        uint crc = uint.MaxValue;
        for (int index = offset; index < offset + count; index++)
        {
            byte value = index >= zeroOffset && index < zeroOffset + zeroCount ? (byte)0 : bytes[index];
            crc ^= value;
            for (int bit = 0; bit < 8; bit++) crc = (crc & 1) != 0 ? (crc >> 1) ^ 0x82F63B78u : crc >> 1;
        }
        return ~crc;
    }
}
