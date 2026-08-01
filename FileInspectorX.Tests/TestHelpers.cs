using System;
using System.IO;

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

    private static void WriteUInt16LittleEndian(byte[] bytes, int offset, ushort value)
    {
        bytes[offset] = (byte)value;
        bytes[offset + 1] = (byte)(value >> 8);
    }

    private static void WriteUInt32LittleEndian(byte[] bytes, int offset, uint value)
    {
        bytes[offset] = (byte)value;
        bytes[offset + 1] = (byte)(value >> 8);
        bytes[offset + 2] = (byte)(value >> 16);
        bytes[offset + 3] = (byte)(value >> 24);
    }
}
