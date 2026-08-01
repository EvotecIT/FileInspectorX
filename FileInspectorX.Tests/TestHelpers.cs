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

    internal static byte[] CreateMinimalCrx3(int signedHeaderLength = 0)
    {
        var header = new List<byte> { 0x0A, 0x06, 0x0A, 0x01, 0x01, 0x12, 0x01, 0x01 };
        AddProtobufVarint(header, (10000u << 3) | 2u);
        header.Add(18);
        header.Add(0x0A);
        header.Add(16);
        for (int index = 0; index < 16; index++) header.Add((byte)(index + 1));

        if (signedHeaderLength > header.Count)
        {
            int remaining = signedHeaderLength - header.Count;
            int payloadLength = -1;
            for (int candidate = Math.Max(0, remaining - 1); candidate >= 0; candidate--)
            {
                if (1 + ProtobufVarintLength((uint)candidate) + candidate == remaining)
                {
                    payloadLength = candidate;
                    break;
                }
            }
            if (payloadLength < 0) throw new ArgumentOutOfRangeException(nameof(signedHeaderLength));
            header.Add(0x1A);
            AddProtobufVarint(header, (uint)payloadLength);
            for (int index = 0; index < payloadLength; index++) header.Add(0xA5);
        }

        var zip = new byte[31];
        Encoding.ASCII.GetBytes("PK\u0003\u0004").CopyTo(zip, 0);
        WriteUInt16LittleEndian(zip, 4, 20);
        WriteUInt16LittleEndian(zip, 26, 1);
        zip[30] = (byte)'a';
        var bytes = new byte[12 + header.Count + zip.Length];
        Encoding.ASCII.GetBytes("Cr24").CopyTo(bytes, 0);
        WriteUInt32LittleEndian(bytes, 4, 3);
        WriteUInt32LittleEndian(bytes, 8, (uint)header.Count);
        header.CopyTo(bytes, 12);
        zip.CopyTo(bytes, 12 + header.Count);
        return bytes;
    }

    private static void AddProtobufVarint(List<byte> bytes, uint value)
    {
        while (value >= 0x80)
        {
            bytes.Add((byte)(value | 0x80));
            value >>= 7;
        }
        bytes.Add((byte)value);
    }

    private static int ProtobufVarintLength(uint value)
    {
        int length = 1;
        while (value >= 0x80) { value >>= 7; length++; }
        return length;
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
        bool unicode = version >= 21;
        var bytes = new byte[unicode ? 564 : 512];
        Encoding.ASCII.GetBytes("!BDN").CopyTo(bytes, 0);
        Encoding.ASCII.GetBytes("SM").CopyTo(bytes, 8);
        WriteUInt16LittleEndian(bytes, 10, version);
        WriteUInt16LittleEndian(bytes, 12, 19);
        bytes[14] = 1;
        bytes[15] = 1;
        if (unicode)
            WriteUInt32LittleEndian(bytes, 524, ComputeCrc32(bytes, 8, 516));
        WriteUInt32LittleEndian(bytes, 4, ComputeCrc32(bytes, 8, 464));
        return bytes;
    }

    internal static byte[] CreateMinimalDicom(int metaLength = 0, int totalLength = 0)
    {
        var meta = new List<byte>();
        AddVersion();
        AddUid(0x0002, "1.2.840.10008.5.1.4.1.1.7");
        AddUid(0x0003, "1.2.3.4.5.6.7.8.9");
        AddUid(0x0010, "1.2.840.10008.1.2.1");
        AddUid(0x0012, "1.2.826.0.1.3680043.10.543");
        if (metaLength == 0) metaLength = meta.Count;
        if (metaLength < meta.Count || metaLength - meta.Count is > 0 and < 12)
            throw new ArgumentOutOfRangeException(nameof(metaLength));
        if (metaLength > meta.Count)
        {
            int payloadLength = metaLength - meta.Count - 12;
            AddUInt16(meta, 2); AddUInt16(meta, 0x0102);
            meta.Add((byte)'O'); meta.Add((byte)'B'); meta.Add(0); meta.Add(0);
            AddUInt32(meta, checked((uint)payloadLength));
            for (int index = 0; index < payloadLength; index++) meta.Add(0);
        }

        int requiredLength = 144 + metaLength;
        if (totalLength == 0) totalLength = requiredLength;
        if (totalLength < requiredLength) throw new ArgumentOutOfRangeException(nameof(totalLength));
        var bytes = new byte[totalLength];
        Encoding.ASCII.GetBytes("DICM").CopyTo(bytes, 128);
        WriteUInt16LittleEndian(bytes, 132, 2);
        Encoding.ASCII.GetBytes("UL").CopyTo(bytes, 136);
        WriteUInt16LittleEndian(bytes, 138, 4);
        WriteUInt32LittleEndian(bytes, 140, checked((uint)metaLength));
        meta.CopyTo(bytes, 144);
        return bytes;

        void AddVersion()
        {
            AddUInt16(meta, 2); AddUInt16(meta, 1);
            meta.Add((byte)'O'); meta.Add((byte)'B'); meta.Add(0); meta.Add(0);
            AddUInt32(meta, 2); meta.Add(0); meta.Add(1);
        }

        void AddUid(ushort tag, string uid)
        {
            byte[] value = Encoding.ASCII.GetBytes(uid);
            int paddedLength = value.Length + (value.Length & 1);
            AddUInt16(meta, 2); AddUInt16(meta, tag);
            meta.Add((byte)'U'); meta.Add((byte)'I'); AddUInt16(meta, checked((ushort)paddedLength));
            meta.AddRange(value);
            if (paddedLength != value.Length) meta.Add(0);
        }

        static void AddUInt16(List<byte> target, ushort value)
        {
            target.Add((byte)value); target.Add((byte)(value >> 8));
        }

        static void AddUInt32(List<byte> target, uint value)
        {
            for (int index = 0; index < 4; index++) target.Add((byte)(value >> (8 * index)));
        }
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

    internal static byte[] CreateMinimalVhd()
    {
        var bytes = new byte[1024];
        int footer = bytes.Length - 512;
        Encoding.ASCII.GetBytes("conectix").CopyTo(bytes, footer);
        WriteUInt32BigEndian(bytes, footer + 8, 2);
        WriteUInt32BigEndian(bytes, footer + 12, 0x00010000);
        for (int index = 16; index < 24; index++) bytes[footer + index] = 0xFF;
        WriteUInt64BigEndian(bytes, footer + 40, 512);
        WriteUInt64BigEndian(bytes, footer + 48, 512);
        WriteUInt32BigEndian(bytes, footer + 56, 0x00010101);
        WriteUInt32BigEndian(bytes, footer + 60, 2);
        bytes[footer + 68] = 1;
        uint sum = 0;
        for (int index = 0; index < 512; index++) if (index < 64 || index >= 68) sum += bytes[footer + index];
        WriteUInt32BigEndian(bytes, footer + 64, ~sum);
        return bytes;
    }

    internal static byte[] CreateMinimalDeb()
    {
        using var stream = new MemoryStream();
        byte[] archive = CreateMinimalTar();
        stream.Write(Encoding.ASCII.GetBytes("!<arch>\n"), 0, 8);
        WriteArMember(stream, "debian-binary", Encoding.ASCII.GetBytes("2.0\n"));
        WriteArMember(stream, "control.tar", archive);
        WriteArMember(stream, "data.tar", archive);
        return stream.ToArray();
    }

    internal static byte[] CreateMinimalMatroska(string documentType = "matroska")
    {
        byte[] documentTypeBytes = Encoding.ASCII.GetBytes(documentType);
        var bytes = new byte[4 + 1 + 3 + documentTypeBytes.Length + 5];
        new byte[] { 0x1A, 0x45, 0xDF, 0xA3, (byte)(0x80 | (3 + documentTypeBytes.Length)), 0x42, 0x82,
            (byte)(0x80 | documentTypeBytes.Length) }.CopyTo(bytes, 0);
        documentTypeBytes.CopyTo(bytes, 8);
        int segment = 8 + documentTypeBytes.Length;
        new byte[] { 0x18, 0x53, 0x80, 0x67, 0x80 }.CopyTo(bytes, segment);
        return bytes;
    }

    private static byte[] CreateMinimalTar()
    {
        var bytes = new byte[1536];
        Encoding.ASCII.GetBytes("payload").CopyTo(bytes, 0);
        Encoding.ASCII.GetBytes("0000644\0").CopyTo(bytes, 100);
        Encoding.ASCII.GetBytes("0000000\0").CopyTo(bytes, 108);
        Encoding.ASCII.GetBytes("0000000\0").CopyTo(bytes, 116);
        Encoding.ASCII.GetBytes("00000000000\0").CopyTo(bytes, 124);
        Encoding.ASCII.GetBytes("00000000000\0").CopyTo(bytes, 136);
        for (int index = 148; index < 156; index++) bytes[index] = (byte)' ';
        bytes[156] = (byte)'0';
        Encoding.ASCII.GetBytes("ustar\0").CopyTo(bytes, 257);
        Encoding.ASCII.GetBytes("00").CopyTo(bytes, 263);
        int checksum = 0;
        for (int index = 0; index < 512; index++) checksum += bytes[index];
        Encoding.ASCII.GetBytes(Convert.ToString(checksum, 8)!.PadLeft(6, '0') + "\0 ").CopyTo(bytes, 148);
        return bytes;
    }

    private static void WriteArMember(Stream stream, string name, byte[] data)
    {
        string header = (name + "/").PadRight(16) + "0".PadRight(12) + "0".PadRight(6) + "0".PadRight(6) +
                        "100644".PadRight(8) + data.Length.ToString(System.Globalization.CultureInfo.InvariantCulture).PadRight(10) + "`\n";
        byte[] headerBytes = Encoding.ASCII.GetBytes(header);
        stream.Write(headerBytes, 0, headerBytes.Length);
        stream.Write(data, 0, data.Length);
        if ((data.Length & 1) != 0) stream.WriteByte((byte)'\n');
    }

    internal static byte[] CreateMinimalPng()
    {
        var bytes = new byte[57];
        new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }.CopyTo(bytes, 0);
        bytes[11] = 13;
        System.Text.Encoding.ASCII.GetBytes("IHDR").CopyTo(bytes, 12);
        bytes[19] = 1;
        bytes[23] = 1;
        bytes[24] = 8;
        bytes[25] = 6;
        WriteUInt32BigEndian(bytes, 29, ComputeCrc32(new ReadOnlySpan<byte>(bytes, 12, 17)));
        System.Text.Encoding.ASCII.GetBytes("IDAT").CopyTo(bytes, 37);
        WriteUInt32BigEndian(bytes, 41, ComputeCrc32(new ReadOnlySpan<byte>(bytes, 37, 4)));
        System.Text.Encoding.ASCII.GetBytes("IEND").CopyTo(bytes, 49);
        WriteUInt32BigEndian(bytes, 53, ComputeCrc32(new ReadOnlySpan<byte>(bytes, 49, 4)));
        return bytes;
    }

    private static uint ComputeCrc32(ReadOnlySpan<byte> data)
    {
        uint crc = uint.MaxValue;
        for (int index = 0; index < data.Length; index++)
        {
            crc ^= data[index];
            for (int bit = 0; bit < 8; bit++) crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320u : crc >> 1;
        }
        return ~crc;
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

    internal static byte[] CreateMinimalMultipartOpenExr(int partCount = 2)
    {
        using var stream = new MemoryStream();
        stream.Write(new byte[] { 0x76, 0x2F, 0x31, 0x01 }, 0, 4);
        WriteUInt32LittleEndian(stream, 2u | 0x00001000u);
        for (int part = 0; part < partCount; part++)
        {
            var channelList = new byte[19];
            channelList[0] = (byte)'R';
            WriteUInt32LittleEndian(channelList, 2, 2);
            WriteUInt32LittleEndian(channelList, 10, 1);
            WriteUInt32LittleEndian(channelList, 14, 1);
            WriteOpenExrAttribute(stream, "channels", "chlist", channelList);
            WriteOpenExrAttribute(stream, "compression", "compression", new byte[] { 10 });
            WriteOpenExrAttribute(stream, "dataWindow", "box2i", new byte[16]);
            WriteOpenExrAttribute(stream, "displayWindow", "box2i", new byte[16]);
            WriteOpenExrAttribute(stream, "lineOrder", "lineOrder", new byte[] { 0 });
            WriteOpenExrAttribute(stream, "pixelAspectRatio", "float", new byte[] { 0, 0, 0x80, 0x3F });
            WriteOpenExrAttribute(stream, "screenWindowCenter", "v2f", new byte[8]);
            WriteOpenExrAttribute(stream, "screenWindowWidth", "float", new byte[] { 0, 0, 0x80, 0x3F });
            WriteOpenExrAttribute(stream, "name", "string", Encoding.ASCII.GetBytes("part" + part));
            WriteOpenExrAttribute(stream, "type", "string", Encoding.ASCII.GetBytes("scanlineimage"));
            WriteOpenExrAttribute(stream, "chunkCount", "int", new byte[] { 1, 0, 0, 0 });
            stream.WriteByte(0);
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

    private static void WriteUInt64BigEndian(byte[] bytes, int offset, ulong value)
    {
        for (int index = 0; index < 8; index++) bytes[offset + index] = (byte)(value >> (8 * (7 - index)));
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
