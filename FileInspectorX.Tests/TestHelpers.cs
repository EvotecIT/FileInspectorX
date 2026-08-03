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
        WriteUInt32LittleEndian(bytes, 0xB8, 0x1000);
        WriteUInt32LittleEndian(bytes, 0xBC, 0x0200);
        WriteUInt32LittleEndian(bytes, 0xD0, 0x1000);
        WriteUInt32LittleEndian(bytes, 0xD4, 0x0200);
        return bytes;
    }

    internal static byte[] CreateMinimalCrx3(int signedHeaderLength = 0)
    {
        var header = new List<byte> { 0x12, 0x06, 0x0A, 0x01, 0x01, 0x12, 0x01, 0x01 };
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
            header.Add(0x22);
            AddProtobufVarint(header, (uint)payloadLength);
            for (int index = 0; index < payloadLength; index++) header.Add(0xA5);
        }

        byte[] zip;
        using (var zipStream = new MemoryStream())
        {
            using (var archive = new System.IO.Compression.ZipArchive(zipStream,
                       System.IO.Compression.ZipArchiveMode.Create, leaveOpen: true))
                archive.CreateEntry("a");
            zip = zipStream.ToArray();
        }
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
        int mapOffset = (headerSize + 3) & ~3;
        int minimumLength = mapOffset + 28;
        if (length < minimumLength) length = minimumLength;
        var bytes = new byte[length];
        Encoding.ASCII.GetBytes("dex\n" + version + "\0").CopyTo(bytes, 0);
        WriteUInt32(bytes, 32, (uint)length, !reverseEndian);
        WriteUInt32(bytes, 36, (uint)headerSize, !reverseEndian);
        WriteUInt32(bytes, 40, 0x12345678, !reverseEndian);
        WriteUInt32(bytes, 52, (uint)mapOffset, !reverseEndian);
        WriteUInt32(bytes, 104, (uint)(length - mapOffset), !reverseEndian);
        WriteUInt32(bytes, 108, (uint)mapOffset, !reverseEndian);
        if (version == "041")
        {
            WriteUInt32(bytes, 112, (uint)length, !reverseEndian);
            WriteUInt32(bytes, 116, 0, !reverseEndian);
        }
        WriteUInt32(bytes, mapOffset, 2, !reverseEndian);
        WriteUInt16LittleEndian(bytes, mapOffset + 4, 0);
        WriteUInt16LittleEndian(bytes, mapOffset + 6, 0);
        WriteUInt32(bytes, mapOffset + 8, 1, !reverseEndian);
        WriteUInt32(bytes, mapOffset + 12, 0, !reverseEndian);
        if (reverseEndian) { bytes[mapOffset + 16] = 0x10; bytes[mapOffset + 17] = 0; }
        else WriteUInt16LittleEndian(bytes, mapOffset + 16, 0x1000);
        WriteUInt16LittleEndian(bytes, mapOffset + 18, 0);
        WriteUInt32(bytes, mapOffset + 20, 1, !reverseEndian);
        WriteUInt32(bytes, mapOffset + 24, (uint)mapOffset, !reverseEndian);
        FinalizeDex(bytes, !reverseEndian);
        return bytes;
    }

    internal static byte[] CreateDex041Container(int memberCount = 2)
    {
        const int memberLength = 148;
        int containerLength = checked(memberCount * memberLength);
        var container = new byte[containerLength];
        for (int member = 0; member < memberCount; member++)
        {
            byte[] dex = CreateMinimalDex("041", length: memberLength);
            WriteUInt32LittleEndian(dex, 112, (uint)containerLength);
            WriteUInt32LittleEndian(dex, 116, (uint)(member * memberLength));
            FinalizeDex(dex);
            dex.CopyTo(container, member * memberLength);
        }
        return container;
    }

    internal static void FinalizeDex(byte[] bytes, bool littleEndian = true, int dexLength = -1)
    {
        if (dexLength < 0) dexLength = bytes.Length;
        uint dataOffset = littleEndian
            ? (uint)(bytes[108] | bytes[109] << 8 | bytes[110] << 16 | bytes[111] << 24)
            : (uint)(bytes[111] | bytes[110] << 8 | bytes[109] << 16 | bytes[108] << 24);
        if (dataOffset != 0 && dataOffset <= dexLength) WriteUInt32(bytes, 104, (uint)dexLength - dataOffset, littleEndian);
        using var sha1 = SHA1.Create();
        sha1.ComputeHash(bytes, 32, dexLength - 32).CopyTo(bytes, 12);
        WriteUInt32(bytes, 8, ComputeAdler32(bytes, 12, dexLength - 12), littleEndian);
    }

    internal static byte[] CreateMinimalPhotoshop(ushort version = 1)
    {
        int layerLengthBytes = version == 2 ? 8 : 4;
        var bytes = new byte[26 + 4 + 4 + layerLengthBytes + 2 + 3];
        Encoding.ASCII.GetBytes("8BPS").CopyTo(bytes, 0);
        WriteUInt16BigEndian(bytes, 4, version);
        WriteUInt16BigEndian(bytes, 12, 3);
        WriteUInt32BigEndian(bytes, 14, 1);
        WriteUInt32BigEndian(bytes, 18, 1);
        WriteUInt16BigEndian(bytes, 22, 8);
        WriteUInt16BigEndian(bytes, 24, 3);
        return bytes;
    }

    internal static byte[] CreateMinimalJpeg2000(string brand = "jp2 ")
    {
        string firstRequired = brand == "jpx " ? "jpxh" : brand == "jpm " ? "jpmh" : brand == "mjp2" ? "moov" : "jp2h";
        string secondRequired = brand == "mjp2" ? "mdat" : "jp2c";
        int headerLength = brand == "mjp2" ? 34 : brand == "jpm " ? 16 : brand == "jp2 " ? 45 : 30;
        byte[] codestream = brand == "mjp2" ? Array.Empty<byte>() : CreateMinimalJpeg2000Codestream();
        int dataLength = brand == "mjp2" ? 9 : 8 + codestream.Length;
        var bytes = new byte[32 + headerLength + dataLength];
        new byte[] { 0, 0, 0, 12, (byte)'j', (byte)'P', (byte)' ', (byte)' ', 0x0D, 0x0A, 0x87, 0x0A }.CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 12, 20);
        Encoding.ASCII.GetBytes("ftyp").CopyTo(bytes, 16);
        Encoding.ASCII.GetBytes(brand).CopyTo(bytes, 20);
        Encoding.ASCII.GetBytes(brand).CopyTo(bytes, 28);
        WriteUInt32BigEndian(bytes, 32, (uint)headerLength);
        Encoding.ASCII.GetBytes(firstRequired).CopyTo(bytes, 36);
        if (brand == "jpm ") {
            WriteUInt32BigEndian(bytes, 40, 8);
            Encoding.ASCII.GetBytes("free").CopyTo(bytes, 44);
        } else if (brand == "mjp2") {
            WriteUInt32BigEndian(bytes, 40, 9);
            Encoding.ASCII.GetBytes("mvhd").CopyTo(bytes, 44);
            bytes[48] = 0;
            WriteUInt32BigEndian(bytes, 49, 17);
            Encoding.ASCII.GetBytes("trak").CopyTo(bytes, 53);
            WriteUInt32BigEndian(bytes, 57, 9);
            Encoding.ASCII.GetBytes("mdia").CopyTo(bytes, 61);
            bytes[65] = 0;
        } else {
            WriteUInt32BigEndian(bytes, 40, 22);
            Encoding.ASCII.GetBytes("ihdr").CopyTo(bytes, 44);
            WriteUInt32BigEndian(bytes, 48, 1);
            WriteUInt32BigEndian(bytes, 52, 1);
            WriteUInt16BigEndian(bytes, 56, 1);
            bytes[58] = 7;
            bytes[59] = 7;
            if (brand == "jp2 ")
            {
                WriteUInt32BigEndian(bytes, 62, 15);
                Encoding.ASCII.GetBytes("colr").CopyTo(bytes, 66);
                bytes[70] = 1;
                WriteUInt32BigEndian(bytes, 73, 16);
            }
        }
        int dataOffset = 32 + headerLength;
        WriteUInt32BigEndian(bytes, dataOffset, (uint)dataLength);
        Encoding.ASCII.GetBytes(secondRequired).CopyTo(bytes, dataOffset + 4);
        if (brand != "mjp2") codestream.CopyTo(bytes, dataOffset + 8);
        return bytes;
    }

    private static byte[] CreateMinimalJpeg2000Codestream()
    {
        var bytes = new byte[82];
        bytes[0] = 0xFF; bytes[1] = 0x4F;
        bytes[2] = 0xFF; bytes[3] = 0x51;
        WriteUInt16BigEndian(bytes, 4, 41);
        WriteUInt32BigEndian(bytes, 8, 1); WriteUInt32BigEndian(bytes, 12, 1);
        WriteUInt32BigEndian(bytes, 24, 1); WriteUInt32BigEndian(bytes, 28, 1);
        WriteUInt16BigEndian(bytes, 40, 1);
        bytes[42] = 7; bytes[43] = 1; bytes[44] = 1;
        bytes[45] = 0xFF; bytes[46] = 0x52;
        WriteUInt16BigEndian(bytes, 47, 12);
        bytes[52] = 1;
        bytes[59] = 0xFF; bytes[60] = 0x5C;
        WriteUInt16BigEndian(bytes, 61, 4);
        bytes[65] = 0xFF; bytes[66] = 0x90;
        WriteUInt16BigEndian(bytes, 67, 10);
        WriteUInt32BigEndian(bytes, 71, 15);
        bytes[77] = 0xFF; bytes[78] = 0x93; bytes[79] = 0;
        bytes[80] = 0xFF; bytes[81] = 0xD9;
        return bytes;
    }

    internal static byte[] CreateMinimalParquet()
    {
        byte[] metadata = {
            0x15, 0x02,
            0x19, 0x1C, 0x48, 0x04, (byte)'r', (byte)'o', (byte)'o', (byte)'t', 0x15, 0x00, 0x00,
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

    internal static byte[] CreateMinimalJpeg()
    {
        return new byte[]
        {
            0xFF, 0xD8,
            0xFF, 0xC0, 0x00, 0x0B, 8, 0, 1, 0, 1, 1, 1, 0x11, 0,
            0xFF, 0xDA, 0x00, 0x08, 1, 1, 0, 0, 63, 0,
            0, 0xFF, 0xD9
        };
    }

    internal static byte[] CreateMinimalGzip()
        => new byte[] { 0x1F, 0x8B, 8, 0, 0, 0, 0, 0, 0, 255, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    internal static byte[] CreateMinimalOgg()
    {
        var bytes = new byte[27];
        Encoding.ASCII.GetBytes("OggS").CopyTo(bytes, 0);
        bytes[5] = 4;
        WriteUInt32LittleEndian(bytes, 22, ComputeOggCrc(bytes));
        return bytes;
    }

    internal static byte[] CreateMinimalMp3()
    {
        const int frameLength = 417;
        var bytes = new byte[10 + frameLength];
        Encoding.ASCII.GetBytes("ID3").CopyTo(bytes, 0);
        bytes[3] = 4;
        new byte[] { 0xFF, 0xFB, 0x90, 0x64 }.CopyTo(bytes, 10);
        return bytes;
    }

    internal static byte[] CreateMinimalArrow()
    {
        var footer = new byte[60];
        WriteUInt32LittleEndian(footer, 0, 16);
        WriteUInt16LittleEndian(footer, 4, 12);
        WriteUInt16LittleEndian(footer, 6, 12);
        WriteUInt16LittleEndian(footer, 8, 4);
        WriteUInt16LittleEndian(footer, 10, 8);
        WriteUInt32LittleEndian(footer, 16, 12);
        WriteUInt32LittleEndian(footer, 24, 24);
        WriteUInt16LittleEndian(footer, 40, 8);
        WriteUInt16LittleEndian(footer, 42, 8);
        WriteUInt16LittleEndian(footer, 46, 4);
        WriteUInt32LittleEndian(footer, 48, 8);
        WriteUInt32LittleEndian(footer, 52, 4);

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

        int requiredLength = 152 + metaLength;
        if (totalLength == 0) totalLength = requiredLength;
        if (totalLength < requiredLength) throw new ArgumentOutOfRangeException(nameof(totalLength));
        var bytes = new byte[totalLength];
        Encoding.ASCII.GetBytes("DICM").CopyTo(bytes, 128);
        WriteUInt16LittleEndian(bytes, 132, 2);
        Encoding.ASCII.GetBytes("UL").CopyTo(bytes, 136);
        WriteUInt16LittleEndian(bytes, 138, 4);
        WriteUInt32LittleEndian(bytes, 140, checked((uint)metaLength));
        meta.CopyTo(bytes, 144);
        int dataSet = 144 + metaLength;
        WriteUInt16LittleEndian(bytes, dataSet, 0x0008);
        WriteUInt16LittleEndian(bytes, dataSet + 2, 0x0016);
        Encoding.ASCII.GetBytes("UI").CopyTo(bytes, dataSet + 4);
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

        int metadata = 2 * 1024 * 1024;
        Encoding.ASCII.GetBytes("metadata").CopyTo(bytes, metadata);
        WriteUInt16LittleEndian(bytes, metadata + 10, 5);
        AddMetadataEntry(0, new byte[] { 0x37, 0x67, 0xA1, 0xCA, 0x36, 0xFA, 0x43, 0x4D, 0xB3, 0xB6, 0x33, 0xF0, 0xAA, 0x44, 0xE7, 0x6B }, 0x10000, 8);
        AddMetadataEntry(1, new byte[] { 0x24, 0x42, 0xA5, 0x2F, 0x1B, 0xCD, 0x76, 0x48, 0xB2, 0x11, 0x5D, 0xBE, 0xD8, 0x3B, 0xF4, 0xB8 }, 0x10008, 8);
        AddMetadataEntry(2, new byte[] { 0x1D, 0xBF, 0x41, 0x81, 0x6F, 0xA9, 0x09, 0x47, 0xBA, 0x47, 0xF2, 0x33, 0xA8, 0xFA, 0xAB, 0x5F }, 0x10010, 4);
        AddMetadataEntry(3, new byte[] { 0xC7, 0x48, 0xA3, 0xCD, 0x5D, 0x44, 0x71, 0x44, 0x9C, 0xC9, 0xE9, 0x88, 0x52, 0x51, 0xC5, 0x56 }, 0x10014, 4);
        AddMetadataEntry(4, new byte[] { 0xAB, 0x12, 0xCA, 0xBE, 0xE6, 0xB2, 0x23, 0x45, 0x93, 0xEF, 0xC3, 0x09, 0xE0, 0x00, 0xC7, 0x46 }, 0x10018, 16);
        WriteUInt32LittleEndian(bytes, metadata + 0x10000, 1024 * 1024);
        WriteUInt64LittleEndian(bytes, metadata + 0x10008, 1024 * 1024);
        WriteUInt32LittleEndian(bytes, metadata + 0x10010, 512);
        WriteUInt32LittleEndian(bytes, metadata + 0x10014, 4096);
        bytes[metadata + 0x10018] = 1;
        return bytes;

        void AddMetadataEntry(int index, byte[] guid, uint offset, uint length)
        {
            int entry = metadata + 32 + index * 32;
            guid.CopyTo(bytes, entry);
            WriteUInt32LittleEndian(bytes, entry + 16, offset);
            WriteUInt32LittleEndian(bytes, entry + 20, length);
            bytes[entry + 25] = 1;
            bytes[entry + 26] = 1;
        }
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
        byte[] controlArchive = CreateMinimalTar("control");
        byte[] dataArchive = CreateMinimalTar("payload");
        stream.Write(Encoding.ASCII.GetBytes("!<arch>\n"), 0, 8);
        WriteArMember(stream, "debian-binary", Encoding.ASCII.GetBytes("2.0\n"));
        WriteArMember(stream, "control.tar", controlArchive);
        WriteArMember(stream, "data.tar", dataArchive);
        return stream.ToArray();
    }

    internal static byte[] CreateMinimalMatroska(string documentType = "matroska")
    {
        byte[] documentTypeBytes = Encoding.ASCII.GetBytes(documentType);
        byte[] segmentPayload = {
            0x15, 0x49, 0xA9, 0x66, 0x85, 0x2A, 0xD7, 0xB1, 0x81, 0x01,
            0x16, 0x54, 0xAE, 0x6B, 0x83, 0xAE, 0x81, 0x00
        };
        var bytes = new byte[4 + 1 + 3 + documentTypeBytes.Length + 5 + segmentPayload.Length];
        new byte[] { 0x1A, 0x45, 0xDF, 0xA3, (byte)(0x80 | (3 + documentTypeBytes.Length)), 0x42, 0x82,
            (byte)(0x80 | documentTypeBytes.Length) }.CopyTo(bytes, 0);
        documentTypeBytes.CopyTo(bytes, 8);
        int segment = 8 + documentTypeBytes.Length;
        new byte[] { 0x18, 0x53, 0x80, 0x67, (byte)(0x80 | segmentPayload.Length) }.CopyTo(bytes, segment);
        segmentPayload.CopyTo(bytes, segment + 5);
        return bytes;
    }

    private static byte[] CreateMinimalTar(string memberName)
    {
        var bytes = new byte[1536];
        Encoding.ASCII.GetBytes(memberName).CopyTo(bytes, 0);
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
        var bytes = new byte[68];
        new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }.CopyTo(bytes, 0);
        bytes[11] = 13;
        System.Text.Encoding.ASCII.GetBytes("IHDR").CopyTo(bytes, 12);
        bytes[19] = 1;
        bytes[23] = 1;
        bytes[24] = 8;
        bytes[25] = 6;
        WriteUInt32BigEndian(bytes, 29, ComputeCrc32(new ReadOnlySpan<byte>(bytes, 12, 17)));
        WriteUInt32BigEndian(bytes, 33, 11);
        System.Text.Encoding.ASCII.GetBytes("IDAT").CopyTo(bytes, 37);
        new byte[] { 0x78, 0x9C, 0x63, 0x60, 0x00, 0x02, 0x00, 0x00, 0x05, 0x00, 0x01 }.CopyTo(bytes, 41);
        WriteUInt32BigEndian(bytes, 52, ComputeCrc32(new ReadOnlySpan<byte>(bytes, 37, 15)));
        System.Text.Encoding.ASCII.GetBytes("IEND").CopyTo(bytes, 60);
        WriteUInt32BigEndian(bytes, 64, ComputeCrc32(new ReadOnlySpan<byte>(bytes, 60, 4)));
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
        long chunkOffset = stream.Position + 8;
        WriteUInt64LittleEndian(stream, checked((ulong)chunkOffset));
        WriteOpenExrChunk(stream, tiled: (flags & 0x00000200) != 0, deep: (flags & 0x00000800) != 0, multipartPart: null);
        return stream.ToArray();
    }

    internal static byte[] CreateMinimalMultipartOpenExr(int partCount = 2, bool secondPartTiled = false)
    {
        using var stream = new MemoryStream();
        stream.Write(new byte[] { 0x76, 0x2F, 0x31, 0x01 }, 0, 4);
        WriteUInt32LittleEndian(stream, 2u | 0x00001000u);
        for (int part = 0; part < partCount; part++)
        {
            bool tiled = secondPartTiled && part == 1;
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
            WriteOpenExrAttribute(stream, "type", "string", Encoding.ASCII.GetBytes(tiled ? "tiledimage" : "scanlineimage"));
            if (tiled)
            {
                var tileDescription = new byte[9];
                WriteUInt32LittleEndian(tileDescription, 0, 1);
                WriteUInt32LittleEndian(tileDescription, 4, 1);
                WriteOpenExrAttribute(stream, "tiles", "tiledesc", tileDescription);
            }
            WriteOpenExrAttribute(stream, "chunkCount", "int", new byte[] { 1, 0, 0, 0 });
            stream.WriteByte(0);
        }
        stream.WriteByte(0);
        long chunkOffset = stream.Position + partCount * 8L;
        for (int part = 0; part < partCount; part++)
        {
            WriteUInt64LittleEndian(stream, checked((ulong)chunkOffset));
            chunkOffset += secondPartTiled && part == 1 ? 28 : 16;
        }
        for (int part = 0; part < partCount; part++)
            WriteOpenExrChunk(stream, tiled: secondPartTiled && part == 1, deep: false, multipartPart: part);
        return stream.ToArray();
    }

    private static void WriteOpenExrChunk(Stream stream, bool tiled, bool deep, int? multipartPart)
    {
        if (multipartPart.HasValue) WriteUInt32LittleEndian(stream, checked((uint)multipartPart.Value));
        if (tiled)
            for (int index = 0; index < 4; index++) WriteUInt32LittleEndian(stream, 0);
        else
            WriteUInt32LittleEndian(stream, 0);

        if (deep)
        {
            WriteUInt64LittleEndian(stream, 4);
            WriteUInt64LittleEndian(stream, 0);
            WriteUInt64LittleEndian(stream, 0);
        }
        else
        {
            WriteUInt32LittleEndian(stream, 4);
        }
        stream.Write(new byte[4], 0, 4);
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

    private static void WriteUInt64LittleEndian(Stream stream, ulong value)
    {
        for (int index = 0; index < 8; index++) stream.WriteByte((byte)(value >> (index * 8)));
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

    internal static void WriteUInt16BigEndian(byte[] bytes, int offset, ushort value)
    {
        bytes[offset] = (byte)(value >> 8);
        bytes[offset + 1] = (byte)value;
    }

    internal static void WriteUInt32BigEndian(byte[] bytes, int offset, uint value)
    {
        bytes[offset] = (byte)(value >> 24);
        bytes[offset + 1] = (byte)(value >> 16);
        bytes[offset + 2] = (byte)(value >> 8);
        bytes[offset + 3] = (byte)value;
    }

    internal static void WriteUInt64LittleEndian(byte[] bytes, int offset, ulong value)
    {
        for (int index = 0; index < 8; index++) bytes[offset + index] = (byte)(value >> (8 * index));
    }

    internal static void WriteUInt64BigEndian(byte[] bytes, int offset, ulong value)
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

    private static uint ComputeOggCrc(byte[] bytes)
    {
        uint crc = 0;
        for (int index = 0; index < bytes.Length; index++)
        {
            byte value = index is >= 22 and < 26 ? (byte)0 : bytes[index];
            crc ^= (uint)value << 24;
            for (int bit = 0; bit < 8; bit++) crc = (crc & 0x80000000) != 0 ? crc << 1 ^ 0x04C11DB7u : crc << 1;
        }
        return crc;
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
