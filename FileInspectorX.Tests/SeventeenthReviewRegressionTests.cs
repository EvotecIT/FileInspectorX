using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class SeventeenthReviewRegressionTests
{
    [Fact]
    public void ElfExtendedNumberingUsesSectionHeaderZero()
    {
        var valid = ExtendedElf64();
        AssertParity(valid, "elf");

        var missingSectionCount = (byte[])valid.Clone();
        WriteUInt64LittleEndian(missingSectionCount, 96, 0);
        AssertNotDetectedAs("elf", missingSectionCount);

        var outOfRangeProgramCount = (byte[])valid.Clone();
        WriteUInt32LittleEndian(outOfRangeProgramCount, 108, 2);
        AssertNotDetectedAs("elf", outOfRangeProgramCount);
    }

    [Fact]
    public void Woff2RequiresTransformedGlyfAndLocaAsAPair()
    {
        AssertNotDetectedAs("woff2", Woff2((0x0A, 4, 4)));
        AssertNotDetectedAs("woff2", Woff2((0x0B, 4, 0)));
        AssertNotDetectedAs("woff2", Woff2((0x0A, 4, 4), (0x0B, 4, 1)));
        AssertParity(Woff2((0x0A, 4, 4), (0x0B, 4, 0)), "woff2");
    }

    [Fact]
    public void IndexedPngRequiresAValidPaletteBeforeIdat()
    {
        AssertParity(IndexedPng(includePalette: true, paletteAfterIdat: false), "png");
        AssertNotDetectedAs("png", IndexedPng(includePalette: false, paletteAfterIdat: false));
        AssertNotDetectedAs("png", IndexedPng(includePalette: true, paletteAfterIdat: true));
    }

    [Fact]
    public void DdsRequiresAConsistentPixelFormatEncoding()
    {
        var valid = DdsRgb();
        AssertParity(valid, "dds");

        var missingEncoding = (byte[])valid.Clone();
        WriteUInt32LittleEndian(missingEncoding, 80, 0);
        AssertNotDetectedAs("dds", missingEncoding);

        var overlappingMasks = (byte[])valid.Clone();
        WriteUInt32LittleEndian(overlappingMasks, 96, 0x00FF0000);
        AssertNotDetectedAs("dds", overlappingMasks);
    }

    [Fact]
    public void DicomRequiresAllMandatoryFileMetaUids()
    {
        var valid = TestHelpers.CreateMinimalDicom();
        AssertParity(valid, "dcm");

        var missingTransferSyntax = (byte[])valid.Clone();
        int transferTag = Find(missingTransferSyntax, new byte[] { 2, 0, 0x10, 0 });
        Assert.True(transferTag >= 0);
        missingTransferSyntax[transferTag + 2] = 0x11;
        AssertNotDetectedAs("dcm", missingTransferSyntax);

        var invalidUid = (byte[])valid.Clone();
        int uid = Find(invalidUid, Encoding.ASCII.GetBytes("1.2.3.4.5.6.7.8.9"));
        Assert.True(uid >= 0);
        invalidUid[uid] = (byte)'X';
        AssertNotDetectedAs("dcm", invalidUid);
    }

    [Fact]
    public void ParquetAllowsExplicitlyReorderedCompactFieldsButRejectsDuplicates()
    {
        AssertParity(ReorderedParquet(duplicateVersion: false), "parquet");
        AssertNotDetectedAs("parquet", ReorderedParquet(duplicateVersion: true));
    }

    [Fact]
    public void OutlookNdbVersion21UsesTheUnicodeHeaderAndSecondaryCrc()
    {
        var valid = TestHelpers.CreateMinimalOutlookNdb(21);
        AssertParity(valid, "ndb");

        var invalid = (byte[])valid.Clone();
        invalid[524] ^= 1;
        AssertNotDetectedAs("ndb", invalid);
    }

    private static void AssertParity(byte[] bytes, string extension)
    {
        Assert.Equal(extension, FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false) { Position = Math.Min(7, bytes.Length) };
        Assert.Equal(extension, FileInspector.Detect(stream)?.Extension);
        Assert.Equal(Math.Min(7, bytes.Length), stream.Position);
    }

    private static void AssertNotDetectedAs(string extension, byte[] bytes)
    {
        Assert.NotEqual(extension, FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false);
        Assert.NotEqual(extension, FileInspector.Detect(stream)?.Extension);
    }

    private static byte[] ExtendedElf64()
    {
        var bytes = new byte[184];
        new byte[] { 0x7F, (byte)'E', (byte)'L', (byte)'F', 2, 1, 1 }.CopyTo(bytes, 0);
        WriteUInt16LittleEndian(bytes, 16, 2);
        WriteUInt16LittleEndian(bytes, 18, 62);
        WriteUInt32LittleEndian(bytes, 20, 1);
        WriteUInt64LittleEndian(bytes, 32, 128);
        WriteUInt64LittleEndian(bytes, 40, 64);
        WriteUInt16LittleEndian(bytes, 52, 64);
        WriteUInt16LittleEndian(bytes, 54, 56);
        WriteUInt16LittleEndian(bytes, 56, ushort.MaxValue);
        WriteUInt16LittleEndian(bytes, 58, 64);
        WriteUInt16LittleEndian(bytes, 60, 0);
        WriteUInt16LittleEndian(bytes, 62, ushort.MaxValue);
        WriteUInt64LittleEndian(bytes, 96, 1);
        WriteUInt32LittleEndian(bytes, 104, 0);
        WriteUInt32LittleEndian(bytes, 108, 1);
        return bytes;
    }

    private static byte[] Woff2(params (byte Flags, byte OriginalLength, byte TransformedLength)[] tables)
    {
        var bytes = new byte[48 + tables.Length * 3 + 1];
        Encoding.ASCII.GetBytes("wOF2OTTO").CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 8, (uint)bytes.Length);
        WriteUInt16BigEndian(bytes, 12, checked((ushort)tables.Length));
        WriteUInt32BigEndian(bytes, 16, checked((uint)(12 + tables.Length * 16)));
        WriteUInt32BigEndian(bytes, 20, 1);
        int cursor = 48;
        foreach (var table in tables)
        {
            bytes[cursor++] = table.Flags;
            bytes[cursor++] = table.OriginalLength;
            bytes[cursor++] = table.TransformedLength;
        }
        return bytes;
    }

    private static byte[] IndexedPng(bool includePalette, bool paletteAfterIdat)
    {
        using var stream = new MemoryStream();
        stream.Write(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }, 0, 8);
        var ihdr = new byte[13];
        ihdr[3] = 1; ihdr[7] = 1; ihdr[8] = 1; ihdr[9] = 3;
        WritePngChunk(stream, "IHDR", ihdr);
        if (includePalette && !paletteAfterIdat) WritePngChunk(stream, "PLTE", new byte[] { 0, 0, 0, 255, 255, 255 });
        WritePngChunk(stream, "IDAT", new byte[] { 0x78, 0x9C, 0x63, 0x60, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01 });
        if (includePalette && paletteAfterIdat) WritePngChunk(stream, "PLTE", new byte[] { 0, 0, 0, 255, 255, 255 });
        WritePngChunk(stream, "IEND", Array.Empty<byte>());
        return stream.ToArray();
    }

    private static void WritePngChunk(Stream stream, string type, byte[] data)
    {
        var header = new byte[8];
        WriteUInt32BigEndian(header, 0, (uint)data.Length);
        Encoding.ASCII.GetBytes(type).CopyTo(header, 4);
        stream.Write(header, 0, header.Length);
        stream.Write(data, 0, data.Length);
        var crcInput = new byte[4 + data.Length];
        Array.Copy(header, 4, crcInput, 0, 4);
        Array.Copy(data, 0, crcInput, 4, data.Length);
        var crc = new byte[4];
        WriteUInt32BigEndian(crc, 0, ComputeCrc32(crcInput));
        stream.Write(crc, 0, crc.Length);
    }

    private static byte[] DdsRgb()
    {
        var bytes = new byte[128];
        Encoding.ASCII.GetBytes("DDS ").CopyTo(bytes, 0);
        WriteUInt32LittleEndian(bytes, 4, 124);
        WriteUInt32LittleEndian(bytes, 8, 0x1007);
        WriteUInt32LittleEndian(bytes, 12, 1);
        WriteUInt32LittleEndian(bytes, 16, 1);
        WriteUInt32LittleEndian(bytes, 76, 32);
        WriteUInt32LittleEndian(bytes, 80, 0x41);
        WriteUInt32LittleEndian(bytes, 88, 32);
        WriteUInt32LittleEndian(bytes, 92, 0x00FF0000);
        WriteUInt32LittleEndian(bytes, 96, 0x0000FF00);
        WriteUInt32LittleEndian(bytes, 100, 0x000000FF);
        WriteUInt32LittleEndian(bytes, 104, 0xFF000000);
        WriteUInt32LittleEndian(bytes, 108, 0x1000);
        return bytes;
    }

    private static byte[] ReorderedParquet(bool duplicateVersion)
    {
        var metadata = new List<byte> {
            0x06, 0x06, 0x00,
            0x05, 0x02, 0x02,
            0x09, 0x08, 0x0C,
            0x09, 0x04, 0x1C, 0x48, 0x04, (byte)'r', (byte)'o', (byte)'o', (byte)'t', 0x00
        };
        if (duplicateVersion) metadata.AddRange(new byte[] { 0x05, 0x02, 0x02 });
        metadata.Add(0);
        var bytes = new byte[4 + metadata.Count + 8];
        Encoding.ASCII.GetBytes("PAR1").CopyTo(bytes, 0);
        metadata.CopyTo(bytes, 4);
        WriteUInt32LittleEndian(bytes, bytes.Length - 8, (uint)metadata.Count);
        Encoding.ASCII.GetBytes("PAR1").CopyTo(bytes, bytes.Length - 4);
        return bytes;
    }

    private static int Find(byte[] source, byte[] value)
    {
        for (int offset = 0; offset <= source.Length - value.Length; offset++)
        {
            bool equal = true;
            for (int index = 0; index < value.Length; index++) equal &= source[offset + index] == value[index];
            if (equal) return offset;
        }
        return -1;
    }

    private static uint ComputeCrc32(byte[] data)
    {
        uint crc = uint.MaxValue;
        foreach (byte value in data)
        {
            crc ^= value;
            for (int bit = 0; bit < 8; bit++) crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320u : crc >> 1;
        }
        return ~crc;
    }

    private static void WriteUInt16LittleEndian(byte[] bytes, int offset, ushort value)
    {
        bytes[offset] = (byte)value; bytes[offset + 1] = (byte)(value >> 8);
    }

    private static void WriteUInt16BigEndian(byte[] bytes, int offset, ushort value)
    {
        bytes[offset] = (byte)(value >> 8); bytes[offset + 1] = (byte)value;
    }

    private static void WriteUInt32LittleEndian(byte[] bytes, int offset, uint value)
    {
        for (int index = 0; index < 4; index++) bytes[offset + index] = (byte)(value >> (8 * index));
    }

    private static void WriteUInt32BigEndian(byte[] bytes, int offset, uint value)
    {
        for (int index = 0; index < 4; index++) bytes[offset + 3 - index] = (byte)(value >> (8 * index));
    }

    private static void WriteUInt64LittleEndian(byte[] bytes, int offset, ulong value)
    {
        for (int index = 0; index < 8; index++) bytes[offset + index] = (byte)(value >> (8 * index));
    }
}
