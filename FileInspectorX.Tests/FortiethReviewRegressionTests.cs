using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class FortiethReviewRegressionTests
{
    [Fact]
    public void PngRejectsInvalidAndUnknownCriticalChunkTypes()
    {
        AssertNotDetectedAs(PngWithInsertedChunk(new byte[] { (byte)'a', (byte)'b', (byte)'c', (byte)'d' }), "png");
        AssertNotDetectedAs(PngWithInsertedChunk(Encoding.ASCII.GetBytes("ABCD")), "png");
    }

    [Fact]
    public void WebAssemblyFramingWithoutPayloadSemanticsUsesReducedConfidence()
    {
        var result = AssertParity(Wasm(1, 1, 0xFF), "wasm", "Medium");
        Assert.Contains("section-payloads-not-validated", result.Reason);
    }

    [Fact]
    public void PcapNgFramingWithoutKnownBlockLayoutsUsesReducedConfidence()
    {
        var result = AssertParity(PcapNgWithUnknownBlock(), "pcapng", "Medium");
        Assert.Contains("block-layouts-not-fully-validated", result.Reason);
    }

    [Fact]
    public void ModernHdf5RootPrefixWithoutFullObjectHeaderUsesReducedConfidence()
    {
        var result = AssertParity(ModernHdf5(), "h5", "Medium");
        Assert.Contains("modern-root-not-fully-validated", result.Reason);
    }

    [Fact]
    public void OggPageFramingWithoutLogicalStreamSequencingUsesReducedConfidence()
    {
        var result = AssertParity(TestHelpers.CreateMinimalOgg(), "ogg", "Medium");
        Assert.Contains("logical-stream-sequencing-not-validated", result.Reason);
    }

    [Fact]
    public void RegistryBinsWithoutACompleteCellWalkUseReducedConfidence()
    {
        var result = AssertParity(RegistryHive(), "hive", "Medium");
        Assert.Contains("cell-chain-not-validated", result.Reason);
    }

    [Fact]
    public void MachOLoadCommandFramingWithoutCommandSemanticsUsesReducedConfidence()
    {
        var result = AssertParity(ThinMachO(), "macho", "Medium");
        Assert.Contains("command-layouts-not-fully-validated", result.Reason);
    }

    [Fact]
    public void ElfTableRangesWithoutEntrySemanticsUseReducedConfidence()
    {
        var result = AssertParity(ElfWithUnvalidatedProgramEntry(), "elf", "Medium");
        Assert.Contains("table-entries-not-validated", result.Reason);
    }

    [Fact]
    public void PeSectionTableFramingWithoutEntrySemanticsUsesReducedConfidence()
    {
        byte[] bytes = TestHelpers.CreateMinimalPe();
        TestHelpers.WriteUInt32LittleEndian(bytes, 0x188, 0x200);
        TestHelpers.WriteUInt32LittleEndian(bytes, 0x18C, 0x1000);
        var result = AssertParity(bytes, "exe", "Medium");
        Assert.Contains("section-entries-not-validated", result.Reason);
    }

    private static ContentTypeDetectionResult AssertParity(byte[] bytes, string extension, string confidence)
    {
        var fromBytes = FileInspector.Detect(bytes);
        using var stream = new MemoryStream(bytes, writable: false) { Position = Math.Min(3, bytes.Length) };
        var fromStream = FileInspector.Detect(stream);
        Assert.Equal(extension, fromBytes?.Extension);
        Assert.Equal(extension, fromStream?.Extension);
        Assert.Equal(confidence, fromBytes?.Confidence);
        Assert.Equal(confidence, fromStream?.Confidence);
        Assert.Equal(Math.Min(3, bytes.Length), stream.Position);
        return fromBytes!;
    }

    private static void AssertNotDetectedAs(byte[] bytes, string extension)
    {
        Assert.NotEqual(extension, FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false);
        Assert.NotEqual(extension, FileInspector.Detect(stream)?.Extension);
    }

    private static byte[] PngWithInsertedChunk(byte[] type)
    {
        byte[] png = TestHelpers.CreateMinimalPng();
        const int insertionOffset = 33;
        var bytes = new byte[png.Length + 12];
        Array.Copy(png, 0, bytes, 0, insertionOffset);
        type.CopyTo(bytes, insertionOffset + 4);
        TestHelpers.WriteUInt32BigEndian(bytes, insertionOffset + 8, ComputePngCrc(type));
        Array.Copy(png, insertionOffset, bytes, insertionOffset + 12, png.Length - insertionOffset);
        return bytes;
    }

    private static uint ComputePngCrc(ReadOnlySpan<byte> bytes)
    {
        uint crc = 0xFFFFFFFF;
        for (int index = 0; index < bytes.Length; index++)
        {
            crc ^= bytes[index];
            for (int bit = 0; bit < 8; bit++) crc = (crc & 1) != 0 ? 0xEDB88320 ^ (crc >> 1) : crc >> 1;
        }
        return ~crc;
    }

    private static byte[] Wasm(params byte[] sections)
    {
        var bytes = new byte[8 + sections.Length];
        bytes[0] = 0;
        Encoding.ASCII.GetBytes("asm").CopyTo(bytes, 1);
        bytes[4] = 1;
        sections.CopyTo(bytes, 8);
        return bytes;
    }

    private static byte[] PcapNgWithUnknownBlock()
    {
        var bytes = new byte[40];
        bytes[0] = 0x0A; bytes[1] = 0x0D; bytes[2] = 0x0D; bytes[3] = 0x0A;
        TestHelpers.WriteUInt32LittleEndian(bytes, 4, 28);
        bytes[8] = 0x4D; bytes[9] = 0x3C; bytes[10] = 0x2B; bytes[11] = 0x1A;
        TestHelpers.WriteUInt16LittleEndian(bytes, 12, 1);
        for (int offset = 16; offset < 24; offset++) bytes[offset] = 0xFF;
        TestHelpers.WriteUInt32LittleEndian(bytes, 24, 28);
        TestHelpers.WriteUInt32LittleEndian(bytes, 28, 0x00000BAD);
        TestHelpers.WriteUInt32LittleEndian(bytes, 32, 12);
        TestHelpers.WriteUInt32LittleEndian(bytes, 36, 12);
        return bytes;
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

    private static uint Hdf5Checksum(ReadOnlySpan<byte> source)
    {
        unchecked
        {
            uint a = 0xDEADBEEF + (uint)source.Length, b = a, c = a;
            int cursor = 0, remaining = source.Length;
            while (remaining > 12)
            {
                a += Read32(source, cursor); b += Read32(source, cursor + 4); c += Read32(source, cursor + 8);
                a -= c; a ^= Rotate(c, 4); c += b; b -= a; b ^= Rotate(a, 6); a += c;
                c -= b; c ^= Rotate(b, 8); b += a; a -= c; a ^= Rotate(c, 16); c += b;
                b -= a; b ^= Rotate(a, 19); a += c; c -= b; c ^= Rotate(b, 4); b += a;
                cursor += 12; remaining -= 12;
            }
            for (int index = 0; index < remaining; index++)
            {
                uint value = (uint)source[cursor + index] << ((index % 4) * 8);
                if (index < 4) a += value; else if (index < 8) b += value; else c += value;
            }
            if (remaining == 0) return c;
            c ^= b; c -= Rotate(b, 14); a ^= c; a -= Rotate(c, 11); b ^= a; b -= Rotate(a, 25);
            c ^= b; c -= Rotate(b, 16); a ^= c; a -= Rotate(c, 4); b ^= a; b -= Rotate(a, 14); c ^= b; c -= Rotate(b, 24);
            return c;
        }
    }

    private static uint Read32(ReadOnlySpan<byte> source, int offset)
        => (uint)(source[offset] | source[offset + 1] << 8 | source[offset + 2] << 16 | source[offset + 3] << 24);

    private static uint Rotate(uint value, int count) => value << count | value >> (32 - count);

    private static byte[] RegistryHive()
    {
        var bytes = new byte[8192];
        Encoding.ASCII.GetBytes("regf").CopyTo(bytes, 0);
        TestHelpers.WriteUInt32LittleEndian(bytes, 4, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 8, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 20, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 24, 5);
        TestHelpers.WriteUInt32LittleEndian(bytes, 32, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 36, 0x20);
        TestHelpers.WriteUInt32LittleEndian(bytes, 40, 0x1000);
        TestHelpers.WriteUInt32LittleEndian(bytes, 44, 1);
        Encoding.ASCII.GetBytes("hbin").CopyTo(bytes, 4096);
        TestHelpers.WriteUInt32LittleEndian(bytes, 4104, 0x1000);
        TestHelpers.WriteUInt32LittleEndian(bytes, 4096 + 0x20, 0xFFFFFFB0);
        Encoding.ASCII.GetBytes("nk").CopyTo(bytes, 4096 + 0x24);
        uint checksum = 0;
        for (int offset = 0; offset < 0x1FC; offset += 4) checksum ^= ReadUInt32LittleEndian(bytes, offset);
        TestHelpers.WriteUInt32LittleEndian(bytes, 0x1FC, checksum == 0 ? 1 : checksum == uint.MaxValue ? 0xFFFFFFFE : checksum);
        return bytes;
    }

    private static uint ReadUInt32LittleEndian(byte[] bytes, int offset)
        => (uint)(bytes[offset] | bytes[offset + 1] << 8 | bytes[offset + 2] << 16 | bytes[offset + 3] << 24);

    private static byte[] ThinMachO()
    {
        var bytes = new byte[40];
        TestHelpers.WriteUInt32LittleEndian(bytes, 0, 0xFEEDFACF);
        TestHelpers.WriteUInt32LittleEndian(bytes, 4, 0x01000007);
        TestHelpers.WriteUInt32LittleEndian(bytes, 12, 2);
        TestHelpers.WriteUInt32LittleEndian(bytes, 16, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 20, 8);
        TestHelpers.WriteUInt32LittleEndian(bytes, 32, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 36, 8);
        return bytes;
    }

    private static byte[] ElfWithUnvalidatedProgramEntry()
    {
        var bytes = new byte[120];
        bytes[0] = 0x7F; bytes[1] = (byte)'E'; bytes[2] = (byte)'L'; bytes[3] = (byte)'F';
        bytes[4] = 2; bytes[5] = 1; bytes[6] = 1;
        TestHelpers.WriteUInt16LittleEndian(bytes, 16, 2);
        TestHelpers.WriteUInt16LittleEndian(bytes, 18, 62);
        TestHelpers.WriteUInt32LittleEndian(bytes, 20, 1);
        TestHelpers.WriteUInt64LittleEndian(bytes, 32, 64);
        TestHelpers.WriteUInt16LittleEndian(bytes, 52, 64);
        TestHelpers.WriteUInt16LittleEndian(bytes, 54, 56);
        TestHelpers.WriteUInt16LittleEndian(bytes, 56, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 64, 1);
        TestHelpers.WriteUInt64LittleEndian(bytes, 72, 1000);
        TestHelpers.WriteUInt64LittleEndian(bytes, 96, 10);
        return bytes;
    }
}
