using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class TwentiethReviewRegressionTests
{
    [Theory]
    [InlineData("elf")]
    [InlineData("macho")]
    public void NativeExecutableDetectionsAreDangerous(string extension)
    {
        byte[] bytes = extension == "elf" ? MinimalElf64() : ThinMachO64();
        var detection = FileInspector.Detect(bytes);

        Assert.Equal(extension, detection?.Extension);
        Assert.True(detection?.IsDangerous);
        var comparison = FileInspector.CompareDeclaredDetailed("txt", detection);
        Assert.True(comparison.IsDetectedDangerous);
        Assert.True(comparison.Mismatch);
    }

    [Fact]
    public void ZipDescriptorFlagRequiresBytesBeyondTheLocalHeader()
    {
        byte[] incomplete = ZipWithDescriptorFlag(includeDescriptor: false);
        AssertNotDetectedAs("zip", incomplete);
        AssertParity(ZipWithDescriptorFlag(includeDescriptor: true), "zip");
    }

    [Fact]
    public void ParquetWideListsAreBoundedByFooterBytesInsteadOfAnElementCap()
        => AssertParity(WideParquet(4097), "parquet");

    [Fact]
    public void DynamicVhdBatMustCoverTheCurrentVirtualSize()
    {
        AssertParity(DynamicVhd(2UL * 1024 * 1024, entries: 1), "vhd");
        AssertNotDetectedAs("vhd", DynamicVhd(4UL * 1024 * 1024, entries: 1));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void PhotoshopRequiresCompressionSpecificImageData(ushort compression)
    {
        byte[] valid = MinimalPhotoshop(compression);
        AssertParity(valid, "psd");
        Array.Resize(ref valid, 40);
        AssertNotDetectedAs("psd", valid);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void WoffMetadataRequiresACompleteLengthTuple(bool woff2)
    {
        byte[] valid = woff2 ? MinimalWoff2() : MinimalWoff1();
        AssertParity(valid, woff2 ? "woff2" : "woff");
        AssertParity(WoffWithMetadata(valid, woff2), woff2 ? "woff2" : "woff");

        byte[] invalid = (byte[])valid.Clone();
        WriteUInt32BigEndian(invalid, woff2 ? 36 : 32, 1);
        AssertNotDetectedAs(woff2 ? "woff2" : "woff", invalid);
    }

    [Theory]
    [InlineData(0u, 1u)]
    [InlineData(1u, 0u)]
    public void Crx2RequiresNonemptyKeyAndSignature(uint keyLength, uint signatureLength)
        => AssertNotDetectedAs("crx", Crx2(keyLength, signatureLength));

    [Fact]
    public void Crx2AcceptsBoundedNonemptyAuthenticationSections()
        => AssertParity(Crx2(1, 1), "crx");

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

    private static byte[] MinimalElf64()
    {
        var bytes = new byte[64];
        new byte[] { 0x7F, (byte)'E', (byte)'L', (byte)'F', 2, 1, 1 }.CopyTo(bytes, 0);
        WriteUInt16LittleEndian(bytes, 16, 2);
        WriteUInt16LittleEndian(bytes, 18, 62);
        WriteUInt32LittleEndian(bytes, 20, 1);
        WriteUInt16LittleEndian(bytes, 52, 64);
        WriteUInt16LittleEndian(bytes, 54, 56);
        WriteUInt16LittleEndian(bytes, 58, 64);
        return bytes;
    }

    private static byte[] ThinMachO64()
    {
        var bytes = new byte[32];
        new byte[] { 0xCF, 0xFA, 0xED, 0xFE }.CopyTo(bytes, 0);
        WriteUInt32LittleEndian(bytes, 4, 0x01000007);
        WriteUInt32LittleEndian(bytes, 8, 3);
        WriteUInt32LittleEndian(bytes, 12, 2);
        return bytes;
    }

    private static byte[] ZipWithDescriptorFlag(bool includeDescriptor)
    {
        var bytes = new byte[31 + (includeDescriptor ? 12 : 0)];
        WriteUInt32LittleEndian(bytes, 0, 0x04034B50);
        WriteUInt16LittleEndian(bytes, 4, 20);
        WriteUInt16LittleEndian(bytes, 6, 8);
        WriteUInt16LittleEndian(bytes, 26, 1);
        bytes[30] = (byte)'a';
        return bytes;
    }

    private static byte[] WideParquet(int schemaElements)
    {
        var metadata = new List<byte> { 0x15, 0x02, 0x19, 0xFC };
        AddVarint(metadata, (uint)schemaElements);
        for (int index = 0; index < schemaElements; index++)
            metadata.AddRange(new byte[] { 0x48, 0x01, (byte)'x', 0x00 });
        metadata.AddRange(new byte[] { 0x16, 0x00, 0x19, 0x0C, 0x00 });
        var bytes = new byte[4 + metadata.Count + 8];
        Encoding.ASCII.GetBytes("PAR1").CopyTo(bytes, 0);
        metadata.CopyTo(bytes, 4);
        WriteUInt32LittleEndian(bytes, bytes.Length - 8, (uint)metadata.Count);
        Encoding.ASCII.GetBytes("PAR1").CopyTo(bytes, bytes.Length - 4);
        return bytes;
    }

    private static byte[] DynamicVhd(ulong currentSize, uint entries)
    {
        var bytes = new byte[2560];
        int header = 512;
        Encoding.ASCII.GetBytes("cxsparse").CopyTo(bytes, header);
        WriteUInt64BigEndian(bytes, header + 8, ulong.MaxValue);
        WriteUInt64BigEndian(bytes, header + 16, 1536);
        WriteUInt32BigEndian(bytes, header + 24, 0x00010000);
        WriteUInt32BigEndian(bytes, header + 28, entries);
        WriteUInt32BigEndian(bytes, header + 32, 2 * 1024 * 1024);
        FinalizeChecksum(bytes, header, 1024, header + 36);

        int footer = bytes.Length - 512;
        Encoding.ASCII.GetBytes("conectix").CopyTo(bytes, footer);
        WriteUInt32BigEndian(bytes, footer + 8, 2);
        WriteUInt32BigEndian(bytes, footer + 12, 0x00010000);
        WriteUInt64BigEndian(bytes, footer + 16, 512);
        WriteUInt64BigEndian(bytes, footer + 40, currentSize);
        WriteUInt64BigEndian(bytes, footer + 48, currentSize);
        WriteUInt32BigEndian(bytes, footer + 56, 0x00010101);
        WriteUInt32BigEndian(bytes, footer + 60, 3);
        bytes[footer + 68] = 1;
        FinalizeChecksum(bytes, footer, 512, footer + 64);
        return bytes;
    }

    private static byte[] MinimalWoff1()
    {
        var bytes = new byte[68];
        Encoding.ASCII.GetBytes("wOFF").CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 4, 0x00010000);
        WriteUInt32BigEndian(bytes, 8, (uint)bytes.Length);
        WriteUInt16BigEndian(bytes, 12, 1);
        WriteUInt32BigEndian(bytes, 16, 32);
        Encoding.ASCII.GetBytes("head").CopyTo(bytes, 44);
        WriteUInt32BigEndian(bytes, 48, 64);
        WriteUInt32BigEndian(bytes, 52, 1);
        WriteUInt32BigEndian(bytes, 56, 1);
        return bytes;
    }

    private static byte[] MinimalWoff2()
    {
        var bytes = new byte[52];
        Encoding.ASCII.GetBytes("wOF2OTTO").CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 8, (uint)bytes.Length);
        WriteUInt16BigEndian(bytes, 12, 1);
        WriteUInt32BigEndian(bytes, 16, 32);
        WriteUInt32BigEndian(bytes, 20, 2);
        bytes[48] = 0;
        bytes[49] = 1;
        return bytes;
    }

    private static byte[] WoffWithMetadata(byte[] source, bool woff2)
    {
        int metadataLength = woff2 ? 2 : 4;
        var bytes = new byte[source.Length + metadataLength];
        source.CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 8, (uint)bytes.Length);
        WriteUInt32BigEndian(bytes, woff2 ? 28 : 24, (uint)source.Length);
        WriteUInt32BigEndian(bytes, woff2 ? 32 : 28, (uint)metadataLength);
        WriteUInt32BigEndian(bytes, woff2 ? 36 : 32, (uint)(metadataLength + 1));
        return bytes;
    }

    private static byte[] MinimalPhotoshop(ushort compression)
    {
        byte[] payload = compression switch
        {
            0 => new byte[3],
            1 => new byte[] { 0, 2, 0, 2, 0, 2, 0xFF, 0, 0xFF, 0, 0xFF, 0 },
            2 or 3 => new byte[] { 0x78, 0x9C },
            _ => throw new ArgumentOutOfRangeException(nameof(compression))
        };
        var bytes = new byte[40 + payload.Length];
        Encoding.ASCII.GetBytes("8BPS").CopyTo(bytes, 0);
        WriteUInt16BigEndian(bytes, 4, 1);
        WriteUInt16BigEndian(bytes, 12, 3);
        WriteUInt32BigEndian(bytes, 14, 1);
        WriteUInt32BigEndian(bytes, 18, 1);
        WriteUInt16BigEndian(bytes, 22, 8);
        WriteUInt16BigEndian(bytes, 24, 3);
        WriteUInt16BigEndian(bytes, 38, compression);
        payload.CopyTo(bytes, 40);
        return bytes;
    }

    private static byte[] Crx2(uint keyLength, uint signatureLength)
    {
        byte[] zip = ZipWithDescriptorFlag(includeDescriptor: false);
        WriteUInt16LittleEndian(zip, 6, 0);
        var bytes = new byte[16 + checked((int)keyLength) + checked((int)signatureLength) + zip.Length];
        Encoding.ASCII.GetBytes("Cr24").CopyTo(bytes, 0);
        WriteUInt32LittleEndian(bytes, 4, 2);
        WriteUInt32LittleEndian(bytes, 8, keyLength);
        WriteUInt32LittleEndian(bytes, 12, signatureLength);
        if (keyLength > 0) bytes[16] = 1;
        if (signatureLength > 0) bytes[16 + (int)keyLength] = 2;
        zip.CopyTo(bytes, 16 + (int)keyLength + (int)signatureLength);
        return bytes;
    }

    private static void FinalizeChecksum(byte[] bytes, int offset, int length, int checksumOffset)
    {
        WriteUInt32BigEndian(bytes, checksumOffset, 0);
        uint sum = 0;
        for (int index = offset; index < offset + length; index++)
            if (index < checksumOffset || index >= checksumOffset + 4) sum += bytes[index];
        WriteUInt32BigEndian(bytes, checksumOffset, ~sum);
    }

    private static void AddVarint(List<byte> bytes, uint value)
    {
        while (value >= 0x80) { bytes.Add((byte)(value | 0x80)); value >>= 7; }
        bytes.Add((byte)value);
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

    private static void WriteUInt64BigEndian(byte[] bytes, int offset, ulong value)
    {
        for (int index = 0; index < 8; index++) bytes[offset + 7 - index] = (byte)(value >> (8 * index));
    }
}
