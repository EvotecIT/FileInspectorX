using System.IO.Compression;
using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class FiftyFourthReviewRegressionTests
{
    [Fact]
    public void IndexedPngPixelsMustReferenceTheDeclaredPalette()
    {
        AssertParity(IndexedPng(0), "png", "High");
        AssertNotDetectedAs(IndexedPng(1), "png");
    }

    [Fact]
    public void PngWithAnUnenforcedSmallDeflateWindowStaysAtMediumConfidence()
    {
        byte[] bytes = TestHelpers.CreateMinimalPng();
        bytes[41] = 0x08;
        bytes[42] = 0x1D;
        TestHelpers.WriteUInt32BigEndian(bytes, 52, ComputeCrc32(bytes.AsSpan(37, 15)));

        ContentTypeDetectionResult result = AssertParity(bytes, "png", "Medium");
        Assert.Contains("idat-not-fully-validated", result.Reason);
    }

    [Fact]
    public void StructurallyCompleteJpegStaysAtMediumWithoutEntropyValidation()
    {
        ContentTypeDetectionResult result = AssertParity(TestHelpers.CreateMinimalJpeg(), "jpg", "Medium");
        Assert.Contains("entropy-data-not-validated", result.Reason);
    }

    [Fact]
    public void ParquetColumnPayloadMustFitBeforeTheFooter()
    {
        AssertParity(ParquetWithColumnPayload(1), "parquet", "High");
        AssertNotDetectedAs(ParquetWithColumnPayload(2), "parquet");
    }

    [Fact]
    public void DebianTarMemberPaddingMustBeZero()
    {
        AssertParity(DebianPackage(nonzeroPadding: false), "deb", "High");
        AssertNotDetectedAs(DebianPackage(nonzeroPadding: true), "deb");
    }

    private static byte[] IndexedPng(byte paletteIndex)
    {
        using var output = new MemoryStream();
        output.Write(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }, 0, 8);
        var ihdr = new byte[13];
        TestHelpers.WriteUInt32BigEndian(ihdr, 0, 1);
        TestHelpers.WriteUInt32BigEndian(ihdr, 4, 1);
        ihdr[8] = 8;
        ihdr[9] = 3;
        WritePngChunk(output, "IHDR", ihdr);
        WritePngChunk(output, "PLTE", new byte[] { 0, 0, 0 });
        WritePngChunk(output, "IDAT", Zlib(new byte[] { 0, paletteIndex }));
        WritePngChunk(output, "IEND", Array.Empty<byte>());
        return output.ToArray();
    }

    private static byte[] Zlib(byte[] raw)
    {
        using var compressed = new MemoryStream();
        compressed.WriteByte(0x78);
        compressed.WriteByte(0x9C);
        using (var deflate = new DeflateStream(compressed, CompressionMode.Compress, leaveOpen: true))
            deflate.Write(raw, 0, raw.Length);
        uint adler = Adler32(raw);
        compressed.WriteByte((byte)(adler >> 24));
        compressed.WriteByte((byte)(adler >> 16));
        compressed.WriteByte((byte)(adler >> 8));
        compressed.WriteByte((byte)adler);
        return compressed.ToArray();
    }

    private static void WritePngChunk(Stream output, string type, byte[] data)
    {
        var length = new byte[4];
        TestHelpers.WriteUInt32BigEndian(length, 0, (uint)data.Length);
        output.Write(length, 0, length.Length);
        byte[] typeBytes = Encoding.ASCII.GetBytes(type);
        output.Write(typeBytes, 0, typeBytes.Length);
        output.Write(data, 0, data.Length);
        byte[] crcInput = typeBytes.Concat(data).ToArray();
        uint crc = ComputeCrc32(crcInput);
        var crcBytes = new byte[4];
        TestHelpers.WriteUInt32BigEndian(crcBytes, 0, crc);
        output.Write(crcBytes, 0, crcBytes.Length);
    }

    private static byte[] ParquetWithColumnPayload(int compressedSize)
    {
        var metadata = new List<byte>
        {
            0x15, 0x02,
            0x19, 0x2C,
                0x48, 0x04, (byte)'r', (byte)'o', (byte)'o', (byte)'t', 0x15, 0x02, 0x00,
                0x15, 0x00, 0x25, 0x00, 0x18, 0x01, (byte)'x', 0x00,
            0x16, 0x02,
            0x19, 0x1C,
                0x19, 0x1C, 0x18, 0x01, (byte)'x',
                0x16, 0x08,
                0x1C,
                    0x15, 0x00,
                    0x19, 0x15, 0x00,
                    0x19, 0x18, 0x01, (byte)'x',
                    0x15, 0x00,
                    0x16, 0x02,
                    0x16, 0x02,
                    0x16, (byte)(compressedSize * 2),
                    0x26, 0x08,
                    0x00,
                0x00,
                0x16, 0x02,
                0x16, 0x02,
                0x00,
            0x00
        };
        var bytes = new byte[5 + metadata.Count + 8];
        Encoding.ASCII.GetBytes("PAR1").CopyTo(bytes, 0);
        bytes[4] = 0x2A;
        metadata.CopyTo(bytes, 5);
        TestHelpers.WriteUInt32LittleEndian(bytes, bytes.Length - 8, (uint)metadata.Count);
        Encoding.ASCII.GetBytes("PAR1").CopyTo(bytes, bytes.Length - 4);
        return bytes;
    }

    private static byte[] DebianPackage(bool nonzeroPadding)
    {
        using var output = new MemoryStream();
        output.Write(Encoding.ASCII.GetBytes("!<arch>\n"), 0, 8);
        WriteArMember(output, "debian-binary", Encoding.ASCII.GetBytes("2.0\n"));
        WriteArMember(output, "control.tar", TarWithOneByteMember("control", nonzeroPadding));
        WriteArMember(output, "data.tar", TarWithOneByteMember("payload", nonzeroPadding: false));
        return output.ToArray();
    }

    private static byte[] TarWithOneByteMember(string name, bool nonzeroPadding)
    {
        var bytes = new byte[2048];
        Encoding.ASCII.GetBytes(name).CopyTo(bytes, 0);
        Encoding.ASCII.GetBytes("0000644\0").CopyTo(bytes, 100);
        Encoding.ASCII.GetBytes("0000000\0").CopyTo(bytes, 108);
        Encoding.ASCII.GetBytes("0000000\0").CopyTo(bytes, 116);
        Encoding.ASCII.GetBytes("00000000001\0").CopyTo(bytes, 124);
        Encoding.ASCII.GetBytes("00000000000\0").CopyTo(bytes, 136);
        for (int index = 148; index < 156; index++) bytes[index] = (byte)' ';
        bytes[156] = (byte)'0';
        Encoding.ASCII.GetBytes("ustar\0").CopyTo(bytes, 257);
        Encoding.ASCII.GetBytes("00").CopyTo(bytes, 263);
        int checksum = 0;
        for (int index = 0; index < 512; index++) checksum += bytes[index];
        Encoding.ASCII.GetBytes(Convert.ToString(checksum, 8)!.PadLeft(6, '0') + "\0 ").CopyTo(bytes, 148);
        bytes[512] = (byte)'x';
        if (nonzeroPadding) bytes[513] = 0xA5;
        return bytes;
    }

    private static void WriteArMember(Stream output, string name, byte[] data)
    {
        string header = (name + "/").PadRight(16) + "0".PadRight(12) + "0".PadRight(6) +
                        "0".PadRight(6) + "100644".PadRight(8) +
                        data.Length.ToString(System.Globalization.CultureInfo.InvariantCulture).PadRight(10) + "`\n";
        byte[] headerBytes = Encoding.ASCII.GetBytes(header);
        output.Write(headerBytes, 0, headerBytes.Length);
        output.Write(data, 0, data.Length);
        if ((data.Length & 1) != 0) output.WriteByte((byte)'\n');
    }

    private static uint Adler32(ReadOnlySpan<byte> data)
    {
        const uint modulus = 65521;
        uint a = 1;
        uint b = 0;
        foreach (byte value in data)
        {
            a = (a + value) % modulus;
            b = (b + a) % modulus;
        }
        return b << 16 | a;
    }

    private static uint ComputeCrc32(ReadOnlySpan<byte> data)
    {
        uint crc = uint.MaxValue;
        foreach (byte value in data)
        {
            crc ^= value;
            for (int bit = 0; bit < 8; bit++)
                crc = (crc & 1) != 0 ? crc >> 1 ^ 0xEDB88320u : crc >> 1;
        }
        return ~crc;
    }

    private static ContentTypeDetectionResult AssertParity(byte[] bytes, string extension, string confidence)
    {
        ContentTypeDetectionResult? fromBytes = FileInspector.Detect(bytes);
        using var stream = new MemoryStream(bytes, writable: false) { Position = Math.Min(3, bytes.Length) };
        ContentTypeDetectionResult? fromStream = FileInspector.Detect(stream);
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
}
