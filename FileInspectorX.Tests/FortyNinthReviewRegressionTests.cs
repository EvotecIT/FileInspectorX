using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class FortyNinthReviewRegressionTests
{
    [Theory]
    [InlineData(10)]
    [InlineData(14)]
    public void LosslessJpegAcceptsTwoThroughSixteenBitSamplePrecision(byte precision)
    {
        byte[] lossless = TestHelpers.CreateMinimalJpeg();
        lossless[3] = 0xC3;
        lossless[6] = precision;
        AssertParity(lossless, "jpg", "High");

        byte[] baseline = TestHelpers.CreateMinimalJpeg();
        baseline[6] = precision;
        AssertNotDetectedAs(baseline, "jpg");
    }

    [Fact]
    public void PngOrderConstrainedAncillaryChunksMustPrecedeIdat()
    {
        ContentTypeDetectionResult result = AssertParity(PngWithTransparency(afterIdat: false), "png", "Medium");
        Assert.Contains("ancillary-semantics-not-validated", result.Reason);
        AssertNotDetectedAs(PngWithTransparency(afterIdat: true), "png");
    }

    [Fact]
    public void RleBmpAndIconPayloadsStayAtMediumConfidenceUntilDecoded()
    {
        ContentTypeDetectionResult bmp = AssertParity(RleBmp(), "bmp", "Medium");
        Assert.Contains("rle-payload-not-validated", bmp.Reason);
        ContentTypeDetectionResult icon = AssertParity(RleIcon(), "ico", "Medium");
        Assert.Contains("rle-payload-not-validated", icon.Reason);
    }

    [Fact]
    public void Crx3SkipsUnknownLegalProtobufWireTypes()
    {
        byte[] unknownFields =
        {
            0x20, 0x01,
            0x29, 1, 2, 3, 4, 5, 6, 7, 8,
            0x35, 1, 2, 3, 4,
            0x3A, 0,
            0x43, 0x48, 1, 0x44
        };
        AssertParity(InsertCrx3HeaderBytes(TestHelpers.CreateMinimalCrx3(), unknownFields), "crx", "Medium");

        byte[] wrongGroupEnd = { 0x43, 0x4C };
        AssertNotDetectedAs(InsertCrx3HeaderBytes(TestHelpers.CreateMinimalCrx3(), wrongGroupEnd), "crx");
    }

    private static byte[] PngWithTransparency(bool afterIdat)
    {
        using var stream = new MemoryStream();
        stream.Write(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A });
        byte[] ihdr = new byte[13];
        TestHelpers.WriteUInt32BigEndian(ihdr, 0, 1);
        TestHelpers.WriteUInt32BigEndian(ihdr, 4, 1);
        ihdr[8] = 8;
        ihdr[9] = 2;
        WritePngChunk(stream, "IHDR", ihdr);
        if (!afterIdat) WritePngChunk(stream, "tRNS", new byte[6]);
        WritePngChunk(stream, "IDAT", new byte[] { 0x78, 0x9C, 0x63, 0x60, 0x60, 0x60, 0, 0, 0, 4, 0, 1 });
        if (afterIdat) WritePngChunk(stream, "tRNS", new byte[6]);
        WritePngChunk(stream, "IEND", Array.Empty<byte>());
        return stream.ToArray();
    }

    private static void WritePngChunk(Stream stream, string type, byte[] data)
    {
        var length = new byte[4];
        TestHelpers.WriteUInt32BigEndian(length, 0, (uint)data.Length);
        stream.Write(length);
        byte[] typeBytes = Encoding.ASCII.GetBytes(type);
        stream.Write(typeBytes);
        stream.Write(data);
        byte[] crcData = typeBytes.Concat(data).ToArray();
        var crc = new byte[4];
        TestHelpers.WriteUInt32BigEndian(crc, 0, Crc32(crcData));
        stream.Write(crc);
    }

    private static byte[] RleBmp()
    {
        const int pixelOffset = 58;
        var bytes = new byte[pixelOffset + 4];
        Encoding.ASCII.GetBytes("BM").CopyTo(bytes, 0);
        TestHelpers.WriteUInt32LittleEndian(bytes, 2, (uint)bytes.Length);
        TestHelpers.WriteUInt32LittleEndian(bytes, 10, pixelOffset);
        TestHelpers.WriteUInt32LittleEndian(bytes, 14, 40);
        TestHelpers.WriteUInt32LittleEndian(bytes, 18, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 22, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, 26, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, 28, 8);
        TestHelpers.WriteUInt32LittleEndian(bytes, 30, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 34, 4);
        TestHelpers.WriteUInt32LittleEndian(bytes, 46, 1);
        new byte[] { 0, 2, 0, 0 }.CopyTo(bytes, pixelOffset);
        return bytes;
    }

    private static byte[] RleIcon()
    {
        const int payloadOffset = 22;
        const int payloadLength = 50;
        var bytes = new byte[payloadOffset + payloadLength];
        TestHelpers.WriteUInt16LittleEndian(bytes, 2, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, 4, 1);
        bytes[6] = 1;
        bytes[7] = 1;
        TestHelpers.WriteUInt16LittleEndian(bytes, 10, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, 12, 8);
        TestHelpers.WriteUInt32LittleEndian(bytes, 14, payloadLength);
        TestHelpers.WriteUInt32LittleEndian(bytes, 18, payloadOffset);
        TestHelpers.WriteUInt32LittleEndian(bytes, payloadOffset, 40);
        TestHelpers.WriteUInt32LittleEndian(bytes, payloadOffset + 4, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, payloadOffset + 8, 2);
        TestHelpers.WriteUInt16LittleEndian(bytes, payloadOffset + 12, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, payloadOffset + 14, 8);
        TestHelpers.WriteUInt32LittleEndian(bytes, payloadOffset + 16, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, payloadOffset + 20, 2);
        TestHelpers.WriteUInt32LittleEndian(bytes, payloadOffset + 32, 1);
        return bytes;
    }

    private static byte[] InsertCrx3HeaderBytes(byte[] original, byte[] added)
    {
        int headerLength = checked((int)ReadUInt32LittleEndian(original, 8));
        var bytes = new byte[original.Length + added.Length];
        Array.Copy(original, 0, bytes, 0, 12 + headerLength);
        added.CopyTo(bytes, 12 + headerLength);
        Array.Copy(original, 12 + headerLength, bytes, 12 + headerLength + added.Length,
            original.Length - 12 - headerLength);
        TestHelpers.WriteUInt32LittleEndian(bytes, 8, checked((uint)(headerLength + added.Length)));
        return bytes;
    }

    private static uint ReadUInt32LittleEndian(byte[] bytes, int offset)
        => (uint)(bytes[offset] | bytes[offset + 1] << 8 | bytes[offset + 2] << 16 | bytes[offset + 3] << 24);

    private static uint Crc32(byte[] data)
    {
        uint crc = uint.MaxValue;
        foreach (byte value in data)
        {
            crc ^= value;
            for (int bit = 0; bit < 8; bit++) crc = (crc & 1) != 0 ? 0xEDB88320u ^ crc >> 1 : crc >> 1;
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
        using var stream = new MemoryStream(bytes, writable: false) { Position = Math.Min(3, bytes.Length) };
        Assert.NotEqual(extension, FileInspector.Detect(stream)?.Extension);
        Assert.Equal(Math.Min(3, bytes.Length), stream.Position);
    }
}
