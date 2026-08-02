using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

[Collection(nameof(DetectionSettingsCollection))]
public sealed class FiftySecondReviewRegressionTests
{
    [Fact]
    public void PngRejectsBytesAfterTheFinalDeflateBlock()
    {
        AssertParity(TestHelpers.CreateMinimalPng(), "png", "High");
        AssertNotDetectedAs(PngWithTrailingDeflateByte(), "png");
    }

    [Fact]
    public void SeekableDebianTarPaddingIsBoundedByTheDetectionBudget()
    {
        WithReadBudget(2048, () =>
        {
            using var stream = new CountingMemoryStream(CreateDebWithLargeControlPadding(8 * 1024 * 1024));
            ContentTypeDetectionResult? result = FileInspector.Detect(stream);
            Assert.Equal("deb", result?.Extension);
            Assert.Equal("Medium", result?.Confidence);
            Assert.Contains("partially-validated", result?.Reason);
            Assert.InRange(stream.BytesRead, 1, 100_000);
        });
    }

    [Fact]
    public void SeekableRegistryHiveBinWalkIsBoundedByTheDetectionBudget()
    {
        WithReadBudget(256, () =>
        {
            using var stream = new CountingMemoryStream(LargeRegistryHive(32 * 1024 * 1024));
            Assert.True(Signatures.TryMatchRegistryHive(stream, out ContentTypeDetectionResult? result));
            Assert.Equal("hive", result?.Extension);
            Assert.Equal("Medium", result?.Confidence);
            Assert.Contains("budgeted-hbins", result?.Reason);
            Assert.InRange(stream.BytesRead, 1, 8192);
        });
    }

    [Fact]
    public void DdsTrailingBytesCannotReceiveHighConfidence()
    {
        byte[] exact = MinimalDds();
        AssertParity(exact, "dds", "High");
        ContentTypeDetectionResult result = AssertParity(exact.Concat(new byte[] { 0 }).ToArray(), "dds", "Medium");
        Assert.Contains("trailing-data-not-validated", result.Reason);
    }

    [Fact]
    public void BaselineJpegRequiresSequentialScanParameters()
    {
        AssertParity(TestHelpers.CreateMinimalJpeg(), "jpg", "High");
        byte[] malformed = TestHelpers.CreateMinimalJpeg();
        malformed[22] = 255;
        AssertNotDetectedAs(malformed, "jpg");
    }

    private static byte[] PngWithTrailingDeflateByte()
    {
        byte[] valid = TestHelpers.CreateMinimalPng();
        var malformed = new byte[valid.Length + 1];
        valid.AsSpan(0, 48).CopyTo(malformed);
        malformed[48] = 0xA5;
        valid.AsSpan(48, 4).CopyTo(malformed.AsSpan(49));
        valid.AsSpan(56).CopyTo(malformed.AsSpan(57));
        TestHelpers.WriteUInt32BigEndian(malformed, 33, 12);
        TestHelpers.WriteUInt32BigEndian(malformed, 53, ComputeCrc32(malformed.AsSpan(37, 16)));
        return malformed;
    }

    private static byte[] CreateDebWithLargeControlPadding(int controlLength)
    {
        using var stream = new MemoryStream();
        stream.Write(Encoding.ASCII.GetBytes("!<arch>\n"));
        WriteArMember(stream, "debian-binary", Encoding.ASCII.GetBytes("2.0\n"));
        WriteArMember(stream, "control.tar", CreateTar("control", controlLength));
        WriteArMember(stream, "data.tar", CreateTar("payload", 1536));
        return stream.ToArray();
    }

    private static byte[] CreateTar(string memberName, int length)
    {
        var bytes = new byte[length];
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
        string header = (name + "/").PadRight(16) + "0".PadRight(12) + "0".PadRight(6) +
                        "0".PadRight(6) + "100644".PadRight(8) +
                        data.Length.ToString(System.Globalization.CultureInfo.InvariantCulture).PadRight(10) + "`\n";
        stream.Write(Encoding.ASCII.GetBytes(header));
        stream.Write(data);
        if ((data.Length & 1) != 0) stream.WriteByte((byte)'\n');
    }

    private static byte[] LargeRegistryHive(int hiveBinsSize)
    {
        var bytes = new byte[4096 + hiveBinsSize];
        Encoding.ASCII.GetBytes("regf").CopyTo(bytes, 0);
        TestHelpers.WriteUInt32LittleEndian(bytes, 4, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 8, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 20, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 24, 5);
        TestHelpers.WriteUInt32LittleEndian(bytes, 32, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 36, 0x20);
        TestHelpers.WriteUInt32LittleEndian(bytes, 40, (uint)hiveBinsSize);
        TestHelpers.WriteUInt32LittleEndian(bytes, 44, 1);
        for (int cursor = 0; cursor < hiveBinsSize; cursor += 4096)
        {
            int offset = 4096 + cursor;
            Encoding.ASCII.GetBytes("hbin").CopyTo(bytes, offset);
            TestHelpers.WriteUInt32LittleEndian(bytes, offset + 4, (uint)cursor);
            TestHelpers.WriteUInt32LittleEndian(bytes, offset + 8, 4096);
        }
        TestHelpers.WriteUInt32LittleEndian(bytes, 4096 + 0x20, 0xFFFFFFB0);
        Encoding.ASCII.GetBytes("nk").CopyTo(bytes, 4096 + 0x24);
        uint checksum = 0;
        for (int offset = 0; offset < 0x1FC; offset += 4)
            checksum ^= ReadUInt32LittleEndian(bytes, offset);
        TestHelpers.WriteUInt32LittleEndian(bytes, 0x1FC, checksum);
        return bytes;
    }

    private static byte[] MinimalDds()
    {
        var bytes = new byte[132];
        Encoding.ASCII.GetBytes("DDS ").CopyTo(bytes, 0);
        TestHelpers.WriteUInt32LittleEndian(bytes, 4, 124);
        TestHelpers.WriteUInt32LittleEndian(bytes, 8, 0x1007);
        TestHelpers.WriteUInt32LittleEndian(bytes, 12, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 16, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 76, 32);
        TestHelpers.WriteUInt32LittleEndian(bytes, 80, 0x41);
        TestHelpers.WriteUInt32LittleEndian(bytes, 88, 32);
        TestHelpers.WriteUInt32LittleEndian(bytes, 92, 0x00FF0000);
        TestHelpers.WriteUInt32LittleEndian(bytes, 96, 0x0000FF00);
        TestHelpers.WriteUInt32LittleEndian(bytes, 100, 0x000000FF);
        TestHelpers.WriteUInt32LittleEndian(bytes, 104, 0xFF000000);
        TestHelpers.WriteUInt32LittleEndian(bytes, 108, 0x1000);
        return bytes;
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

    private static uint ReadUInt32LittleEndian(byte[] bytes, int offset)
        => (uint)(bytes[offset] | bytes[offset + 1] << 8 | bytes[offset + 2] << 16 | bytes[offset + 3] << 24);

    private static void WithReadBudget(int budget, Action assertion)
    {
        int original = Settings.DetectionReadBudgetBytes;
        try { Settings.DetectionReadBudgetBytes = budget; assertion(); }
        finally { Settings.DetectionReadBudgetBytes = original; }
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
        return fromStream!;
    }

    private static void AssertNotDetectedAs(byte[] bytes, string extension)
    {
        Assert.NotEqual(extension, FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false);
        Assert.NotEqual(extension, FileInspector.Detect(stream)?.Extension);
    }

    private sealed class CountingMemoryStream : MemoryStream
    {
        internal CountingMemoryStream(byte[] bytes) : base(bytes, writable: false) { }
        internal long BytesRead { get; private set; }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int read = base.Read(buffer, offset, count);
            BytesRead += read;
            return read;
        }
    }
}
