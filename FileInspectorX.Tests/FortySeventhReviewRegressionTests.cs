using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

[Collection(nameof(DetectionSettingsCollection))]
public sealed class FortySeventhReviewRegressionTests
{
    [Fact]
    public void DebianTarBudgetCannotBypassTheRequiredControlMember()
    {
        WithReadBudget(1024, () =>
        {
            AssertNotDetectedAs(CreateDeb(CreateTar("first", "second", "third")), "deb");

            ContentTypeDetectionResult result = AssertParity(
                CreateDeb(CreateTar("control", "second", "third")), "deb");
            Assert.Equal("Medium", result.Confidence);
        });
    }

    [Fact]
    public void EveryRecognizedCrx3HeaderFieldMustBeValid()
    {
        byte[] original = TestHelpers.CreateMinimalCrx3();
        int headerLength = checked((int)ReadUInt32LittleEndian(original, 8));
        byte[] malformed = new byte[original.Length + 3];
        Array.Copy(original, 0, malformed, 0, 12 + headerLength);
        new byte[] { 0x12, 0x01, 0x00 }.CopyTo(malformed, 12 + headerLength);
        Array.Copy(original, 12 + headerLength, malformed, 15 + headerLength,
            original.Length - 12 - headerLength);
        TestHelpers.WriteUInt32LittleEndian(malformed, 8, checked((uint)headerLength + 3));

        AssertNotDetectedAs(malformed, "crx");
    }

    [Fact]
    public void EveryJpeg2000CodestreamBoxMustBeValid()
    {
        byte[] valid = TestHelpers.CreateMinimalJpeg2000();
        byte[] malformed = new byte[valid.Length + 10];
        valid.CopyTo(malformed, 0);
        TestHelpers.WriteUInt32BigEndian(malformed, valid.Length, 10);
        Encoding.ASCII.GetBytes("jp2c").CopyTo(malformed, valid.Length + 4);

        AssertNotDetectedAs(malformed, "jp2");
    }

    [Fact]
    public void LargeSeekableDexUsesTheKnownWholeFileLength()
    {
        WithReadBudget(256, () =>
        {
            byte[] valid = TestHelpers.CreateMinimalDex(length: 5000);
            AssertParity(valid, "dex");

            byte[] mismatched = (byte[])valid.Clone();
            TestHelpers.WriteUInt32LittleEndian(mismatched, 32, 4996);
            AssertNotDetectedAs(mismatched, "dex");
        });
    }

    [Fact]
    public void SampledQoiPrefixCannotClaimWholeFileValidation()
    {
        int originalHeaderBytes = Settings.HeaderReadBytes;
        try
        {
            Settings.HeaderReadBytes = 256;
            byte[] bytes = CreateSampleBoundaryQoi(trailingBytes: 20);
            ContentTypeDetectionResult result = AssertParity(bytes, "qoi");
            Assert.Equal("Medium", result.Confidence);
            Assert.Equal("qoi:header", result.Reason);
        }
        finally
        {
            Settings.HeaderReadBytes = originalHeaderBytes;
        }
    }

    private static byte[] CreateSampleBoundaryQoi(int trailingBytes)
    {
        const int pixelCount = 234;
        var bytes = new byte[14 + pixelCount + 8 + trailingBytes];
        Encoding.ASCII.GetBytes("qoif").CopyTo(bytes, 0);
        TestHelpers.WriteUInt32BigEndian(bytes, 4, pixelCount);
        TestHelpers.WriteUInt32BigEndian(bytes, 8, 1);
        bytes[12] = 4;
        bytes[14 + pixelCount + 7] = 1;
        return bytes;
    }

    private static byte[] CreateDeb(byte[] controlArchive)
    {
        using var stream = new MemoryStream();
        stream.Write(Encoding.ASCII.GetBytes("!<arch>\n"));
        WriteArMember(stream, "debian-binary", Encoding.ASCII.GetBytes("2.0\n"));
        WriteArMember(stream, "control.tar", controlArchive);
        WriteArMember(stream, "data.tar", CreateTar("payload"));
        return stream.ToArray();
    }

    private static byte[] CreateTar(params string[] memberNames)
    {
        var bytes = new byte[(memberNames.Length + 2) * 512];
        for (int member = 0; member < memberNames.Length; member++)
        {
            int offset = member * 512;
            Encoding.ASCII.GetBytes(memberNames[member]).CopyTo(bytes, offset);
            Encoding.ASCII.GetBytes("0000644\0").CopyTo(bytes, offset + 100);
            Encoding.ASCII.GetBytes("0000000\0").CopyTo(bytes, offset + 108);
            Encoding.ASCII.GetBytes("0000000\0").CopyTo(bytes, offset + 116);
            Encoding.ASCII.GetBytes("00000000000\0").CopyTo(bytes, offset + 124);
            Encoding.ASCII.GetBytes("00000000000\0").CopyTo(bytes, offset + 136);
            for (int index = 148; index < 156; index++) bytes[offset + index] = (byte)' ';
            bytes[offset + 156] = (byte)'0';
            Encoding.ASCII.GetBytes("ustar\0").CopyTo(bytes, offset + 257);
            Encoding.ASCII.GetBytes("00").CopyTo(bytes, offset + 263);
            int checksum = 0;
            for (int index = 0; index < 512; index++) checksum += bytes[offset + index];
            Encoding.ASCII.GetBytes(Convert.ToString(checksum, 8)!.PadLeft(6, '0') + "\0 ")
                .CopyTo(bytes, offset + 148);
        }
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

    private static uint ReadUInt32LittleEndian(byte[] bytes, int offset)
        => (uint)(bytes[offset] | bytes[offset + 1] << 8 | bytes[offset + 2] << 16 | bytes[offset + 3] << 24);

    private static void WithReadBudget(int budget, Action assertion)
    {
        int original = Settings.DetectionReadBudgetBytes;
        try { Settings.DetectionReadBudgetBytes = budget; assertion(); }
        finally { Settings.DetectionReadBudgetBytes = original; }
    }

    private static ContentTypeDetectionResult AssertParity(byte[] bytes, string extension)
    {
        ContentTypeDetectionResult? fromBytes = FileInspector.Detect(bytes);
        using var stream = new MemoryStream(bytes, writable: false) { Position = Math.Min(3, bytes.Length) };
        ContentTypeDetectionResult? fromStream = FileInspector.Detect(stream);
        Assert.Equal(extension, fromBytes?.Extension);
        Assert.Equal(extension, fromStream?.Extension);
        Assert.Equal(fromBytes?.Confidence, fromStream?.Confidence);
        Assert.Equal(Math.Min(3, bytes.Length), stream.Position);
        return fromStream!;
    }

    private static void AssertNotDetectedAs(byte[] bytes, string extension)
    {
        Assert.NotEqual(extension, FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false);
        Assert.NotEqual(extension, FileInspector.Detect(stream)?.Extension);
    }
}
