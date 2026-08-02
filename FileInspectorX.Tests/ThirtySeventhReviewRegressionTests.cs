using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class ThirtySeventhReviewRegressionTests
{
    [Fact]
    public void MidiFixedLengthMetaEventsAreValidatedAcrossCompleteOverloads()
    {
        AssertParity(Midi(new byte[] { 0x00, 0xFF, 0x51, 0x03, 0x07, 0xA1, 0x20, 0x00, 0xFF, 0x2F, 0x00 }), "mid", "High");
        AssertNotDetectedAs(Midi(new byte[] { 0x00, 0xFF, 0x51, 0x01, 0x00, 0x00, 0xFF, 0x2F, 0x00 }), "mid");
    }

    [Fact]
    public void NetCdfNamesRequireStrictUtf8AcrossSpanAndStreamReaders()
    {
        AssertParity(NetCdfWithDimensionName(new byte[] { 0xC3, 0xA9 }), "nc", "High");
        AssertNotDetectedAs(NetCdfWithDimensionName(new byte[] { 0xFF }), "nc");
    }

    [Fact]
    public void LegacyHdf5WithoutValidatedRootObjectHeaderStaysAtMediumConfidence()
    {
        var result = AssertParity(LegacyHdf5(), "h5", "Medium");
        Assert.Contains("legacy-root-not-validated", result.Reason);
    }

    [Fact]
    public void ArrowSchemaRequiresItsFieldsVector()
    {
        AssertParity(TestHelpers.CreateMinimalArrow(), "arrow", "Medium");
        byte[] missingFields = TestHelpers.CreateMinimalArrow();
        missingFields[8 + 46] = 0;
        missingFields[8 + 47] = 0;
        AssertNotDetectedAs(missingFields, "arrow");
    }

    [Fact]
    public void TiffRequiresAUsableImageDirectoryForHighConfidence()
    {
        var partial = AssertParity(EmptyTiff(), "tif", "Medium");
        Assert.Contains("image-data-not-validated", partial.Reason);
        AssertParity(UsableTiff(), "tif", "High");
    }

    private static ContentTypeDetectionResult AssertParity(byte[] bytes, string extension, string confidence)
    {
        var fromBytes = FileInspector.Detect(bytes);
        using var stream = new MemoryStream(bytes, writable: false) { Position = Math.Min(3, bytes.Length) };
        long position = stream.Position;
        var fromStream = FileInspector.Detect(stream);
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".bin");
        try
        {
            File.WriteAllBytes(path, bytes);
            var fromPath = FileInspector.Detect(path);
            Assert.Equal(extension, fromBytes?.Extension);
            Assert.Equal(extension, fromStream?.Extension);
            Assert.Equal(extension, fromPath?.Extension);
            Assert.Equal(confidence, fromBytes?.Confidence);
            Assert.Equal(confidence, fromStream?.Confidence);
            Assert.Equal(confidence, fromPath?.Confidence);
            Assert.Equal(position, stream.Position);
            return fromBytes!;
        }
        finally
        {
            TestHelpers.SafeDelete(path);
        }
    }

    private static void AssertNotDetectedAs(byte[] bytes, string extension)
    {
        Assert.NotEqual(extension, FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false) { Position = Math.Min(2, bytes.Length) };
        long position = stream.Position;
        Assert.NotEqual(extension, FileInspector.Detect(stream)?.Extension);
        Assert.Equal(position, stream.Position);
    }

    private static byte[] Midi(byte[] track)
    {
        var bytes = new byte[22 + track.Length];
        Encoding.ASCII.GetBytes("MThd").CopyTo(bytes, 0);
        TestHelpers.WriteUInt32BigEndian(bytes, 4, 6);
        TestHelpers.WriteUInt16BigEndian(bytes, 8, 0);
        TestHelpers.WriteUInt16BigEndian(bytes, 10, 1);
        TestHelpers.WriteUInt16BigEndian(bytes, 12, 96);
        Encoding.ASCII.GetBytes("MTrk").CopyTo(bytes, 14);
        TestHelpers.WriteUInt32BigEndian(bytes, 18, (uint)track.Length);
        track.CopyTo(bytes, 22);
        return bytes;
    }

    private static byte[] NetCdfWithDimensionName(byte[] name)
    {
        int paddedName = (name.Length + 3) & ~3;
        var bytes = new byte[40 + paddedName];
        Encoding.ASCII.GetBytes("CDF").CopyTo(bytes, 0);
        bytes[3] = 1;
        TestHelpers.WriteUInt32BigEndian(bytes, 8, 10);
        TestHelpers.WriteUInt32BigEndian(bytes, 12, 1);
        TestHelpers.WriteUInt32BigEndian(bytes, 16, (uint)name.Length);
        name.CopyTo(bytes, 20);
        TestHelpers.WriteUInt32BigEndian(bytes, 20 + paddedName, 1);
        return bytes;
    }

    private static byte[] LegacyHdf5()
    {
        const int length = 256;
        var bytes = new byte[length];
        new byte[] { 0x89, (byte)'H', (byte)'D', (byte)'F', 0x0D, 0x0A, 0x1A, 0x0A }.CopyTo(bytes, 0);
        bytes[13] = 8;
        bytes[14] = 8;
        TestHelpers.WriteUInt16LittleEndian(bytes, 16, 4);
        TestHelpers.WriteUInt16LittleEndian(bytes, 18, 16);
        WriteUInt64LittleEndian(bytes, 24, 0);
        FillUndefined(bytes, 32);
        WriteUInt64LittleEndian(bytes, 40, length);
        FillUndefined(bytes, 48);
        WriteUInt64LittleEndian(bytes, 56, 80);
        WriteUInt64LittleEndian(bytes, 64, 100);
        return bytes;
    }

    private static byte[] EmptyTiff()
        => new byte[] { (byte)'I', (byte)'I', 42, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    private static byte[] UsableTiff()
    {
        var bytes = new byte[63];
        bytes[0] = bytes[1] = (byte)'I';
        TestHelpers.WriteUInt16LittleEndian(bytes, 2, 42);
        TestHelpers.WriteUInt32LittleEndian(bytes, 4, 8);
        TestHelpers.WriteUInt16LittleEndian(bytes, 8, 4);
        WriteTiffEntry(bytes, 10, 256, 1);
        WriteTiffEntry(bytes, 22, 257, 1);
        WriteTiffEntry(bytes, 34, 273, 62);
        WriteTiffEntry(bytes, 46, 279, 1);
        bytes[62] = 0;
        return bytes;
    }

    private static void WriteTiffEntry(byte[] bytes, int offset, ushort tag, uint value)
    {
        TestHelpers.WriteUInt16LittleEndian(bytes, offset, tag);
        TestHelpers.WriteUInt16LittleEndian(bytes, offset + 2, 4);
        TestHelpers.WriteUInt32LittleEndian(bytes, offset + 4, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, offset + 8, value);
    }

    private static void WriteUInt64LittleEndian(byte[] bytes, int offset, ulong value)
    {
        for (int index = 0; index < 8; index++) bytes[offset + index] = (byte)(value >> (index * 8));
    }

    private static void FillUndefined(byte[] bytes, int offset)
    {
        for (int index = 0; index < 8; index++) bytes[offset + index] = 0xFF;
    }
}
