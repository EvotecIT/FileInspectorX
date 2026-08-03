using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

[Collection(nameof(DetectionSettingsCollection))]
public sealed class EighteenthReviewRegressionTests
{
    [Fact]
    public void DicomRequiresTheFileMetaInformationVersion()
    {
        var valid = TestHelpers.CreateMinimalDicom();
        AssertParity(valid, "dcm");

        var missing = (byte[])valid.Clone();
        missing[146] = 0x13;
        AssertNotDetectedAs("dcm", missing);

        var invalidValue = (byte[])valid.Clone();
        invalidValue[157] = 2;
        AssertNotDetectedAs("dcm", invalidValue);
    }

    [Theory]
    [InlineData(36u)]
    [InlineData(110u)]
    [InlineData(116u)]
    public void DdsAcceptsDefinedNumericD3dFormats(uint format)
        => AssertParity(NumericDds(format), "dds");

    [Fact]
    public void OpenExrRetainsOversizedSeekableHeaderIdentityAtMediumConfidence()
    {
        var bytes = OpenExrWithLargeCustomAttribute();
        Assert.Equal("Medium", FileInspector.Detect(bytes)?.Confidence);
        using var stream = new MemoryStream(bytes, writable: false) { Position = 5 };

        var result = FileInspector.Detect(stream);

        Assert.Equal("exr", result?.Extension);
        Assert.Equal("Medium", result?.Confidence);
        Assert.Contains("sampled-attribute-header", result?.Reason);
        Assert.Equal(5, stream.Position);
    }

    [Fact]
    public void SeekableMachOLoadCommandWalkHonorsTheReadBudget()
    {
        var bytes = MachOWithManyLoadCommands(1000);
        Assert.Equal("Medium", FileInspector.Detect(bytes)?.Confidence);
        int originalBudget = Settings.DetectionReadBudgetBytes;
        try
        {
            Settings.DetectionReadBudgetBytes = 256;
            using var stream = new MemoryStream(bytes, writable: false) { Position = 3 };

            var result = FileInspector.Detect(stream);

            Assert.Equal("macho", result?.Extension);
            Assert.Equal("Medium", result?.Confidence);
            Assert.Contains("validation-budget-exceeded", result?.Reason);
            Assert.Equal(3, stream.Position);
        }
        finally
        {
            Settings.DetectionReadBudgetBytes = originalBudget;
        }
    }

    [Theory]
    [InlineData(0xA641, 0x20B)]
    [InlineData(0xA64E, 0x20B)]
    [InlineData(0x6232, 0x10B)]
    public void PeAcceptsCurrentMachineIdentifiers(ushort machine, ushort magic)
    {
        var bytes = TestHelpers.CreateMinimalPe();
        TestHelpers.WriteUInt16LittleEndian(bytes, 0x84, machine);
        TestHelpers.WriteUInt16LittleEndian(bytes, 0x98, magic);
        AssertParity(bytes, "exe");
    }

    [Fact]
    public void MidiSkipsBoundedAlienChunksWithoutCountingThemAsTracks()
        => AssertParity(MidiWithAlienChunk(), "mid");

    [Fact]
    public void ArrowAcceptsVtablesAfterTheirObjects()
        => AssertParity(ArrowWithNegativeVtableDisplacements(), "arrow");

    private static void AssertParity(byte[] bytes, string extension)
    {
        Assert.Equal(extension, FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false) { Position = Math.Min(3, bytes.Length) };
        Assert.Equal(extension, FileInspector.Detect(stream)?.Extension);
        Assert.Equal(Math.Min(3, bytes.Length), stream.Position);
    }

    private static void AssertNotDetectedAs(string extension, byte[] bytes)
    {
        Assert.NotEqual(extension, FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false);
        Assert.NotEqual(extension, FileInspector.Detect(stream)?.Extension);
    }

    private static byte[] NumericDds(uint format)
    {
        int payloadLength = format switch
        {
            36 or 110 or 113 or 115 => 8,
            111 => 2,
            112 or 114 => 4,
            116 => 16,
            _ => throw new ArgumentOutOfRangeException(nameof(format))
        };
        var bytes = new byte[128 + payloadLength];
        Encoding.ASCII.GetBytes("DDS ").CopyTo(bytes, 0);
        TestHelpers.WriteUInt32LittleEndian(bytes, 4, 124);
        TestHelpers.WriteUInt32LittleEndian(bytes, 8, 0x1007);
        TestHelpers.WriteUInt32LittleEndian(bytes, 12, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 16, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 76, 32);
        TestHelpers.WriteUInt32LittleEndian(bytes, 80, 4);
        TestHelpers.WriteUInt32LittleEndian(bytes, 84, format);
        TestHelpers.WriteUInt32LittleEndian(bytes, 108, 0x1000);
        return bytes;
    }

    private static byte[] OpenExrWithLargeCustomAttribute()
    {
        var minimal = TestHelpers.CreateMinimalOpenExr();
        const int valueLength = 5000;
        using var stream = new MemoryStream();
        stream.Write(minimal, 0, 8);
        byte[] name = Encoding.ASCII.GetBytes("custom\0blob\0");
        stream.Write(name, 0, name.Length);
        var length = new byte[4];
        TestHelpers.WriteUInt32LittleEndian(length, 0, valueLength);
        stream.Write(length, 0, length.Length);
        stream.Write(new byte[valueLength], 0, valueLength);
        stream.Write(minimal, 8, minimal.Length - 8);
        byte[] bytes = stream.ToArray();
        TestHelpers.WriteUInt64LittleEndian(bytes, bytes.Length - 20, checked((ulong)(bytes.Length - 12)));
        return bytes;
    }

    private static byte[] MachOWithManyLoadCommands(int count)
    {
        var bytes = new byte[32 + count * 8];
        new byte[] { 0xCF, 0xFA, 0xED, 0xFE }.CopyTo(bytes, 0);
        TestHelpers.WriteUInt32LittleEndian(bytes, 4, 0x01000007);
        TestHelpers.WriteUInt32LittleEndian(bytes, 12, 2);
        TestHelpers.WriteUInt32LittleEndian(bytes, 16, checked((uint)count));
        TestHelpers.WriteUInt32LittleEndian(bytes, 20, checked((uint)(count * 8)));
        for (int index = 0; index < count; index++)
        {
            TestHelpers.WriteUInt32LittleEndian(bytes, 32 + index * 8, 1);
            TestHelpers.WriteUInt32LittleEndian(bytes, 36 + index * 8, 8);
        }
        return bytes;
    }

    private static byte[] MidiWithAlienChunk()
    {
        var bytes = new byte[37];
        Encoding.ASCII.GetBytes("MThd").CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 4, 6);
        WriteUInt16BigEndian(bytes, 10, 1);
        WriteUInt16BigEndian(bytes, 12, 96);
        Encoding.ASCII.GetBytes("JUNK").CopyTo(bytes, 14);
        WriteUInt32BigEndian(bytes, 18, 3);
        new byte[] { 1, 2, 3 }.CopyTo(bytes, 22);
        Encoding.ASCII.GetBytes("MTrk").CopyTo(bytes, 25);
        WriteUInt32BigEndian(bytes, 29, 4);
        new byte[] { 0, 0xFF, 0x2F, 0 }.CopyTo(bytes, 33);
        return bytes;
    }

    private static byte[] ArrowWithNegativeVtableDisplacements()
    {
        var footer = new byte[76];
        TestHelpers.WriteUInt32LittleEndian(footer, 0, 12);
        TestHelpers.WriteUInt32LittleEndian(footer, 12, unchecked((uint)-40));
        TestHelpers.WriteUInt16LittleEndian(footer, 16, 4);
        TestHelpers.WriteUInt32LittleEndian(footer, 20, 20);
        TestHelpers.WriteUInt32LittleEndian(footer, 40, unchecked((uint)-28));
        TestHelpers.WriteUInt32LittleEndian(footer, 44, 4);
        TestHelpers.WriteUInt16LittleEndian(footer, 52, 8);
        TestHelpers.WriteUInt16LittleEndian(footer, 54, 12);
        TestHelpers.WriteUInt16LittleEndian(footer, 56, 4);
        TestHelpers.WriteUInt16LittleEndian(footer, 58, 8);
        TestHelpers.WriteUInt16LittleEndian(footer, 68, 8);
        TestHelpers.WriteUInt16LittleEndian(footer, 70, 8);
        TestHelpers.WriteUInt16LittleEndian(footer, 74, 4);

        var bytes = new byte[8 + footer.Length + 10];
        Encoding.ASCII.GetBytes("ARROW1").CopyTo(bytes, 0);
        footer.CopyTo(bytes, 8);
        TestHelpers.WriteUInt32LittleEndian(bytes, bytes.Length - 10, (uint)footer.Length);
        Encoding.ASCII.GetBytes("ARROW1").CopyTo(bytes, bytes.Length - 6);
        return bytes;
    }

    private static void WriteUInt16BigEndian(byte[] bytes, int offset, ushort value)
    {
        bytes[offset] = (byte)(value >> 8); bytes[offset + 1] = (byte)value;
    }

    private static void WriteUInt32BigEndian(byte[] bytes, int offset, uint value)
    {
        for (int index = 0; index < 4; index++) bytes[offset + 3 - index] = (byte)(value >> (8 * index));
    }
}
