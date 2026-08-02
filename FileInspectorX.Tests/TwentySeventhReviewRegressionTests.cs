using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class TwentySeventhReviewRegressionTests
{
    [Fact]
    public void OpenExrRejectsDuplicateAttributesAndMultipartNames()
    {
        AssertNotDetectedAs(OpenExrWithDuplicateAttributes(), "exr");
        AssertNotDetectedAs(OpenExrWithDuplicateChannels(), "exr");

        byte[] multipart = TestHelpers.CreateMinimalMultipartOpenExr();
        int secondName = Find(multipart, Encoding.ASCII.GetBytes("part1"));
        Assert.True(secondName >= 0);
        Encoding.ASCII.GetBytes("part0").CopyTo(multipart, secondName);
        AssertNotDetectedAs(multipart, "exr");
    }

    [Theory]
    [InlineData((ushort)1)]
    [InlineData((ushort)2)]
    public void RlePhotoshopCompositeMustEndAtEndOfFile(ushort version)
    {
        byte[] valid = RlePhotoshop(version);
        AssertParity(valid, version == 1 ? "psd" : "psb");

        Array.Resize(ref valid, valid.Length + 1);
        AssertNotDetectedAs(valid, version == 1 ? "psd" : "psb");
    }

    [Fact]
    public void DicomUidAllowsOnlyNullPadding()
    {
        byte[] bytes = TestHelpers.CreateMinimalDicom();
        byte[] uid = Encoding.ASCII.GetBytes("1.2.3.4.5.6.7.8.9");
        int offset = Find(bytes, uid);
        Assert.True(offset >= 0);
        Assert.Equal(0, bytes[offset + uid.Length]);
        bytes[offset + uid.Length] = (byte)' ';

        AssertNotDetectedAs(bytes, "dcm");

        byte[] leadingZero = TestHelpers.CreateMinimalDicom();
        int component = Find(leadingZero, Encoding.ASCII.GetBytes("1.2.840"));
        Assert.True(component >= 0);
        leadingZero[component + 4] = (byte)'0';
        AssertNotDetectedAs(leadingZero, "dcm");
    }

    [Fact]
    public void ArrowV1MayOmitItsDefaultMetadataVersionField()
    {
        byte[] bytes = TestHelpers.CreateMinimalArrow();
        bytes[16] = 0;
        bytes[17] = 0;

        AssertParity(bytes, "arrow");
    }

    [Fact]
    public void ShellLinkRejectsReservedFlags()
    {
        byte[] bytes = ShellLink();
        TestHelpers.WriteUInt32LittleEndian(bytes, 20, 0x80000000);

        AssertNotDetectedAs(bytes, "lnk");
    }

    [Fact]
    public void Crx3RejectsProtobufFieldZeroAtEveryParsedMessageLevel()
    {
        AssertNotDetectedAs(AppendCrxHeaderFieldZero(nestedProof: false), "crx");
        AssertNotDetectedAs(AppendCrxHeaderFieldZero(nestedProof: true), "crx");
    }

    [Fact]
    public void ParquetRequiresTheTopLevelStopMarker()
    {
        byte[] bytes = TestHelpers.CreateMinimalParquet();
        int stop = bytes.Length - 9;
        var unterminated = new byte[bytes.Length - 1];
        Array.Copy(bytes, 0, unterminated, 0, stop);
        Array.Copy(bytes, stop + 1, unterminated, stop, bytes.Length - stop - 1);
        uint metadataLength = ReadUInt32LittleEndian(unterminated, unterminated.Length - 8);
        TestHelpers.WriteUInt32LittleEndian(unterminated, unterminated.Length - 8, metadataLength - 1);

        AssertNotDetectedAs(unterminated, "parquet");
    }

    [Fact]
    public void FatMachOSlicesMustNotOverlap()
    {
        AssertParity(FatMachO(overlap: false), "macho");
        AssertNotDetectedAs(FatMachO(overlap: true), "macho");
    }

    [Theory]
    [InlineData(5u)]
    [InlineData(8u)]
    [InlineData(0x80000000u)]
    public void DdsDx10RejectsUndefinedOrReservedAlphaModes(uint alphaMode)
    {
        byte[] bytes = DdsDx10();
        TestHelpers.WriteUInt32LittleEndian(bytes, 144, alphaMode);

        AssertNotDetectedAs(bytes, "dds");
    }

    private static byte[] OpenExrWithDuplicateAttributes()
    {
        byte[] original = TestHelpers.CreateMinimalOpenExr();
        int terminator = FindOpenExrHeaderTerminator(original);
        byte[] attribute = OpenExrAttribute("custom", "string", new byte[] { (byte)'x' });
        var bytes = new byte[original.Length + attribute.Length * 2];
        Array.Copy(original, 0, bytes, 0, terminator);
        Array.Copy(attribute, 0, bytes, terminator, attribute.Length);
        Array.Copy(attribute, 0, bytes, terminator + attribute.Length, attribute.Length);
        Array.Copy(original, terminator, bytes, terminator + attribute.Length * 2, original.Length - terminator);
        int tableOffset = terminator + attribute.Length * 2 + 1;
        TestHelpers.WriteUInt64LittleEndian(bytes, tableOffset, checked((ulong)tableOffset + 8));
        return bytes;
    }

    private static byte[] OpenExrWithDuplicateChannels()
    {
        byte[] original = TestHelpers.CreateMinimalOpenExr();
        int name = Find(original, Encoding.ASCII.GetBytes("channels\0chlist\0"));
        Assert.True(name >= 0);
        int lengthOffset = name + "channels".Length + 1 + "chlist".Length + 1;
        int valueOffset = lengthOffset + 4;
        uint originalLength = ReadUInt32LittleEndian(original, lengthOffset);
        Assert.Equal(19u, originalLength);
        const int channelEntryLength = 18;
        var bytes = new byte[original.Length + channelEntryLength];
        int insertion = valueOffset + channelEntryLength;
        Array.Copy(original, 0, bytes, 0, insertion);
        Array.Copy(original, valueOffset, bytes, insertion, channelEntryLength);
        Array.Copy(original, insertion, bytes, insertion + channelEntryLength, original.Length - insertion);
        TestHelpers.WriteUInt32LittleEndian(bytes, lengthOffset, originalLength + channelEntryLength);
        int terminator = FindOpenExrHeaderTerminator(bytes);
        int tableOffset = terminator + 1;
        TestHelpers.WriteUInt64LittleEndian(bytes, tableOffset, checked((ulong)tableOffset + 8));
        return bytes;
    }

    private static int FindOpenExrHeaderTerminator(byte[] bytes)
    {
        int cursor = 8;
        while (cursor < bytes.Length && bytes[cursor] != 0)
        {
            while (cursor < bytes.Length && bytes[cursor++] != 0) { }
            while (cursor < bytes.Length && bytes[cursor++] != 0) { }
            uint length = ReadUInt32LittleEndian(bytes, cursor);
            cursor += 4 + checked((int)length);
        }
        Assert.InRange(cursor, 8, bytes.Length - 1);
        return cursor;
    }

    private static byte[] OpenExrAttribute(string name, string type, byte[] value)
    {
        using var stream = new MemoryStream();
        byte[] nameBytes = Encoding.ASCII.GetBytes(name);
        byte[] typeBytes = Encoding.ASCII.GetBytes(type);
        stream.Write(nameBytes, 0, nameBytes.Length);
        stream.WriteByte(0);
        stream.Write(typeBytes, 0, typeBytes.Length);
        stream.WriteByte(0);
        var length = new byte[4];
        TestHelpers.WriteUInt32LittleEndian(length, 0, checked((uint)value.Length));
        stream.Write(length, 0, length.Length);
        stream.Write(value, 0, value.Length);
        return stream.ToArray();
    }

    private static byte[] RlePhotoshop(ushort version)
    {
        int rowLengthSize = version == 1 ? 2 : 4;
        int dataOffset = 26 + 4 + 4 + (version == 1 ? 4 : 8) + 2;
        var bytes = new byte[dataOffset + 3 * rowLengthSize + 6];
        byte[] header = TestHelpers.CreateMinimalPhotoshop(version);
        Array.Copy(header, 0, bytes, 0, dataOffset);
        TestHelpers.WriteUInt16BigEndian(bytes, dataOffset - 2, 1);
        for (int row = 0; row < 3; row++)
        {
            int offset = dataOffset + row * rowLengthSize;
            if (rowLengthSize == 2) TestHelpers.WriteUInt16BigEndian(bytes, offset, 2);
            else TestHelpers.WriteUInt32BigEndian(bytes, offset, 2);
        }
        int compressedOffset = dataOffset + 3 * rowLengthSize;
        for (int row = 0; row < 3; row++)
        {
            bytes[compressedOffset + row * 2] = 0;
            bytes[compressedOffset + row * 2 + 1] = 0;
        }
        return bytes;
    }

    private static byte[] ShellLink()
    {
        var bytes = new byte[80];
        bytes[0] = 0x4C;
        new byte[] { 0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46 }.CopyTo(bytes, 4);
        TestHelpers.WriteUInt32LittleEndian(bytes, 60, 1);
        return bytes;
    }

    private static byte[] AppendCrxHeaderFieldZero(bool nestedProof)
    {
        byte[] original = TestHelpers.CreateMinimalCrx3();
        int headerLength = checked((int)ReadUInt32LittleEndian(original, 8));
        int insertion = nestedProof ? 20 : 12 + headerLength;
        var bytes = new byte[original.Length + 3];
        Array.Copy(original, 0, bytes, 0, insertion);
        new byte[] { 0x02, 0x01, 0x00 }.CopyTo(bytes, insertion);
        Array.Copy(original, insertion, bytes, insertion + 3, original.Length - insertion);
        TestHelpers.WriteUInt32LittleEndian(bytes, 8, checked((uint)headerLength + 3));
        if (nestedProof) bytes[13] += 3;
        return bytes;
    }

    private static byte[] FatMachO(bool overlap)
    {
        var bytes = new byte[144];
        TestHelpers.WriteUInt32BigEndian(bytes, 0, 0xCAFEBABF);
        TestHelpers.WriteUInt32BigEndian(bytes, 4, 2);
        WriteFatEntry(bytes, 8, 80);
        WriteFatEntry(bytes, 40, overlap ? 80UL : 112UL);
        WriteThinSlice(bytes, 80);
        if (!overlap) WriteThinSlice(bytes, 112);
        return bytes;
    }

    private static void WriteFatEntry(byte[] bytes, int offset, ulong sliceOffset)
    {
        TestHelpers.WriteUInt32BigEndian(bytes, offset, 0x01000007);
        TestHelpers.WriteUInt32BigEndian(bytes, offset + 4, 3);
        TestHelpers.WriteUInt64BigEndian(bytes, offset + 8, sliceOffset);
        TestHelpers.WriteUInt64BigEndian(bytes, offset + 16, 32);
        TestHelpers.WriteUInt32BigEndian(bytes, offset + 24, 4);
    }

    private static void WriteThinSlice(byte[] bytes, int offset)
    {
        new byte[] { 0xCF, 0xFA, 0xED, 0xFE }.CopyTo(bytes, offset);
        TestHelpers.WriteUInt32LittleEndian(bytes, offset + 4, 0x01000007);
        TestHelpers.WriteUInt32LittleEndian(bytes, offset + 8, 3);
        TestHelpers.WriteUInt32LittleEndian(bytes, offset + 12, 1);
    }

    private static byte[] DdsDx10()
    {
        var bytes = new byte[148];
        Encoding.ASCII.GetBytes("DDS ").CopyTo(bytes, 0);
        TestHelpers.WriteUInt32LittleEndian(bytes, 4, 124);
        TestHelpers.WriteUInt32LittleEndian(bytes, 8, 0x1007);
        TestHelpers.WriteUInt32LittleEndian(bytes, 12, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 16, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 76, 32);
        TestHelpers.WriteUInt32LittleEndian(bytes, 80, 4);
        Encoding.ASCII.GetBytes("DX10").CopyTo(bytes, 84);
        TestHelpers.WriteUInt32LittleEndian(bytes, 108, 0x1000);
        TestHelpers.WriteUInt32LittleEndian(bytes, 128, 28);
        TestHelpers.WriteUInt32LittleEndian(bytes, 132, 3);
        TestHelpers.WriteUInt32LittleEndian(bytes, 140, 1);
        return bytes;
    }

    private static int Find(byte[] source, byte[] value)
    {
        for (int offset = 0; offset <= source.Length - value.Length; offset++)
        {
            bool equal = true;
            for (int index = 0; index < value.Length; index++)
                if (source[offset + index] != value[index]) { equal = false; break; }
            if (equal) return offset;
        }
        return -1;
    }

    private static uint ReadUInt32LittleEndian(byte[] bytes, int offset)
        => (uint)(bytes[offset] | bytes[offset + 1] << 8 | bytes[offset + 2] << 16 | bytes[offset + 3] << 24);

    private static void AssertParity(byte[] bytes, string extension)
    {
        Assert.Equal(extension, FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false) { Position = Math.Min(7, bytes.Length) };
        Assert.Equal(extension, FileInspector.Detect(stream)?.Extension);
        Assert.Equal(Math.Min(7, bytes.Length), stream.Position);
    }

    private static void AssertNotDetectedAs(byte[] bytes, string extension)
    {
        Assert.NotEqual(extension, FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false);
        Assert.NotEqual(extension, FileInspector.Detect(stream)?.Extension);
    }
}
