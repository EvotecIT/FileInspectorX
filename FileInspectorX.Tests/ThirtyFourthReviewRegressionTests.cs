using System.IO.Compression;
using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class ThirtyFourthReviewRegressionTests
{
    [Fact]
    public void ZipRequiresACentralDirectoryForHighConfidence()
    {
        AssertParity(CompleteZip(), "zip", "High");
        AssertParity(LocalHeaderOnlyZip(), "zip", "Medium");
    }

    [Fact]
    public void JavaConstantPoolStringsUseModifiedUtf8()
    {
        AssertParity(JavaClassWithUnusedUtf8(new byte[] { 0xC0, 0x80 }), "class", "Medium");
        AssertNotDetectedAs(JavaClassWithUnusedUtf8(new byte[] { 0xFF }), "class");
        AssertNotDetectedAs(JavaClassWithUnusedUtf8(new byte[] { 0x00 }), "class");
    }

    [Fact]
    public void TtcTablePayloadsCannotOverlapCollectionDirectories()
    {
        AssertParity(FontCollection(tableOffset: 44), "ttc", "Medium");
        AssertNotDetectedAs(FontCollection(tableOffset: 0), "ttc");
        AssertNotDetectedAs(FontCollection(tableOffset: 16), "ttc");
    }

    [Fact]
    public void WebAssemblyWalksOrderedCanonicalSections()
    {
        AssertParity(Wasm(1, 1, 0), "wasm", "Medium");
        AssertNotDetectedAs(Wasm(0xFF), "wasm");
        AssertNotDetectedAs(Wasm(1, 0x80, 0), "wasm");
        AssertNotDetectedAs(Wasm(2, 0, 1, 0), "wasm");
    }

    [Fact]
    public void PcapNgConsumesEveryFramedBlock()
    {
        byte[] valid = PcapNgWithTrailingBlock();
        AssertParity(valid, "pcapng", "Medium");

        var garbage = new byte[valid.Length + 1];
        valid.CopyTo(garbage, 0);
        AssertNotDetectedAs(garbage, "pcapng");

        var mismatchedTrailer = (byte[])valid.Clone();
        TestHelpers.WriteUInt32LittleEndian(mismatchedTrailer, mismatchedTrailer.Length - 4, 16);
        AssertNotDetectedAs(mismatchedTrailer, "pcapng");

        var missingSectionHeader = (byte[])valid.Clone();
        missingSectionHeader[0] = 0;
        AssertNotDetectedAs(missingSectionHeader, "pcapng");
    }

    private static byte[] CompleteZip()
    {
        using var stream = new MemoryStream();
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
            archive.CreateEntry("a");
        return stream.ToArray();
    }

    private static byte[] LocalHeaderOnlyZip()
    {
        var bytes = new byte[31];
        TestHelpers.WriteUInt32LittleEndian(bytes, 0, 0x04034B50);
        TestHelpers.WriteUInt16LittleEndian(bytes, 4, 20);
        TestHelpers.WriteUInt16LittleEndian(bytes, 26, 1);
        bytes[30] = (byte)'a';
        return bytes;
    }

    private static byte[] JavaClassWithUnusedUtf8(byte[] unused)
    {
        using var stream = new MemoryStream();
        WriteUInt32BigEndian(stream, 0xCAFEBABE);
        WriteUInt16BigEndian(stream, 0);
        WriteUInt16BigEndian(stream, 52);
        WriteUInt16BigEndian(stream, 6);
        WriteJavaUtf8(stream, Encoding.ASCII.GetBytes("Test"));
        stream.WriteByte(7);
        WriteUInt16BigEndian(stream, 1);
        WriteJavaUtf8(stream, Encoding.ASCII.GetBytes("java/lang/Object"));
        stream.WriteByte(7);
        WriteUInt16BigEndian(stream, 3);
        WriteJavaUtf8(stream, unused);
        WriteUInt16BigEndian(stream, 0x21);
        WriteUInt16BigEndian(stream, 2);
        WriteUInt16BigEndian(stream, 4);
        WriteUInt16BigEndian(stream, 0);
        WriteUInt16BigEndian(stream, 0);
        WriteUInt16BigEndian(stream, 0);
        WriteUInt16BigEndian(stream, 0);
        return stream.ToArray();
    }

    private static void WriteJavaUtf8(Stream stream, byte[] value)
    {
        stream.WriteByte(1);
        WriteUInt16BigEndian(stream, checked((ushort)value.Length));
        stream.Write(value, 0, value.Length);
    }

    private static byte[] FontCollection(uint tableOffset)
    {
        var bytes = new byte[48];
        Encoding.ASCII.GetBytes("ttcf").CopyTo(bytes, 0);
        TestHelpers.WriteUInt32BigEndian(bytes, 4, 0x00010000);
        TestHelpers.WriteUInt32BigEndian(bytes, 8, 1);
        TestHelpers.WriteUInt32BigEndian(bytes, 12, 16);
        TestHelpers.WriteUInt32BigEndian(bytes, 16, 0x00010000);
        TestHelpers.WriteUInt16BigEndian(bytes, 20, 1);
        TestHelpers.WriteUInt16BigEndian(bytes, 22, 16);
        Encoding.ASCII.GetBytes("head").CopyTo(bytes, 28);
        TestHelpers.WriteUInt32BigEndian(bytes, 36, tableOffset);
        TestHelpers.WriteUInt32BigEndian(bytes, 40, 4);
        return bytes;
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

    private static byte[] PcapNgWithTrailingBlock()
    {
        var bytes = new byte[40];
        bytes[0] = 0x0A;
        bytes[1] = 0x0D;
        bytes[2] = 0x0D;
        bytes[3] = 0x0A;
        TestHelpers.WriteUInt32LittleEndian(bytes, 4, 28);
        bytes[8] = 0x4D;
        bytes[9] = 0x3C;
        bytes[10] = 0x2B;
        bytes[11] = 0x1A;
        TestHelpers.WriteUInt16LittleEndian(bytes, 12, 1);
        for (int offset = 16; offset < 24; offset++) bytes[offset] = 0xFF;
        TestHelpers.WriteUInt32LittleEndian(bytes, 24, 28);
        TestHelpers.WriteUInt32LittleEndian(bytes, 28, 0x00000BAD);
        TestHelpers.WriteUInt32LittleEndian(bytes, 32, 12);
        TestHelpers.WriteUInt32LittleEndian(bytes, 36, 12);
        return bytes;
    }

    private static void WriteUInt16BigEndian(Stream stream, ushort value)
    {
        stream.WriteByte((byte)(value >> 8));
        stream.WriteByte((byte)value);
    }

    private static void WriteUInt32BigEndian(Stream stream, uint value)
    {
        stream.WriteByte((byte)(value >> 24));
        stream.WriteByte((byte)(value >> 16));
        stream.WriteByte((byte)(value >> 8));
        stream.WriteByte((byte)value);
    }

    private static void AssertParity(byte[] bytes, string extension, string confidence)
    {
        var fromBytes = FileInspector.Detect(bytes);
        using var stream = new MemoryStream(bytes, writable: false) { Position = Math.Min(3, bytes.Length) };
        var fromStream = FileInspector.Detect(stream);
        Assert.Equal(extension, fromBytes?.Extension);
        Assert.Equal(extension, fromStream?.Extension);
        Assert.Equal(confidence, fromBytes?.Confidence);
        Assert.Equal(confidence, fromStream?.Confidence);
        Assert.Equal(Math.Min(3, bytes.Length), stream.Position);
    }

    private static void AssertNotDetectedAs(byte[] bytes, string extension)
    {
        Assert.NotEqual(extension, FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false);
        Assert.NotEqual(extension, FileInspector.Detect(stream)?.Extension);
    }
}
