using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class EleventhReviewRegressionTests
{
    [Fact]
    public void LargeNonSeekableCrxRetainsIdentityAtReducedConfidence()
    {
        var bytes = Crx3(5000);
        Assert.Equal("High", FileInspector.Detect(bytes)?.Confidence);

        using var stream = new NonSeekableReadStream(bytes);
        var result = FileInspector.Detect(stream);

        Assert.Equal("crx", result?.Extension);
        Assert.Equal("Medium", result?.Confidence);
        Assert.Contains("sampled-signed-header", result?.Reason);
    }

    [Fact]
    public void UnknownLengthGlbSampleIsNeverHighConfidence()
    {
        var bytes = Glb(5000);
        Assert.Equal("Medium", FileInspector.Detect(bytes)?.Confidence);
        Assert.Contains("asset-metadata-not-validated", FileInspector.Detect(bytes)?.Reason);

        using var stream = new NonSeekableReadStream(bytes);
        var result = FileInspector.Detect(stream);

        Assert.Equal("glb", result?.Extension);
        Assert.Equal("Medium", result?.Confidence);
        Assert.Contains("sampled-length-unknown", result?.Reason);
    }

    [Theory]
    [InlineData(7)]
    [InlineData(8)]
    [InlineData(9)]
    [InlineData(10)]
    [InlineData(11)]
    [InlineData(12)]
    [InlineData(15)]
    [InlineData(16)]
    [InlineData(17)]
    [InlineData(18)]
    [InlineData(19)]
    [InlineData(20)]
    public void JavaConstantPoolReferencesAreValidated(byte invalidTag)
    {
        var bytes = JavaClassWithInvalidExtraConstant(invalidTag);

        Assert.NotEqual("class", FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false);
        Assert.NotEqual("class", FileInspector.Detect(stream)?.Extension);
    }

    [Fact]
    public void Qcow2MetadataRangesMustFitTheCompleteFile()
    {
        var valid = Qcow2();
        Assert.Equal("qcow2", FileInspector.Detect(valid)?.Extension);
        using (var stream = new MemoryStream(valid, writable: false))
            Assert.Equal("qcow2", FileInspector.Detect(stream)?.Extension);

        Assert.NotEqual("qcow2", FileInspector.Detect(valid.AsSpan(0, 72).ToArray())?.Extension);

        var badL1 = (byte[])valid.Clone();
        WriteUInt64BigEndian(badL1, 40, (ulong)valid.Length);
        Assert.NotEqual("qcow2", FileInspector.Detect(badL1)?.Extension);

        var badRefcount = (byte[])valid.Clone();
        WriteUInt64BigEndian(badRefcount, 48, (ulong)valid.Length);
        Assert.NotEqual("qcow2", FileInspector.Detect(badRefcount)?.Extension);

        var badBacking = (byte[])valid.Clone();
        WriteUInt64BigEndian(badBacking, 8, (ulong)valid.Length - 16);
        WriteUInt32BigEndian(badBacking, 16, 32);
        Assert.NotEqual("qcow2", FileInspector.Detect(badBacking)?.Extension);
    }

    [Fact]
    public void Woff1ValidatesEveryTableDirectoryEntry()
    {
        var valid = Woff1WithTwoTables();
        Assert.Equal("woff", FileInspector.Detect(valid)?.Extension);
        using (var stream = new MemoryStream(valid, writable: false))
            Assert.Equal("woff", FileInspector.Detect(stream)?.Extension);

        var invalid = (byte[])valid.Clone();
        WriteUInt32BigEndian(invalid, 68, uint.MaxValue);
        Assert.NotEqual("woff", FileInspector.Detect(invalid)?.Extension);
        using var invalidStream = new MemoryStream(invalid, writable: false);
        Assert.NotEqual("woff", FileInspector.Detect(invalidStream)?.Extension);
    }

    [Fact]
    public void PeUnknownMachineValueIsRejected()
    {
        var bytes = Pe(machine: 0);

        Assert.NotEqual("exe", FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false);
        Assert.NotEqual("exe", FileInspector.Detect(stream)?.Extension);
    }

    [Fact]
    public void DicomMetaLengthUsesTheKnownOrSampledBoundary()
    {
        var bytes = TestHelpers.CreateMinimalDicom(metaLength: 5000, totalLength: 6000);
        Assert.Equal("High", FileInspector.Detect(bytes)?.Confidence);

        using (var stream = new NonSeekableReadStream(bytes)) {
            var sampled = FileInspector.Detect(stream);
            Assert.Equal("dcm", sampled?.Extension);
            Assert.Equal("Medium", sampled?.Confidence);
            Assert.Contains("sampled-meta-header", sampled?.Reason);
        }

        var overlong = TestHelpers.CreateMinimalDicom();
        WriteUInt32LittleEndian(overlong, 140, uint.MaxValue);
        Assert.NotEqual("dcm", FileInspector.Detect(overlong)?.Extension);
    }

    [Theory]
    [InlineData(0x00000001u)]
    [InlineData(0x00000002u)]
    [InlineData(0x00000004u)]
    [InlineData(0x00000008u)]
    [InlineData(0x00000010u)]
    [InlineData(0x00000020u)]
    [InlineData(0x00000040u)]
    public void ShellLinkRejectsMissingFlagSelectedStructures(uint flag)
    {
        var bytes = ShellLink(76, flag);
        Assert.NotEqual("lnk", FileInspector.Detect(bytes)?.Extension);
    }

    [Fact]
    public void ShellLinkValidatesCompleteAndSampledFlagSelectedStructures()
    {
        var complete = ShellLinkWithAllStructures();
        Assert.Equal("High", FileInspector.Detect(complete)?.Confidence);

        var large = ShellLink(6100, 0x00000084);
        WriteUInt16LittleEndian(large, 76, 3000);
        WriteUInt32LittleEndian(large, 6078, 18);
        WriteUInt32LittleEndian(large, 6082, 0xA0000009);
        Assert.Equal("High", FileInspector.Detect(large)?.Confidence);
        using var stream = new NonSeekableReadStream(large);
        var sampled = FileInspector.Detect(stream);
        Assert.Equal("lnk", sampled?.Extension);
        Assert.Equal("Medium", sampled?.Confidence);
    }

    [Fact]
    public void MidiPreservesRunningStatusAcrossMetaAndClearsItAfterSysExEvents()
    {
        byte[] channel = { 0, 0x90, 60, 64 };
        byte[] bareChannel = { 0, 60, 64 };
        byte[] meta = { 0, 0xFF, 0x01, 0 };
        byte[] sysEx = { 0, 0xF0, 0 };
        byte[] explicitChannel = { 0, 0x90, 60, 64 };
        byte[] end = { 0, 0xFF, 0x2F, 0 };

        AssertMidiAccepted(Midi(channel, meta, bareChannel, end));
        AssertMidiRejected(Midi(channel, sysEx, bareChannel, end));
        AssertMidiAccepted(Midi(channel, meta, explicitChannel, end));

        var largeInvalid = MidiWithLargeInvalidTrack();
        using var nonSeekable = new NonSeekableReadStream(largeInvalid);
        Assert.NotEqual("mid", FileInspector.Detect(nonSeekable)?.Extension);
    }

    private static void AssertMidiRejected(byte[] bytes)
    {
        Assert.NotEqual("mid", FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false);
        Assert.NotEqual("mid", FileInspector.Detect(stream)?.Extension);
    }

    private static void AssertMidiAccepted(byte[] bytes)
    {
        Assert.Equal("mid", FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false);
        Assert.Equal("mid", FileInspector.Detect(stream)?.Extension);
    }

    private static byte[] Crx3(int signedHeaderLength) => TestHelpers.CreateMinimalCrx3(signedHeaderLength);

    private static byte[] Glb(int length)
    {
        var bytes = new byte[length];
        Encoding.ASCII.GetBytes("glTF").CopyTo(bytes, 0);
        WriteUInt32LittleEndian(bytes, 4, 2);
        WriteUInt32LittleEndian(bytes, 8, (uint)length);
        WriteUInt32LittleEndian(bytes, 12, 4);
        WriteUInt32LittleEndian(bytes, 16, 0x4E4F534A);
        Encoding.ASCII.GetBytes("{}  ").CopyTo(bytes, 20);
        if (length > 24)
        {
            WriteUInt32LittleEndian(bytes, 24, (uint)length - 32);
            WriteUInt32LittleEndian(bytes, 28, 0x004E4942);
        }
        return bytes;
    }

    private static byte[] JavaClassWithInvalidExtraConstant(byte invalidTag)
    {
        using var stream = new MemoryStream();
        WriteUInt32BigEndian(stream, 0xCAFEBABE);
        WriteUInt16BigEndian(stream, 0);
        WriteUInt16BigEndian(stream, 61);
        WriteUInt16BigEndian(stream, 6);
        WriteJavaUtf8(stream, "Test");
        stream.WriteByte(7); WriteUInt16BigEndian(stream, 1);
        WriteJavaUtf8(stream, "java/lang/Object");
        stream.WriteByte(7); WriteUInt16BigEndian(stream, 3);
        stream.WriteByte(invalidTag);
        switch (invalidTag) {
            case 7:
            case 8:
            case 16:
            case 19:
            case 20:
                WriteUInt16BigEndian(stream, 0);
                break;
            case 9:
            case 10:
            case 11:
            case 12:
            case 17:
            case 18:
                WriteUInt16BigEndian(stream, 0);
                WriteUInt16BigEndian(stream, 0);
                break;
            case 15:
                stream.WriteByte(1);
                WriteUInt16BigEndian(stream, 0);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(invalidTag));
        }
        WriteUInt16BigEndian(stream, 0x21);
        WriteUInt16BigEndian(stream, 2);
        WriteUInt16BigEndian(stream, 4);
        WriteUInt16BigEndian(stream, 0);
        WriteUInt16BigEndian(stream, 0);
        WriteUInt16BigEndian(stream, 0);
        WriteUInt16BigEndian(stream, 0);
        return stream.ToArray();
    }

    private static void WriteJavaUtf8(Stream stream, string value)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(value);
        stream.WriteByte(1);
        WriteUInt16BigEndian(stream, (ushort)bytes.Length);
        stream.Write(bytes, 0, bytes.Length);
    }

    private static byte[] Qcow2()
    {
        var bytes = new byte[0x30000];
        new byte[] { (byte)'Q', (byte)'F', (byte)'I', 0xFB }.CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 4, 2);
        WriteUInt32BigEndian(bytes, 20, 16);
        WriteUInt64BigEndian(bytes, 24, 1024 * 1024);
        WriteUInt32BigEndian(bytes, 36, 1);
        WriteUInt64BigEndian(bytes, 40, 0x10000);
        WriteUInt64BigEndian(bytes, 48, 0x20000);
        WriteUInt32BigEndian(bytes, 56, 1);
        return bytes;
    }

    private static byte[] Woff1WithTwoTables()
    {
        var bytes = new byte[92];
        Encoding.ASCII.GetBytes("wOFF").CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 4, 0x00010000);
        WriteUInt32BigEndian(bytes, 8, (uint)bytes.Length);
        WriteUInt16BigEndian(bytes, 12, 2);
        WriteUInt32BigEndian(bytes, 16, 52);
        Encoding.ASCII.GetBytes("head").CopyTo(bytes, 44);
        WriteUInt32BigEndian(bytes, 48, 84);
        WriteUInt32BigEndian(bytes, 52, 4);
        WriteUInt32BigEndian(bytes, 56, 4);
        Encoding.ASCII.GetBytes("name").CopyTo(bytes, 64);
        WriteUInt32BigEndian(bytes, 68, 88);
        WriteUInt32BigEndian(bytes, 72, 4);
        WriteUInt32BigEndian(bytes, 76, 4);
        return bytes;
    }

    private static byte[] Pe(ushort machine)
    {
        var bytes = new byte[224];
        Encoding.ASCII.GetBytes("MZ").CopyTo(bytes, 0);
        WriteUInt32LittleEndian(bytes, 0x3C, 0x40);
        Encoding.ASCII.GetBytes("PE\0\0").CopyTo(bytes, 0x40);
        WriteUInt16LittleEndian(bytes, 0x44, machine);
        WriteUInt16LittleEndian(bytes, 0x46, 1);
        WriteUInt16LittleEndian(bytes, 0x54, 96);
        WriteUInt16LittleEndian(bytes, 0x56, 2);
        WriteUInt16LittleEndian(bytes, 0x58, 0x10B);
        return bytes;
    }

    private static byte[] ShellLink(int length, uint flags)
    {
        var bytes = new byte[length];
        bytes[0] = 0x4C;
        new byte[] {
            0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
        }.CopyTo(bytes, 4);
        WriteUInt32LittleEndian(bytes, 20, flags);
        WriteUInt32LittleEndian(bytes, 60, 1);
        return bytes;
    }

    private static byte[] ShellLinkWithAllStructures()
    {
        var bytes = ShellLink(161, 0x000000FF);
        int cursor = 76;
        WriteUInt16LittleEndian(bytes, cursor, 2);
        cursor += 4;
        WriteUInt32LittleEndian(bytes, cursor, 57);
        WriteUInt32LittleEndian(bytes, cursor + 4, 28);
        WriteUInt32LittleEndian(bytes, cursor + 8, 1);
        WriteUInt32LittleEndian(bytes, cursor + 12, 28);
        WriteUInt32LittleEndian(bytes, cursor + 16, 46);
        WriteUInt32LittleEndian(bytes, cursor + 24, 50);
        WriteUInt32LittleEndian(bytes, cursor + 28, 18);
        WriteUInt32LittleEndian(bytes, cursor + 32, 3);
        WriteUInt32LittleEndian(bytes, cursor + 36, 1);
        WriteUInt32LittleEndian(bytes, cursor + 40, 16);
        bytes[cursor + 44] = (byte)'V';
        bytes[cursor + 46] = (byte)'C'; bytes[cursor + 47] = (byte)':'; bytes[cursor + 48] = (byte)'\\';
        Encoding.ASCII.GetBytes("file").CopyTo(bytes, cursor + 50);
        cursor += 57;
        for (int index = 0; index < 5; index++) {
            WriteUInt16LittleEndian(bytes, cursor, 1);
            bytes[cursor + 2] = (byte)'A';
            cursor += 4;
        }
        return bytes;
    }

    private static byte[] Midi(params byte[][] events)
    {
        int trackLength = events.Sum(value => value.Length);
        var bytes = new byte[22 + trackLength];
        Encoding.ASCII.GetBytes("MThd").CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 4, 6);
        WriteUInt16BigEndian(bytes, 10, 1);
        WriteUInt16BigEndian(bytes, 12, 96);
        Encoding.ASCII.GetBytes("MTrk").CopyTo(bytes, 14);
        WriteUInt32BigEndian(bytes, 18, (uint)trackLength);
        int cursor = 22;
        foreach (byte[] value in events) {
            value.CopyTo(bytes, cursor);
            cursor += value.Length;
        }
        return bytes;
    }

    private static byte[] MidiWithLargeInvalidTrack()
    {
        const int trackLength = 5000;
        var track = new byte[trackLength];
        new byte[] { 0, 0x90, 60, 64, 0, 0xF0, 0, 0, 60, 64 }.CopyTo(track, 0);
        return Midi(track);
    }

    private static void WriteUInt16LittleEndian(byte[] bytes, int offset, ushort value)
    {
        bytes[offset] = (byte)value;
        bytes[offset + 1] = (byte)(value >> 8);
    }

    private static void WriteUInt32LittleEndian(byte[] bytes, int offset, uint value)
    {
        for (int index = 0; index < 4; index++) bytes[offset + index] = (byte)(value >> (index * 8));
    }

    private static void WriteUInt16BigEndian(byte[] bytes, int offset, ushort value)
    {
        bytes[offset] = (byte)(value >> 8);
        bytes[offset + 1] = (byte)value;
    }

    private static void WriteUInt32BigEndian(byte[] bytes, int offset, uint value)
    {
        bytes[offset] = (byte)(value >> 24);
        bytes[offset + 1] = (byte)(value >> 16);
        bytes[offset + 2] = (byte)(value >> 8);
        bytes[offset + 3] = (byte)value;
    }

    private static void WriteUInt64BigEndian(byte[] bytes, int offset, ulong value)
    {
        for (int index = 0; index < 8; index++) bytes[offset + index] = (byte)(value >> ((7 - index) * 8));
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

    private sealed class NonSeekableReadStream : Stream
    {
        private readonly MemoryStream _inner;
        internal NonSeekableReadStream(byte[] bytes) => _inner = new MemoryStream(bytes, writable: false);
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) { if (disposing) _inner.Dispose(); base.Dispose(disposing); }
    }
}
