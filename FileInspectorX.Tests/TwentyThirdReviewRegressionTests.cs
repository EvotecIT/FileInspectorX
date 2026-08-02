using System.Globalization;
using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

[Collection(nameof(DetectionSettingsCollection))]
public sealed class TwentyThirdReviewRegressionTests
{
    [Fact]
    public void ElfRequiresZeroOffsetsForAbsentTables()
    {
        byte[] valid = ElfWithoutTables();
        AssertParity(valid, "elf");

        WriteUInt64LittleEndian(valid, 32, 64);
        AssertNotDetectedAs(valid, "elf");
    }

    [Fact]
    public void GlbRejectsDuplicateJsonAndBinaryChunks()
    {
        AssertParity(Glb(0x4E4F534A, 0x004E4942), "glb");
        AssertNotDetectedAs(Glb(0x4E4F534A, 0x4E4F534A), "glb");
        AssertNotDetectedAs(Glb(0x4E4F534A, 0x004E4942, 0x004E4942), "glb");
    }

    [Fact]
    public void SeekableTtcDirectoryWalkHonorsTheReadBudget()
    {
        int originalBudget = Settings.DetectionReadBudgetBytes;
        try
        {
            Settings.DetectionReadBudgetBytes = 256;
            byte[] bytes = LargeSharedDirectoryTtc();
            var fromBytes = FileInspector.Detect(bytes);
            Assert.Equal("ttc", fromBytes?.Extension);
            Assert.Equal("Medium", fromBytes?.Confidence);
            Assert.Contains("directory-budget", fromBytes?.Reason);

            using var stream = new CountingReadStream(bytes) { Position = 7 };

            var result = FileInspector.Detect(stream);

            Assert.Equal("ttc", result?.Extension);
            Assert.Equal("Medium", result?.Confidence);
            Assert.Contains("directory-budget", result?.Reason);
            Assert.Equal(7, stream.Position);
            Assert.True(stream.BytesRead < 100_000, $"Unexpectedly read {stream.BytesRead} bytes.");
        }
        finally
        {
            Settings.DetectionReadBudgetBytes = originalBudget;
        }
    }

    [Fact]
    public void JpmUsesTheCompoundImageHeaderBox()
        => AssertParity(Jpm(), "jpm");

    [Fact]
    public void Qcow2VersionThreeHeaderFitsInsideTheFirstCluster()
    {
        byte[] valid = Qcow2V3(headerLength: 104);
        AssertParity(valid, "qcow2");

        byte[] invalid = Qcow2V3(headerLength: 1024);
        AssertNotDetectedAs(invalid, "qcow2");
    }

    [Fact]
    public void ShellLinkExtraDataBlocksIncludeTheirSignature()
    {
        AssertParity(ShellLink(blockSize: 0), "lnk");
        AssertNotDetectedAs(ShellLink(blockSize: 4), "lnk");
    }

    [Fact]
    public void DebRequiresCompleteChecksummedUncompressedTarMembers()
    {
        AssertParity(TestHelpers.CreateMinimalDeb(), "deb");
        AssertNotDetectedAs(DebWithMarkerOnlyTarMembers(), "deb");
    }

    private static void AssertParity(byte[] bytes, string extension)
    {
        Assert.Equal(extension, FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false) { Position = Math.Min(3, bytes.Length) };
        Assert.Equal(extension, FileInspector.Detect(stream)?.Extension);
        Assert.Equal(Math.Min(3, bytes.Length), stream.Position);
    }

    private static void AssertNotDetectedAs(byte[] bytes, string extension)
    {
        Assert.NotEqual(extension, FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false);
        Assert.NotEqual(extension, FileInspector.Detect(stream)?.Extension);
    }

    private static byte[] ElfWithoutTables()
    {
        var bytes = new byte[128];
        new byte[] { 0x7F, (byte)'E', (byte)'L', (byte)'F', 2, 1, 1 }.CopyTo(bytes, 0);
        WriteUInt16LittleEndian(bytes, 16, 2);
        WriteUInt16LittleEndian(bytes, 18, 62);
        WriteUInt32LittleEndian(bytes, 20, 1);
        WriteUInt16LittleEndian(bytes, 52, 64);
        WriteUInt16LittleEndian(bytes, 54, 56);
        WriteUInt16LittleEndian(bytes, 58, 64);
        return bytes;
    }

    private static byte[] Glb(params uint[] chunkTypes)
    {
        var bytes = new byte[12 + chunkTypes.Length * 12];
        Encoding.ASCII.GetBytes("glTF").CopyTo(bytes, 0);
        WriteUInt32LittleEndian(bytes, 4, 2);
        WriteUInt32LittleEndian(bytes, 8, (uint)bytes.Length);
        int cursor = 12;
        foreach (uint chunkType in chunkTypes)
        {
            WriteUInt32LittleEndian(bytes, cursor, 4);
            WriteUInt32LittleEndian(bytes, cursor + 4, chunkType);
            if (chunkType == 0x4E4F534A) Encoding.ASCII.GetBytes("{}  ").CopyTo(bytes, cursor + 8);
            cursor += 12;
        }
        return bytes;
    }

    private static byte[] LargeSharedDirectoryTtc()
    {
        const int fontCount = 4095;
        const int tableCount = 4095;
        int headerLength = 12 + fontCount * 4;
        int directoryOffset = (headerLength + 3) & ~3;
        int directoryLength = 12 + tableCount * 16;
        int tableOffset = directoryOffset + directoryLength;
        var bytes = new byte[tableOffset + 4];
        Encoding.ASCII.GetBytes("ttcf").CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 4, 0x00010000);
        WriteUInt32BigEndian(bytes, 8, fontCount);
        for (int font = 0; font < fontCount; font++)
            WriteUInt32BigEndian(bytes, 12 + font * 4, (uint)directoryOffset);
        WriteUInt32BigEndian(bytes, directoryOffset, 0x00010000);
        WriteUInt16BigEndian(bytes, directoryOffset + 4, tableCount);
        WriteUInt16BigEndian(bytes, directoryOffset + 6, 32768);
        WriteUInt16BigEndian(bytes, directoryOffset + 8, 11);
        WriteUInt16BigEndian(bytes, directoryOffset + 10, 32752);
        for (int table = 0; table < tableCount; table++)
        {
            int record = directoryOffset + 12 + table * 16;
            Encoding.ASCII.GetBytes("head").CopyTo(bytes, record);
            WriteUInt32BigEndian(bytes, record + 8, (uint)tableOffset);
            WriteUInt32BigEndian(bytes, record + 12, 4);
        }
        return bytes;
    }

    private static byte[] Jpm()
    {
        var bytes = new byte[48];
        WriteUInt32BigEndian(bytes, 0, 12);
        Encoding.ASCII.GetBytes("jP  ").CopyTo(bytes, 4);
        new byte[] { 0x0D, 0x0A, 0x87, 0x0A }.CopyTo(bytes, 8);
        WriteUInt32BigEndian(bytes, 12, 20);
        Encoding.ASCII.GetBytes("ftypjpm ").CopyTo(bytes, 16);
        WriteUInt32BigEndian(bytes, 24, 0);
        Encoding.ASCII.GetBytes("jpm ").CopyTo(bytes, 28);
        WriteUInt32BigEndian(bytes, 32, 8);
        Encoding.ASCII.GetBytes("jpmh").CopyTo(bytes, 36);
        WriteUInt32BigEndian(bytes, 40, 8);
        Encoding.ASCII.GetBytes("jp2c").CopyTo(bytes, 44);
        return bytes;
    }

    private static byte[] Qcow2V3(uint headerLength)
    {
        var bytes = new byte[2048];
        new byte[] { (byte)'Q', (byte)'F', (byte)'I', 0xFB }.CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 4, 3);
        WriteUInt32BigEndian(bytes, 20, 9);
        WriteUInt64BigEndian(bytes, 24, 1024 * 1024);
        WriteUInt32BigEndian(bytes, 36, 32);
        WriteUInt64BigEndian(bytes, 40, 512);
        WriteUInt64BigEndian(bytes, 48, 1024);
        WriteUInt32BigEndian(bytes, 56, 1);
        WriteUInt32BigEndian(bytes, 100, headerLength);
        return bytes;
    }

    private static byte[] ShellLink(uint blockSize)
    {
        int length = blockSize == 0 ? 80 : 84;
        var bytes = new byte[length];
        bytes[0] = 0x4C;
        new byte[] {
            0x01, 0x14, 0x02, 0, 0, 0, 0, 0,
            0xC0, 0, 0, 0, 0, 0, 0, 0x46
        }.CopyTo(bytes, 4);
        WriteUInt32LittleEndian(bytes, 76, blockSize);
        return bytes;
    }

    private static byte[] DebWithMarkerOnlyTarMembers()
    {
        var fakeTar = new byte[1536];
        Encoding.ASCII.GetBytes("ustar\0").CopyTo(fakeTar, 257);
        using var stream = new MemoryStream();
        stream.Write(Encoding.ASCII.GetBytes("!<arch>\n"), 0, 8);
        WriteArMember(stream, "debian-binary", Encoding.ASCII.GetBytes("2.0\n"));
        WriteArMember(stream, "control.tar", fakeTar);
        WriteArMember(stream, "data.tar", fakeTar);
        return stream.ToArray();
    }

    private static void WriteArMember(Stream stream, string name, byte[] data)
    {
        string header = (name + "/").PadRight(16) + "0".PadRight(12) + "0".PadRight(6) + "0".PadRight(6) +
                        "100644".PadRight(8) + data.Length.ToString(CultureInfo.InvariantCulture).PadRight(10) + "`\n";
        byte[] headerBytes = Encoding.ASCII.GetBytes(header);
        stream.Write(headerBytes, 0, headerBytes.Length);
        stream.Write(data, 0, data.Length);
        if ((data.Length & 1) != 0) stream.WriteByte((byte)'\n');
    }

    private static void WriteUInt16LittleEndian(byte[] bytes, int offset, ushort value)
    {
        bytes[offset] = (byte)value;
        bytes[offset + 1] = (byte)(value >> 8);
    }

    private static void WriteUInt16BigEndian(byte[] bytes, int offset, ushort value)
    {
        bytes[offset] = (byte)(value >> 8);
        bytes[offset + 1] = (byte)value;
    }

    private static void WriteUInt32LittleEndian(byte[] bytes, int offset, uint value)
    {
        for (int index = 0; index < 4; index++) bytes[offset + index] = (byte)(value >> (index * 8));
    }

    private static void WriteUInt32BigEndian(byte[] bytes, int offset, uint value)
    {
        bytes[offset] = (byte)(value >> 24);
        bytes[offset + 1] = (byte)(value >> 16);
        bytes[offset + 2] = (byte)(value >> 8);
        bytes[offset + 3] = (byte)value;
    }

    private static void WriteUInt64LittleEndian(byte[] bytes, int offset, ulong value)
    {
        for (int index = 0; index < 8; index++) bytes[offset + index] = (byte)(value >> (index * 8));
    }

    private static void WriteUInt64BigEndian(byte[] bytes, int offset, ulong value)
    {
        for (int index = 0; index < 8; index++) bytes[offset + index] = (byte)(value >> ((7 - index) * 8));
    }

    private sealed class CountingReadStream : Stream
    {
        private readonly MemoryStream _inner;

        internal CountingReadStream(byte[] value) => _inner = new MemoryStream(value, writable: false);
        internal long BytesRead { get; private set; }
        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => _inner.Length;
        public override long Position { get => _inner.Position; set => _inner.Position = value; }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count)
        {
            int read = _inner.Read(buffer, offset, count);
            BytesRead += read;
            return read;
        }
        public override long Seek(long offset, SeekOrigin origin) => _inner.Seek(offset, origin);
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) { if (disposing) _inner.Dispose(); base.Dispose(disposing); }
    }
}
