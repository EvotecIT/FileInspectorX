using System.IO.Compression;
using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class SecondReviewRegressionTests
{
    public static IEnumerable<object[]> LargeNonSeekableFormats()
    {
        yield return new object[] { LargeGlb(), "glb" };
        yield return new object[] { LargeDex(), "dex" };
        yield return new object[] { LargeRpm(), "rpm" };
        yield return new object[] { LargeFtyp(), "mp4" };
        yield return new object[] { LargeMinidump(), "dmp" };
        yield return new object[] { LargeFatMachO(), "macho" };
        yield return new object[] { LargeWoff2(), "woff2" };
    }

    [Theory]
    [MemberData(nameof(LargeNonSeekableFormats))]
    public void NonSeekableStreamsDoNotTreatSampleLengthAsWholeFile(byte[] bytes, string extension)
    {
        using var stream = new NonSeekableReadStream(bytes);

        Assert.Equal(extension, FileInspector.Detect(stream)?.Extension);
    }

    [Fact]
    public void SplitZipSpanningMarkerIsStructurallyValidated()
    {
        var bytes = new byte[35];
        Encoding.ASCII.GetBytes("PK\u0007\bPK\u0003\u0004").CopyTo(bytes, 0);
        WriteUInt16LittleEndian(bytes, 8, 20);
        WriteUInt16LittleEndian(bytes, 30, 1);
        bytes[34] = (byte)'a';

        AssertParity(bytes, "zip");
    }

    [Fact]
    public void CrxEmbeddedZipBeyondDetectionPrefixKeepsApiParity()
    {
        var bytes = TestHelpers.CreateMinimalCrx3(5000);

        AssertParity(bytes, "crx");
    }

    [Fact]
    public void Woff2CollectionFlavorAndDirectoryAreAccepted()
        => AssertParity(Woff2Collection(), "woff2");

    [Fact]
    public void ExtendedSizeFtypBoxIsClassified()
    {
        var bytes = new byte[24];
        WriteUInt32BigEndian(bytes, 0, 1);
        Encoding.ASCII.GetBytes("ftyp").CopyTo(bytes, 4);
        WriteUInt64BigEndian(bytes, 8, (ulong)bytes.Length);
        Encoding.ASCII.GetBytes("mp42").CopyTo(bytes, 16);

        AssertParity(bytes, "mp4");
    }

    [Fact]
    public void Os2BitmapWithSixteenByteHeaderIsAccepted()
    {
        var bytes = new byte[34];
        Encoding.ASCII.GetBytes("BM").CopyTo(bytes, 0);
        WriteUInt32LittleEndian(bytes, 2, (uint)bytes.Length);
        WriteUInt32LittleEndian(bytes, 10, 30);
        WriteUInt32LittleEndian(bytes, 14, 16);
        WriteUInt32LittleEndian(bytes, 18, 1);
        WriteUInt32LittleEndian(bytes, 22, 1);
        WriteUInt16LittleEndian(bytes, 26, 1);
        WriteUInt16LittleEndian(bytes, 28, 24);

        AssertParity(bytes, "bmp");
    }

    [Fact]
    public void GuessedIpaPackageIsDangerous()
    {
        using var output = new MemoryStream();
        using (var archive = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true))
        {
            using var entry = archive.CreateEntry("Payload/Test.app/Info.plist").Open();
            entry.WriteByte(0);
        }

        var bytes = output.ToArray();
        using var stream = new MemoryStream(bytes, writable: false);
        var fromStream = FileInspector.Detect(stream);
        Assert.Equal("ipa", fromStream?.GuessedExtension);
        Assert.True(fromStream?.IsDangerous);

        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".zip");
        try
        {
            File.WriteAllBytes(path, bytes);
            var fromPath = FileInspector.Detect(path);
            Assert.Equal("ipa", fromPath?.GuessedExtension);
            Assert.True(fromPath?.IsDangerous);
        }
        finally
        {
            TestHelpers.SafeDelete(path);
        }
    }

    [Theory]
    [InlineData((byte)1, 32)]
    [InlineData((byte)2, 32)]
    [InlineData((byte)5, 48)]
    public void NetCdfRequiresAllMandatoryHeaderLists(byte version, int validLength)
    {
        var valid = new byte[validLength];
        new byte[] { (byte)'C', (byte)'D', (byte)'F', version }.CopyTo(valid, 0);

        AssertParity(valid, "nc");
        Assert.NotEqual("nc", FileInspector.Detect(valid.Take(validLength - 1).ToArray())?.Extension);
    }

    [Fact]
    public void NetCdfParsesNonEmptyDimensionList()
    {
        var bytes = new byte[44];
        new byte[] { (byte)'C', (byte)'D', (byte)'F', 1 }.CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 8, 10);
        WriteUInt32BigEndian(bytes, 12, 1);
        WriteUInt32BigEndian(bytes, 16, 1);
        bytes[20] = (byte)'x';
        WriteUInt32BigEndian(bytes, 24, 10);

        AssertParity(bytes, "nc");
    }

    [Theory]
    [InlineData(0u, 1u)]
    [InlineData(uint.MaxValue, 0xFFFFFFFEu)]
    public void RegistryHiveChecksumNormalizationIsAccepted(uint calculated, uint stored)
        => AssertParity(RegistryHiveWithChecksum(calculated, stored), "hive");

    private static void AssertParity(byte[] bytes, string extension)
    {
        Assert.Equal(extension, FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false);
        Assert.Equal(extension, FileInspector.Detect(stream)?.Extension);
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".bin");
        try
        {
            File.WriteAllBytes(path, bytes);
            Assert.Equal(extension, FileInspector.Detect(path)?.Extension);
        }
        finally
        {
            TestHelpers.SafeDelete(path);
        }
    }

    private static byte[] LargeGlb()
    {
        var bytes = new byte[5000];
        Encoding.ASCII.GetBytes("glTF").CopyTo(bytes, 0);
        WriteUInt32LittleEndian(bytes, 4, 2);
        WriteUInt32LittleEndian(bytes, 8, (uint)bytes.Length);
        WriteUInt32LittleEndian(bytes, 12, 4);
        WriteUInt32LittleEndian(bytes, 16, 0x4E4F534A);
        Encoding.ASCII.GetBytes("{}  ").CopyTo(bytes, 20);
        WriteUInt32LittleEndian(bytes, 24, (uint)bytes.Length - 32);
        WriteUInt32LittleEndian(bytes, 28, 0x004E4942);
        return bytes;
    }

    private static byte[] LargeDex()
        => TestHelpers.CreateMinimalDex(length: 5000);

    private static byte[] LargeRpm()
    {
        var bytes = new byte[5000];
        new byte[] { 0xED, 0xAB, 0xEE, 0xDB, 3, 0 }.CopyTo(bytes, 0);
        WriteUInt16BigEndian(bytes, 78, 5);
        new byte[] { 0x8E, 0xAD, 0xE8, 1 }.CopyTo(bytes, 96);
        WriteUInt32BigEndian(bytes, 104, 1);
        WriteUInt32BigEndian(bytes, 108, 4800);
        new byte[] { 0x8E, 0xAD, 0xE8, 1 }.CopyTo(bytes, 4928);
        WriteUInt32BigEndian(bytes, 4936, 1);
        return bytes;
    }

    private static byte[] LargeFtyp()
    {
        var bytes = new byte[5000];
        WriteUInt32BigEndian(bytes, 0, (uint)bytes.Length);
        Encoding.ASCII.GetBytes("ftypmp42").CopyTo(bytes, 4);
        return bytes;
    }

    private static byte[] LargeMinidump()
    {
        var bytes = new byte[5000];
        Encoding.ASCII.GetBytes("MDMP").CopyTo(bytes, 0);
        WriteUInt32LittleEndian(bytes, 4, 0xA793);
        WriteUInt32LittleEndian(bytes, 8, 1);
        WriteUInt32LittleEndian(bytes, 12, 4500);
        return bytes;
    }

    private static byte[] LargeFatMachO()
    {
        var bytes = new byte[5000];
        WriteUInt32BigEndian(bytes, 0, 0xCAFEBABE);
        WriteUInt32BigEndian(bytes, 4, 1);
        WriteUInt32BigEndian(bytes, 8, 7);
        WriteUInt32BigEndian(bytes, 16, 4096);
        WriteUInt32BigEndian(bytes, 20, 512);
        WriteUInt32BigEndian(bytes, 24, 12);
        return bytes;
    }

    private static byte[] LargeWoff2()
    {
        var bytes = new byte[5000];
        Encoding.ASCII.GetBytes("wOF2true").CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 8, (uint)bytes.Length);
        WriteUInt16BigEndian(bytes, 12, 1);
        WriteUInt32BigEndian(bytes, 16, 32);
        WriteUInt32BigEndian(bytes, 20, 4950);
        bytes[48] = 1;
        bytes[49] = 4;
        return bytes;
    }

    private static byte[] Woff2Collection()
    {
        var bytes = new byte[62];
        Encoding.ASCII.GetBytes("wOF2ttcf").CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 8, (uint)bytes.Length);
        WriteUInt16BigEndian(bytes, 12, 1);
        WriteUInt32BigEndian(bytes, 16, 32);
        WriteUInt32BigEndian(bytes, 20, 1);
        bytes[48] = 1; // Known 'head' table, null transform.
        bytes[49] = 4;
        WriteUInt32BigEndian(bytes, 50, 0x00010000);
        bytes[54] = 1; // One font.
        bytes[55] = 1; // One table in the font.
        WriteUInt32BigEndian(bytes, 56, 0x00010000);
        bytes[60] = 0; // Table-directory index.
        bytes[61] = 1; // One byte of compressed data.
        return bytes;
    }

    private static byte[] RegistryHiveWithChecksum(uint calculated, uint stored)
    {
        var bytes = new byte[8192];
        Encoding.ASCII.GetBytes("regf").CopyTo(bytes, 0);
        WriteUInt32LittleEndian(bytes, 4, 1);
        WriteUInt32LittleEndian(bytes, 8, 1);
        WriteUInt32LittleEndian(bytes, 20, 1);
        WriteUInt32LittleEndian(bytes, 24, 5);
        WriteUInt32LittleEndian(bytes, 32, 1);
        WriteUInt32LittleEndian(bytes, 36, 0x20);
        WriteUInt32LittleEndian(bytes, 40, 0x1000);
        WriteUInt32LittleEndian(bytes, 44, 1);
        Encoding.ASCII.GetBytes("hbin").CopyTo(bytes, 4096);
        WriteUInt32LittleEndian(bytes, 4100, 0);
        WriteUInt32LittleEndian(bytes, 4104, 0x1000);
        uint current = 0;
        for (int offset = 0; offset < 0x1FC; offset += 4) current ^= ReadUInt32LittleEndian(bytes, offset);
        WriteUInt32LittleEndian(bytes, 0x100, current ^ calculated);
        WriteUInt32LittleEndian(bytes, 0x1FC, stored);
        return bytes;
    }

    private static uint ReadUInt32LittleEndian(byte[] bytes, int offset)
        => (uint)(bytes[offset] | bytes[offset + 1] << 8 | bytes[offset + 2] << 16 | bytes[offset + 3] << 24);

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
        bytes[offset] = (byte)value;
        bytes[offset + 1] = (byte)(value >> 8);
        bytes[offset + 2] = (byte)(value >> 16);
        bytes[offset + 3] = (byte)(value >> 24);
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
        for (int i = 0; i < 8; i++) bytes[offset + i] = (byte)(value >> ((7 - i) * 8));
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
