using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class ValidatedFormatDetectionTests
{
    public static IEnumerable<object[]> ValidSamples()
    {
        yield return Sample("exe", TestHelpers.CreateMinimalPe(), 0x80);
        yield return Sample("png", TestHelpers.CreateMinimalPng(), 12);
        yield return Sample("gif", Gif(), 6);
        yield return Sample("zip", TestHelpers.CreateEmptyZip(), 0);
        yield return Sample("ole2", Ole2(), 28);
        yield return Sample("pdf", Encoding.ASCII.GetBytes("%PDF-1.7\n"), 6);
        yield return Sample("jpg", new byte[] { 0xFF, 0xD8, 0xFF, 0xE0, 0, 2 }, 0);
        yield return Sample("bmp", Bmp(), 14);
        yield return Sample("gz", Gzip(), 2);
        yield return Sample("bz2", new byte[] { 0x42, 0x5A, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59 }, 4);
        yield return Sample("ogg", Ogg(), 4);
        yield return Sample("mp3", Mp3(), 3);
        yield return Sample("wasm", Wasm(), 4);
        yield return Sample("pcap", Pcap(), 4);
        yield return Sample("pcapng", PcapNg(), 8);
        yield return Sample("flac", Flac(), 7);
        yield return Sample("crx", Crx(), 4);
        yield return Sample("ico", Icon(), 2);
        yield return Sample("ttc", FontCollection(), 4);
        yield return Sample("rpm", Rpm(), 96);
        yield return Sample("qcow2", Qcow2(), 0);
        yield return Sample("mid", Midi(), 4);
        yield return Sample("dds", Dds(), 4);
        yield return Sample("qoi", Qoi(), 12);
        yield return Sample("dcm", Dicom(), 136);
        yield return Sample("ndb", OutlookNdb(), 8);
        yield return Sample("matroska", Matroska(), 6);
        yield return Sample("parquet", Parquet(), 12);
        yield return Sample("arrow", Arrow(), 25);
        yield return Sample("deb", Deb(), 80);
        yield return Sample("vhd", Vhd(), 511);
        yield return Sample("vhdx", Vhdx(), 64 * 1024);
    }

    [Theory]
    [MemberData(nameof(ValidSamples))]
    public void StructurallyValidatedFormatsHaveParityAcrossBytesStreamAndPath(string extension, byte[] bytes, int _)
    {
        var fromBytes = FileInspector.Detect(bytes);
        using var stream = new MemoryStream(bytes, writable: false);
        long originalPosition = Math.Min(7, stream.Length);
        stream.Position = originalPosition;
        var fromStream = FileInspector.Detect(stream);
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".bin");
        try
        {
            File.WriteAllBytes(path, bytes);
            var fromPath = FileInspector.Detect(path);

            Assert.Equal(extension, fromBytes?.Extension);
            Assert.Equal(extension, fromStream?.Extension);
            Assert.Equal(extension, fromPath?.Extension);
            Assert.Equal("High", fromBytes?.Confidence);
            Assert.Equal(fromBytes?.Confidence, fromStream?.Confidence);
            Assert.Equal(fromBytes?.Confidence, fromPath?.Confidence);
            Assert.Equal(originalPosition, stream.Position);
        }
        finally
        {
            TestHelpers.SafeDelete(path);
        }
    }

    [Theory]
    [MemberData(nameof(ValidSamples))]
    public void StructuralNearMissesDoNotRetainTheClaimedFormat(string extension, byte[] bytes, int mutationOffset)
    {
        var mutated = (byte[])bytes.Clone();
        mutated[mutationOffset] ^= 0x01;

        Assert.NotEqual(extension, FileInspector.Detect(mutated)?.Extension);
    }

    [Theory]
    [MemberData(nameof(ValidSamples))]
    public void TruncationBeforeDecisiveStructureDoesNotRetainTheClaimedFormat(string extension, byte[] bytes, int decisiveOffset)
    {
        var truncated = bytes.Take(decisiveOffset).ToArray();

        Assert.NotEqual(extension, FileInspector.Detect(truncated)?.Extension);
    }

    [Fact]
    public void DeterministicRandomBinaryInputsAreNeverHighConfidence()
    {
        var random = new Random(0x51A7C0DE);
        for (int i = 0; i < 1000; i++)
        {
            var bytes = new byte[random.Next(1, 513)];
            random.NextBytes(bytes);

            var result = FileInspector.Detect(bytes);

            Assert.False(string.Equals("High", result?.Confidence, StringComparison.OrdinalIgnoreCase),
                $"Unexpected high-confidence {result?.Extension} detection at random sample {i}: {result?.Reason}");
        }
    }

    [Theory]
    [InlineData(5000, 0, 8)]
    [InlineData(1, 5000, 8)]
    [InlineData(1, 0, 2)]
    [InlineData(1, 0, 10)]
    [InlineData(1, 0, 16)]
    [InlineData(1, 0, 18)]
    [InlineData(1, 0, 19)]
    public void ZipVariableHeadersAndSpecificationMethodsKeepApiParity(int nameLength, int extraLength, ushort method)
    {
        var bytes = ZipLocalHeader(nameLength, extraLength, method);
        using var stream = new MemoryStream(bytes, writable: false);
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".bin");
        try
        {
            File.WriteAllBytes(path, bytes);

            Assert.Equal("zip", FileInspector.Detect(bytes)?.Extension);
            Assert.Equal("zip", FileInspector.Detect(stream)?.Extension);
            Assert.Equal("zip", FileInspector.Detect(path)?.Extension);
        }
        finally
        {
            TestHelpers.SafeDelete(path);
        }
    }

    [Fact]
    public void EmptyZipCommentKeepsApiParity()
    {
        var bytes = new byte[27];
        WriteUInt32LittleEndian(bytes, 0, 0x06054B50);
        WriteUInt16LittleEndian(bytes, 20, 5);
        Encoding.ASCII.GetBytes("notes").CopyTo(bytes, 22);
        using var stream = new MemoryStream(bytes, writable: false);
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".bin");
        try
        {
            File.WriteAllBytes(path, bytes);
            Assert.Equal("zip", FileInspector.Detect(bytes)?.Extension);
            Assert.Equal("zip", FileInspector.Detect(stream)?.Extension);
            Assert.Equal("zip", FileInspector.Detect(path)?.Extension);
        }
        finally
        {
            TestHelpers.SafeDelete(path);
        }
    }

    [Fact]
    public void ArrowRootOffsetCannotWrapPastItsFooter()
    {
        var bytes = Arrow();
        WriteUInt32LittleEndian(bytes, 8, uint.MaxValue);

        Assert.NotEqual("arrow", FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false);
        Assert.NotEqual("arrow", FileInspector.Detect(stream)?.Extension);
    }

    [Fact]
    public void UnknownIsoBmffBrandIsNotMisreportedAsMp4()
    {
        var bytes = new byte[16];
        WriteUInt32BigEndian(bytes, 0, 16);
        Encoding.ASCII.GetBytes("ftypzzzz").CopyTo(bytes, 4);

        var result = FileInspector.Detect(bytes);

        Assert.Equal("isobmff", result?.Extension);
        Assert.Equal("Medium", result?.Confidence);
        Assert.Equal("ftyp:unknown-brand", result?.Reason);
    }

    [Fact]
    public void ShortMagicPrefixesAloneAreRejected()
    {
        (string Extension, byte[] Bytes)[] prefixes =
        {
            ("exe", new byte[] { (byte)'M', (byte)'Z' }),
            ("dmp", Encoding.ASCII.GetBytes("MDMP")),
            ("glb", Encoding.ASCII.GetBytes("glTF")),
            ("parquet", Encoding.ASCII.GetBytes("PAR1")),
            ("ogg", Encoding.ASCII.GetBytes("OggS")),
            ("crx", Encoding.ASCII.GetBytes("Cr24")),
            ("wasm", new byte[] { 0x00, 0x61, 0x73, 0x6D })
        };

        foreach (var prefix in prefixes)
            Assert.NotEqual(prefix.Extension, FileInspector.Detect(prefix.Bytes)?.Extension);
    }

    [Fact]
    public void QoiHeaderWithoutEndMarkerIsOnlyMediumConfidence()
    {
        var bytes = Qoi().Take(14).ToArray();

        var result = FileInspector.Detect(bytes);

        Assert.Equal("qoi", result?.Extension);
        Assert.Equal("Medium", result?.Confidence);
    }

    [Fact]
    public void ExpandedFormatsAreRoutedToUsefulKinds()
    {
        var expected = new Dictionary<string, ContentKind>(StringComparer.OrdinalIgnoreCase)
        {
            ["exe"] = ContentKind.Executable,
            ["wasm"] = ContentKind.Executable,
            ["rpm"] = ContentKind.Package,
            ["crx"] = ContentKind.Package,
            ["deb"] = ContentKind.Package,
            ["qcow2"] = ContentKind.DiskImage,
            ["vhd"] = ContentKind.DiskImage,
            ["vhdx"] = ContentKind.DiskImage,
            ["pcap"] = ContentKind.Capture,
            ["pcapng"] = ContentKind.Capture,
            ["ttc"] = ContentKind.Font,
            ["parquet"] = ContentKind.StructuredData,
            ["arrow"] = ContentKind.StructuredData,
            ["dcm"] = ContentKind.Medical,
            ["ndb"] = ContentKind.Database
        };

        foreach (var sample in ValidSamples())
        {
            string extension = (string)sample[0];
            if (!expected.TryGetValue(extension, out var kind)) continue;
            Assert.Equal(kind, KindClassifier.Classify(FileInspector.Detect((byte[])sample[1])));
        }
    }

    [Theory]
    [InlineData("wasm")]
    [InlineData("class")]
    [InlineData("dex")]
    [InlineData("jar")]
    [InlineData("apk")]
    [InlineData("crx")]
    [InlineData("deb")]
    [InlineData("rpm")]
    [InlineData("appx")]
    [InlineData("msix")]
    public void ExecutableAndInstallableFormatsAreMarkedDangerous(string extension)
        => Assert.True(DangerousExtensions.IsDangerous(extension));

    private static object[] Sample(string extension, byte[] bytes, int mutationOffset)
        => new object[] { extension, bytes, mutationOffset };

    private static byte[] Bmp()
    {
        var bytes = new byte[26];
        bytes[0] = (byte)'B'; bytes[1] = (byte)'M';
        WriteUInt32LittleEndian(bytes, 2, 26);
        WriteUInt32LittleEndian(bytes, 10, 26);
        WriteUInt32LittleEndian(bytes, 14, 12);
        return bytes;
    }

    private static byte[] Gif()
    {
        var bytes = new byte[13];
        Encoding.ASCII.GetBytes("GIF89a").CopyTo(bytes, 0);
        WriteUInt16LittleEndian(bytes, 6, 1);
        WriteUInt16LittleEndian(bytes, 8, 1);
        return bytes;
    }

    private static byte[] Ole2()
    {
        var bytes = new byte[512];
        new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 }.CopyTo(bytes, 0);
        WriteUInt16LittleEndian(bytes, 26, 3);
        WriteUInt16LittleEndian(bytes, 28, 0xFFFE);
        WriteUInt16LittleEndian(bytes, 30, 9);
        WriteUInt16LittleEndian(bytes, 32, 6);
        WriteUInt32LittleEndian(bytes, 44, 1);
        WriteUInt32LittleEndian(bytes, 48, 2);
        return bytes;
    }

    private static byte[] ZipLocalHeader(int nameLength, int extraLength, ushort method)
    {
        var bytes = new byte[30 + nameLength + extraLength];
        WriteUInt32LittleEndian(bytes, 0, 0x04034B50);
        WriteUInt16LittleEndian(bytes, 4, 20);
        WriteUInt16LittleEndian(bytes, 8, method);
        WriteUInt16LittleEndian(bytes, 26, checked((ushort)nameLength));
        WriteUInt16LittleEndian(bytes, 28, checked((ushort)extraLength));
        for (int i = 30; i < 30 + nameLength; i++) bytes[i] = (byte)'a';
        return bytes;
    }

    private static byte[] Gzip() => new byte[] { 0x1F, 0x8B, 8, 0, 0, 0, 0, 0, 0, 255 };

    private static byte[] Ogg()
    {
        var bytes = new byte[27];
        Encoding.ASCII.GetBytes("OggS").CopyTo(bytes, 0);
        return bytes;
    }

    private static byte[] Mp3()
    {
        var bytes = new byte[10];
        Encoding.ASCII.GetBytes("ID3").CopyTo(bytes, 0);
        bytes[3] = 4;
        return bytes;
    }

    private static byte[] Wasm()
        => new byte[] { 0, 0x61, 0x73, 0x6D, 1, 0, 0, 0 };

    private static byte[] Pcap()
    {
        var bytes = new byte[26];
        new byte[] { 0xD4, 0xC3, 0xB2, 0xA1 }.CopyTo(bytes, 0);
        WriteUInt16LittleEndian(bytes, 4, 2);
        WriteUInt16LittleEndian(bytes, 6, 4);
        WriteUInt32LittleEndian(bytes, 16, 65535);
        return bytes;
    }

    private static byte[] PcapNg()
    {
        var bytes = new byte[28];
        new byte[] { 0x0A, 0x0D, 0x0D, 0x0A }.CopyTo(bytes, 0);
        WriteUInt32LittleEndian(bytes, 4, 28);
        new byte[] { 0x4D, 0x3C, 0x2B, 0x1A }.CopyTo(bytes, 8);
        WriteUInt16LittleEndian(bytes, 12, 1);
        WriteUInt32LittleEndian(bytes, 24, 28);
        return bytes;
    }

    private static byte[] Flac()
    {
        var bytes = new byte[42];
        Encoding.ASCII.GetBytes("fLaC").CopyTo(bytes, 0);
        bytes[7] = 34;
        bytes[18] = 0x0A; bytes[19] = 0xC4; bytes[20] = 0x40;
        return bytes;
    }

    private static byte[] Crx()
    {
        var zip = TestHelpers.CreateEmptyZip();
        var bytes = new byte[13 + zip.Length];
        Encoding.ASCII.GetBytes("Cr24").CopyTo(bytes, 0);
        WriteUInt32LittleEndian(bytes, 4, 3);
        WriteUInt32LittleEndian(bytes, 8, 1);
        zip.CopyTo(bytes, 13);
        return bytes;
    }

    private static byte[] Icon()
    {
        var bytes = new byte[23];
        WriteUInt16LittleEndian(bytes, 2, 1);
        WriteUInt16LittleEndian(bytes, 4, 1);
        bytes[6] = 1; bytes[7] = 1;
        WriteUInt32LittleEndian(bytes, 14, 1);
        WriteUInt32LittleEndian(bytes, 18, 22);
        return bytes;
    }

    private static byte[] FontCollection()
    {
        var bytes = new byte[45];
        Encoding.ASCII.GetBytes("ttcf").CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 4, 0x00010000);
        WriteUInt32BigEndian(bytes, 8, 1);
        WriteUInt32BigEndian(bytes, 12, 16);
        WriteUInt32BigEndian(bytes, 16, 0x00010000);
        WriteUInt16BigEndian(bytes, 20, 1);
        WriteUInt16BigEndian(bytes, 22, 16);
        Encoding.ASCII.GetBytes("head").CopyTo(bytes, 28);
        WriteUInt32BigEndian(bytes, 36, 44);
        WriteUInt32BigEndian(bytes, 40, 1);
        return bytes;
    }

    private static byte[] Rpm()
    {
        var bytes = new byte[128];
        new byte[] { 0xED, 0xAB, 0xEE, 0xDB, 3, 0 }.CopyTo(bytes, 0);
        WriteUInt16BigEndian(bytes, 78, 5);
        new byte[] { 0x8E, 0xAD, 0xE8, 1 }.CopyTo(bytes, 96);
        WriteUInt32BigEndian(bytes, 104, 1);
        return bytes;
    }

    private static byte[] Qcow2()
    {
        var bytes = new byte[0x30000];
        new byte[] { (byte)'Q', (byte)'F', (byte)'I', 0xFB }.CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 4, 3);
        WriteUInt32BigEndian(bytes, 20, 16);
        WriteUInt64BigEndian(bytes, 24, 1024 * 1024);
        WriteUInt32BigEndian(bytes, 36, 1);
        WriteUInt64BigEndian(bytes, 40, 0x10000);
        WriteUInt64BigEndian(bytes, 48, 0x20000);
        WriteUInt32BigEndian(bytes, 56, 1);
        WriteUInt32BigEndian(bytes, 100, 104);
        return bytes;
    }

    private static byte[] Midi()
    {
        var bytes = new byte[26];
        Encoding.ASCII.GetBytes("MThd").CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 4, 6);
        WriteUInt16BigEndian(bytes, 10, 1);
        WriteUInt16BigEndian(bytes, 12, 96);
        Encoding.ASCII.GetBytes("MTrk").CopyTo(bytes, 14);
        WriteUInt32BigEndian(bytes, 18, 4);
        new byte[] { 0, 0xFF, 0x2F, 0 }.CopyTo(bytes, 22);
        return bytes;
    }

    private static byte[] Dds()
    {
        var bytes = new byte[128];
        Encoding.ASCII.GetBytes("DDS ").CopyTo(bytes, 0);
        WriteUInt32LittleEndian(bytes, 4, 124);
        WriteUInt32LittleEndian(bytes, 8, 0x1007);
        WriteUInt32LittleEndian(bytes, 12, 1);
        WriteUInt32LittleEndian(bytes, 16, 1);
        WriteUInt32LittleEndian(bytes, 76, 32);
        WriteUInt32LittleEndian(bytes, 80, 0x40);
        WriteUInt32LittleEndian(bytes, 108, 0x1000);
        return bytes;
    }

    private static byte[] Qoi()
    {
        var bytes = new byte[26];
        Encoding.ASCII.GetBytes("qoif").CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 4, 1);
        WriteUInt32BigEndian(bytes, 8, 1);
        bytes[12] = 4;
        bytes[14] = 0xFE;
        new byte[] { 0, 0, 0, 0, 0, 0, 0, 1 }.CopyTo(bytes, bytes.Length - 8);
        return bytes;
    }

    private static byte[] Dicom()
    {
        var bytes = new byte[158];
        Encoding.ASCII.GetBytes("DICM").CopyTo(bytes, 128);
        WriteUInt16LittleEndian(bytes, 132, 2);
        Encoding.ASCII.GetBytes("UL").CopyTo(bytes, 136);
        WriteUInt16LittleEndian(bytes, 138, 4);
        WriteUInt32LittleEndian(bytes, 140, 14);
        WriteUInt16LittleEndian(bytes, 144, 2);
        WriteUInt16LittleEndian(bytes, 146, 1);
        Encoding.ASCII.GetBytes("OB").CopyTo(bytes, 148);
        WriteUInt32LittleEndian(bytes, 152, 2);
        return bytes;
    }

    private static byte[] OutlookNdb()
    {
        var bytes = new byte[24];
        Encoding.ASCII.GetBytes("!BDN").CopyTo(bytes, 0);
        Encoding.ASCII.GetBytes("SM").CopyTo(bytes, 8);
        WriteUInt16LittleEndian(bytes, 10, 23);
        WriteUInt16LittleEndian(bytes, 12, 19);
        bytes[14] = 1; bytes[15] = 1;
        return bytes;
    }

    private static byte[] Matroska()
    {
        var bytes = new byte[20];
        new byte[] { 0x1A, 0x45, 0xDF, 0xA3, 0x8B, 0x42, 0x82, 0x88 }.CopyTo(bytes, 0);
        Encoding.ASCII.GetBytes("matroska").CopyTo(bytes, 8);
        new byte[] { 0x18, 0x53, 0x80, 0x67 }.CopyTo(bytes, 16);
        return bytes;
    }

    private static byte[] Parquet()
    {
        var bytes = new byte[13];
        Encoding.ASCII.GetBytes("PAR1").CopyTo(bytes, 0);
        bytes[4] = 1;
        WriteUInt32LittleEndian(bytes, 5, 1);
        Encoding.ASCII.GetBytes("PAR1").CopyTo(bytes, 9);
        return bytes;
    }

    private static byte[] Arrow()
    {
        var bytes = new byte[26];
        Encoding.ASCII.GetBytes("ARROW1").CopyTo(bytes, 0);
        WriteUInt32LittleEndian(bytes, 8, 4);
        WriteUInt32LittleEndian(bytes, 16, 8);
        Encoding.ASCII.GetBytes("ARROW1").CopyTo(bytes, 20);
        return bytes;
    }

    private static byte[] Deb()
    {
        using var stream = new MemoryStream();
        stream.Write(Encoding.ASCII.GetBytes("!<arch>\n"), 0, 8);
        WriteArMember(stream, "debian-binary", Encoding.ASCII.GetBytes("2.0\n"));
        WriteArMember(stream, "control.tar.xz", new byte[] { 0 });
        WriteArMember(stream, "data.tar.xz", new byte[] { 0 });
        return stream.ToArray();
    }

    private static byte[] Vhd()
    {
        var bytes = new byte[512];
        Encoding.ASCII.GetBytes("conectix").CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 12, 0x00010000);
        WriteUInt32BigEndian(bytes, 60, 2);
        uint sum = 0;
        for (int i = 0; i < bytes.Length; i++) if (i < 64 || i >= 68) sum += bytes[i];
        WriteUInt32BigEndian(bytes, 64, ~sum);
        return bytes;
    }

    private static byte[] Vhdx()
    {
        var bytes = new byte[1024 * 1024];
        Encoding.ASCII.GetBytes("vhdxfile").CopyTo(bytes, 0);
        Encoding.ASCII.GetBytes("head").CopyTo(bytes, 64 * 1024);
        Encoding.ASCII.GetBytes("regi").CopyTo(bytes, 192 * 1024);
        return bytes;
    }

    private static void WriteArMember(Stream stream, string name, byte[] data)
    {
        string header = (name + "/").PadRight(16) + "0".PadRight(12) + "0".PadRight(6) + "0".PadRight(6) + "100644".PadRight(8) + data.Length.ToString(System.Globalization.CultureInfo.InvariantCulture).PadRight(10) + "`\n";
        byte[] headerBytes = Encoding.ASCII.GetBytes(header);
        Assert.Equal(60, headerBytes.Length);
        stream.Write(headerBytes, 0, headerBytes.Length);
        stream.Write(data, 0, data.Length);
        if ((data.Length & 1) != 0) stream.WriteByte((byte)'\n');
    }

    private static void WriteUInt16BigEndian(byte[] bytes, int offset, ushort value)
    {
        bytes[offset] = (byte)(value >> 8);
        bytes[offset + 1] = (byte)value;
    }

    private static void WriteUInt16LittleEndian(byte[] bytes, int offset, ushort value)
    {
        bytes[offset] = (byte)value;
        bytes[offset + 1] = (byte)(value >> 8);
    }

    private static void WriteUInt32BigEndian(byte[] bytes, int offset, uint value)
    {
        bytes[offset] = (byte)(value >> 24);
        bytes[offset + 1] = (byte)(value >> 16);
        bytes[offset + 2] = (byte)(value >> 8);
        bytes[offset + 3] = (byte)value;
    }

    private static void WriteUInt32LittleEndian(byte[] bytes, int offset, uint value)
    {
        bytes[offset] = (byte)value;
        bytes[offset + 1] = (byte)(value >> 8);
        bytes[offset + 2] = (byte)(value >> 16);
        bytes[offset + 3] = (byte)(value >> 24);
    }

    private static void WriteUInt64BigEndian(byte[] bytes, int offset, ulong value)
    {
        for (int i = 7; i >= 0; i--)
        {
            bytes[offset + i] = (byte)value;
            value >>= 8;
        }
    }
}
