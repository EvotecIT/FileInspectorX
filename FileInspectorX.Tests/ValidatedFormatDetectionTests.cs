using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class ValidatedFormatDetectionTests
{
    public static IEnumerable<object[]> ValidSamples()
    {
        yield return Sample("exe", TestHelpers.CreateMinimalPe(), 0x80, "Medium");
        yield return Sample("png", TestHelpers.CreateMinimalPng(), 12);
        yield return Sample("gif", Gif(), 6);
        yield return Sample("zip", TestHelpers.CreateEmptyZip(), 0);
        yield return Sample("ole2", Ole2(), 28);
        yield return Sample("pdf", Encoding.ASCII.GetBytes("%PDF-1.7\n"), 6);
        yield return Sample("jpg", TestHelpers.CreateMinimalJpeg(), 0);
        yield return Sample("bmp", Bmp(), 14);
        yield return Sample("gz", Gzip(), 2, "Medium");
        yield return Sample("bz2", new byte[] { 0x42, 0x5A, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59 }, 4, "Medium");
        yield return Sample("ogg", Ogg(), 4, "Medium");
        yield return Sample("mp3", Mp3(), 3, "Medium");
        yield return Sample("wasm", Wasm(), 4, "Medium");
        yield return Sample("pcap", Pcap(), 4);
        yield return Sample("pcapng", PcapNg(), 8, "Medium");
        yield return Sample("flac", Flac(), 7, "Medium");
        yield return Sample("crx", Crx(), 4, "Medium");
        yield return Sample("ico", Icon(), 2);
        yield return Sample("ttc", FontCollection(), 4);
        yield return Sample("rpm", Rpm(), 96, "Medium");
        yield return Sample("qcow2", Qcow2(), 0, "Medium");
        yield return Sample("mid", Midi(), 4);
        yield return Sample("dds", Dds(), 4);
        yield return Sample("qoi", Qoi(), 12);
        yield return Sample("dcm", Dicom(), 136, "Medium");
        yield return Sample("ndb", OutlookNdb(), 8, "Medium");
        yield return Sample("matroska", Matroska(), 6, "Medium");
        yield return Sample("parquet", Parquet(), 4);
        yield return Sample("arrow", Arrow(), 6);
        yield return Sample("deb", Deb(), 80);
        yield return Sample("vhd", Vhd(), 512);
        yield return Sample("vhdx", Vhdx(), 64 * 1024);
    }

    [Theory]
    [MemberData(nameof(ValidSamples))]
    public void StructurallyValidatedFormatsHaveParityAcrossBytesStreamAndPath(string extension, byte[] bytes, int _, string expectedConfidence)
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
            Assert.Equal(expectedConfidence, fromBytes?.Confidence);
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
    public void StructuralNearMissesDoNotRetainTheClaimedFormat(string extension, byte[] bytes, int mutationOffset, string _)
    {
        var mutated = (byte[])bytes.Clone();
        mutated[mutationOffset] ^= 0x01;

        Assert.NotEqual(extension, FileInspector.Detect(mutated)?.Extension);
    }

    [Theory]
    [MemberData(nameof(ValidSamples))]
    public void TruncationBeforeDecisiveStructureDoesNotRetainTheClaimedFormat(string extension, byte[] bytes, int decisiveOffset, string _)
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

    private static object[] Sample(string extension, byte[] bytes, int mutationOffset, string confidence = "High")
        => new object[] { extension, bytes, mutationOffset, confidence };

    private static byte[] Bmp()
    {
        var bytes = new byte[30];
        bytes[0] = (byte)'B'; bytes[1] = (byte)'M';
        WriteUInt32LittleEndian(bytes, 2, 30);
        WriteUInt32LittleEndian(bytes, 10, 26);
        WriteUInt32LittleEndian(bytes, 14, 12);
        WriteUInt16LittleEndian(bytes, 18, 1);
        WriteUInt16LittleEndian(bytes, 20, 1);
        WriteUInt16LittleEndian(bytes, 22, 1);
        WriteUInt16LittleEndian(bytes, 24, 24);
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

    private static byte[] Gzip() => TestHelpers.CreateMinimalGzip();

    private static byte[] Ogg()
    {
        return TestHelpers.CreateMinimalOgg();
    }

    private static byte[] Mp3()
    {
        return TestHelpers.CreateMinimalMp3();
    }

    private static byte[] Wasm()
        => new byte[] { 0, 0x61, 0x73, 0x6D, 1, 0, 0, 0 };

    private static byte[] Pcap()
    {
        var bytes = new byte[24];
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
        bytes[4] = 0x80;
        bytes[7] = 34;
        WriteUInt16BigEndian(bytes, 8, 16);
        WriteUInt16BigEndian(bytes, 10, 16);
        bytes[18] = 0x0A; bytes[19] = 0xC4; bytes[20] = 0x42; bytes[21] = 0xF0; bytes[25] = 1;
        return bytes;
    }

    private static byte[] Crx() => TestHelpers.CreateMinimalCrx3();

    private static byte[] Icon()
    {
        byte[] png = TestHelpers.CreateMinimalPng();
        var bytes = new byte[22 + png.Length];
        WriteUInt16LittleEndian(bytes, 2, 1);
        WriteUInt16LittleEndian(bytes, 4, 1);
        bytes[6] = 1; bytes[7] = 1;
        WriteUInt16LittleEndian(bytes, 10, 1);
        WriteUInt16LittleEndian(bytes, 12, 32);
        WriteUInt32LittleEndian(bytes, 14, (uint)png.Length);
        WriteUInt32LittleEndian(bytes, 18, 22);
        png.CopyTo(bytes, 22);
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
        var bytes = new byte[174];
        new byte[] { 0xED, 0xAB, 0xEE, 0xDB, 3, 0 }.CopyTo(bytes, 0);
        WriteUInt16BigEndian(bytes, 78, 5);
        new byte[] { 0x8E, 0xAD, 0xE8, 1 }.CopyTo(bytes, 96);
        WriteUInt32BigEndian(bytes, 104, 1);
        WriteUInt32BigEndian(bytes, 108, 1);
        WriteUInt32BigEndian(bytes, 112, 1000);
        WriteUInt32BigEndian(bytes, 116, 7);
        WriteUInt32BigEndian(bytes, 124, 1);
        new byte[] { 0x8E, 0xAD, 0xE8, 1 }.CopyTo(bytes, 136);
        WriteUInt32BigEndian(bytes, 144, 1);
        WriteUInt32BigEndian(bytes, 148, 1);
        WriteUInt32BigEndian(bytes, 152, 1000);
        WriteUInt32BigEndian(bytes, 156, 7);
        WriteUInt32BigEndian(bytes, 164, 1);
        new byte[] { 0x1F, 0x8B, 8, 0, 0 }.CopyTo(bytes, 169);
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
        var bytes = new byte[132];
        Encoding.ASCII.GetBytes("DDS ").CopyTo(bytes, 0);
        WriteUInt32LittleEndian(bytes, 4, 124);
        WriteUInt32LittleEndian(bytes, 8, 0x1007);
        WriteUInt32LittleEndian(bytes, 12, 1);
        WriteUInt32LittleEndian(bytes, 16, 1);
        WriteUInt32LittleEndian(bytes, 76, 32);
        WriteUInt32LittleEndian(bytes, 80, 0x41);
        WriteUInt32LittleEndian(bytes, 88, 32);
        WriteUInt32LittleEndian(bytes, 92, 0x00FF0000);
        WriteUInt32LittleEndian(bytes, 96, 0x0000FF00);
        WriteUInt32LittleEndian(bytes, 100, 0x000000FF);
        WriteUInt32LittleEndian(bytes, 104, 0xFF000000);
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

    private static byte[] Dicom() => TestHelpers.CreateMinimalDicom();

    private static byte[] OutlookNdb() => TestHelpers.CreateMinimalOutlookNdb();

    private static byte[] Matroska() => TestHelpers.CreateMinimalMatroska();

    private static byte[] Parquet() => TestHelpers.CreateMinimalParquet();

    private static byte[] Arrow() => TestHelpers.CreateMinimalArrow();

    private static byte[] Deb() => TestHelpers.CreateMinimalDeb();

    private static byte[] Vhd() => TestHelpers.CreateMinimalVhd();

    private static byte[] Vhdx() => TestHelpers.CreateMinimalVhdx();

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
