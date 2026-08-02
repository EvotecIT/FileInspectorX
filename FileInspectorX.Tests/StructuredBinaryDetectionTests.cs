using Xunit;

namespace FileInspectorX.Tests;

public sealed class StructuredBinaryDetectionTests
{
    public static IEnumerable<object[]> ValidSamples()
    {
        yield return Sample("lnk", ShellLink());
        yield return Sample("class", JavaClass());
        yield return Sample("dex", Dex());
        yield return Sample("dex", ReverseEndianDex());
        yield return Sample("macho", ThinMachO());
        yield return Sample("ttf", TrueType());
        yield return Sample("otf", OpenType());
        yield return Sample("woff", Woff());
        yield return Sample("woff2", Woff2());
        yield return Sample("h5", Hdf5(0));
        yield return Sample("nc", NetCdf());
        yield return Sample("nc", NetCdf(version: 2));
        yield return Sample("nc", NetCdf5());
        yield return Sample("exr", OpenExr());
        yield return Sample("exr", DeepOpenExr());
        yield return Sample("psd", Photoshop(version: 1));
        yield return Sample("psb", Photoshop(version: 2));
        yield return Sample("jp2", Jpeg2000("jp2 "));
        yield return Sample("jpx", Jpeg2000("jpx "));
        yield return Sample("jpm", Jpeg2000("jpm "));
        yield return Sample("mj2", Jpeg2000("mjp2"));
    }

    [Theory]
    [MemberData(nameof(ValidSamples))]
    public void DetectsStructurallyValidHeaders(string extension, byte[] bytes)
    {
        var result = FileInspector.Detect(bytes);

        Assert.NotNull(result);
        Assert.Equal(extension, result!.Extension);
        Assert.Equal(extension is "class" or "ttf" or "otf" or "woff" or "woff2" or "exr" or "mj2" or "macho" or "h5" ? "Medium" : "High", result.Confidence);
    }

    [Fact]
    public void JavaClassWinsSharedCafeBabeMagicWhileIncompletePrefixDoesNotMatch()
    {
        Assert.Equal("class", FileInspector.Detect(JavaClass())?.Extension);
        Assert.NotEqual("macho", FileInspector.Detect(new byte[] { 0xCA, 0xFE, 0xBA, 0xBE })?.Extension);
        Assert.NotEqual("class", FileInspector.Detect(new byte[] { 0xCA, 0xFE, 0xBA, 0xBE })?.Extension);
        Assert.Equal("macho", FileInspector.Detect(FatMachO())?.Extension);
    }

    [Fact]
    public void RejectsHeadersWhoseRequiredStructureIsInvalid()
    {
        var badLink = ShellLink();
        badLink[19] ^= 0x01;
        AssertNotDetectedAs("lnk", badLink);

        var badJava = JavaClass();
        badJava[10] = 2;
        AssertNotDetectedAs("class", badJava);
        AssertNotDetectedAs("macho", badJava);

        var badDex = Dex();
        WriteUInt32LittleEndian(badDex, 40, 0x11111111);
        AssertNotDetectedAs("dex", badDex);

        var badMach = ThinMachO();
        WriteUInt32LittleEndian(badMach, 12, 99);
        AssertNotDetectedAs("macho", badMach);

        var badFont = TrueType();
        WriteUInt16BigEndian(badFont, 6, 32);
        AssertNotDetectedAs("ttf", badFont);

        var badWoff = Woff();
        WriteUInt16BigEndian(badWoff, 14, 1);
        AssertNotDetectedAs("woff", badWoff);

        var badNetCdf = NetCdf();
        WriteUInt32BigEndian(badNetCdf, 8, 11);
        AssertNotDetectedAs("nc", badNetCdf);
        AssertNotDetectedAs("nc", NetCdf5().Take(23).ToArray());

        var badTiledMultipartExr = OpenExr();
        badTiledMultipartExr[5] = 0x12;
        AssertNotDetectedAs("exr", badTiledMultipartExr);

        var badPhotoshop = Photoshop(version: 1);
        badPhotoshop[6] = 1;
        AssertNotDetectedAs("psd", badPhotoshop);

        var badPhotoshopColorMode = Photoshop(version: 1);
        WriteUInt16BigEndian(badPhotoshopColorMode, 24, 6);
        AssertNotDetectedAs("psd", badPhotoshopColorMode);

        var badJpeg2000 = Jpeg2000("jp2 ");
        badJpeg2000[28] = (byte)'x';
        AssertNotDetectedAs("jp2", badJpeg2000);
    }

    [Fact]
    public void RejectsTruncatedStructuredHeaders()
    {
        foreach (var row in ValidSamples())
        {
            string extension = (string)row[0];
            byte[] sample = (byte[])row[1];
            int length = Math.Min(sample.Length - 1, RequiredHeaderLength(extension) - 1);
            AssertNotDetectedAs(extension, sample.Take(length).ToArray());
        }
    }

    [Fact]
    public void DetectsHdf5AfterPowerOfTwoUserBlockAndRestoresStreamPosition()
    {
        var bytes = Hdf5(4096);
        using var stream = new MemoryStream(bytes, writable: false);
        stream.Position = 37;

        var result = FileInspector.Detect(stream);

        Assert.Equal("h5", result?.Extension);
        Assert.Equal("hdf5:signature@4096;modern-root-not-fully-validated", result?.Reason);
        Assert.Equal(37, stream.Position);
    }

    [Fact]
    public void Hdf5UserBlockContentDoesNotOverrideContainerAcrossOverloads()
    {
        var bytes = Hdf5(8192);
        System.Text.Encoding.ASCII.GetBytes("%PDF-1.7\n").CopyTo(bytes, 0);

        using var stream = new MemoryStream(bytes, writable: false);
        stream.Position = 19;
        var fromStream = FileInspector.Detect(stream);
        var fromBytes = FileInspector.Detect(bytes);

        Assert.Equal("h5", fromStream?.Extension);
        Assert.Equal("h5", fromBytes?.Extension);
        Assert.Equal(fromBytes?.Reason, fromStream?.Reason);
        Assert.Equal(19, stream.Position);
    }

    [Fact]
    public void Hdf5UserBlockContentDoesNotOverrideContainerForPathDetection()
    {
        var bytes = Hdf5(8192);
        System.Text.Encoding.ASCII.GetBytes("%PDF-1.7\n").CopyTo(bytes, 0);
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".pdf");
        try
        {
            File.WriteAllBytes(path, bytes);

            var result = FileInspector.Detect(path);

            Assert.Equal("h5", result?.Extension);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void Hdf5SignatureWithoutAValidSuperblockDoesNotOverridePdf()
    {
        var bytes = new byte[1024];
        System.Text.Encoding.ASCII.GetBytes("%PDF-1.7\n").CopyTo(bytes, 0);
        new byte[] { 0x89, (byte)'H', (byte)'D', (byte)'F', 0x0D, 0x0A, 0x1A, 0x0A }.CopyTo(bytes, 512);
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".pdf");
        try
        {
            File.WriteAllBytes(path, bytes);
            Assert.Equal("pdf", FileInspector.Detect(bytes)?.Extension);
            Assert.Equal("pdf", FileInspector.Detect(path)?.Extension);
        }
        finally
        {
            TestHelpers.SafeDelete(path);
        }
    }

    [Theory]
    [InlineData((byte)0)]
    [InlineData((byte)1)]
    [InlineData((byte)2)]
    [InlineData((byte)3)]
    public void Hdf5SupportedSuperblockVersionsAreValidated(byte version)
        => Assert.Equal("h5", FileInspector.Detect(Hdf5(0, version))?.Extension);

    [Fact]
    public void Hdf5ModernSuperblockRequiresItsChecksum()
    {
        var bytes = Hdf5(0, 3);
        bytes[44] ^= 0x01;

        AssertNotDetectedAs("h5", bytes);
    }

    [Fact]
    public void FatMachOMemberMustFitInsideTheCompleteFile()
    {
        var truncated = FatMachO().Take(28).ToArray();

        AssertNotDetectedAs("macho", truncated);
    }

    [Fact]
    public void FatMachOUsesCompleteLengthAcrossDetectionApis()
    {
        var bytes = FatMachO();
        using var stream = new MemoryStream(bytes, writable: false);
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".bin");
        try
        {
            File.WriteAllBytes(path, bytes);
            Assert.Equal("macho", FileInspector.Detect(bytes)?.Extension);
            Assert.Equal("macho", FileInspector.Detect(stream)?.Extension);
            Assert.Equal("macho", FileInspector.Detect(path)?.Extension);
        }
        finally
        {
            TestHelpers.SafeDelete(path);
        }
    }

    [Fact]
    public void ReverseEndianDexIsReportedExplicitly()
    {
        var result = FileInspector.Detect(ReverseEndianDex());

        Assert.Equal("dex", result?.Extension);
        Assert.Equal("dex:035:reverse-endian", result?.Reason);
    }

    [Fact]
    public void ShellLinkDetectionIgnoresBenignDeclaredExtensionAndReportsMismatch()
    {
        var result = FileInspector.Detect(ShellLink(), declaredExtension: "txt");
        var comparison = FileInspector.CompareDeclared("txt", result);

        Assert.Equal("lnk", result?.Extension);
        Assert.True(result?.IsDangerous);
        Assert.True(comparison.Mismatch);
    }

    [Fact]
    public void Hdf5ExtensionAliasesDoNotCreateFalseMismatch()
    {
        var result = FileInspector.Detect(Hdf5(0));

        Assert.False(FileInspector.CompareDeclared("hdf5", result).Mismatch);
        Assert.False(FileInspector.CompareDeclared("h5", result).Mismatch);
    }

    private static object[] Sample(string extension, byte[] bytes) => new object[] { extension, bytes };

    private static void AssertNotDetectedAs(string extension, byte[] bytes)
        => Assert.NotEqual(extension, FileInspector.Detect(bytes)?.Extension);

    private static int RequiredHeaderLength(string extension) => extension switch
    {
        "lnk" => 80,
        "class" => 11,
        "dex" => 112,
        "macho" => 32,
        "ttf" or "otf" => 28,
        "woff" => 44,
        "woff2" => 48,
        "h5" => 48,
        "nc" => 16,
        "exr" => 8,
        "psd" or "psb" => 26,
        "jp2" or "jpx" or "jpm" or "mj2" => 32,
        _ => throw new ArgumentOutOfRangeException(nameof(extension))
    };

    private static byte[] ShellLink()
    {
        var bytes = new byte[80];
        bytes[0] = 0x4C;
        new byte[] {
            0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
        }.CopyTo(bytes, 4);
        WriteUInt32LittleEndian(bytes, 60, 1);
        return bytes;
    }

    private static byte[] JavaClass() => new byte[]
    {
        0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34, 0x00, 0x05,
        0x01, 0x00, 0x04, (byte)'T', (byte)'e', (byte)'s', (byte)'t',
        0x07, 0x00, 0x01,
        0x01, 0x00, 0x10, (byte)'j', (byte)'a', (byte)'v', (byte)'a', (byte)'/',
        (byte)'l', (byte)'a', (byte)'n', (byte)'g', (byte)'/', (byte)'O', (byte)'b',
        (byte)'j', (byte)'e', (byte)'c', (byte)'t',
        0x07, 0x00, 0x03,
        0x00, 0x21, 0x00, 0x02, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    private static byte[] Dex() => TestHelpers.CreateMinimalDex();

    private static byte[] ReverseEndianDex() => TestHelpers.CreateMinimalDex(reverseEndian: true);

    private static byte[] ThinMachO()
    {
        var bytes = new byte[32];
        new byte[] { 0xCF, 0xFA, 0xED, 0xFE }.CopyTo(bytes, 0);
        WriteUInt32LittleEndian(bytes, 4, 0x01000007);
        WriteUInt32LittleEndian(bytes, 8, 3);
        WriteUInt32LittleEndian(bytes, 12, 1);
        return bytes;
    }

    private static byte[] FatMachO()
    {
        var bytes = new byte[4096 + 32];
        new byte[] { 0xCA, 0xFE, 0xBA, 0xBE }.CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 4, 1);
        WriteUInt32BigEndian(bytes, 8, 0x01000007);
        WriteUInt32BigEndian(bytes, 12, 3);
        WriteUInt32BigEndian(bytes, 16, 4096);
        WriteUInt32BigEndian(bytes, 20, 32);
        WriteUInt32BigEndian(bytes, 24, 12);
        new byte[] { 0xCF, 0xFA, 0xED, 0xFE }.CopyTo(bytes, 4096);
        WriteUInt32LittleEndian(bytes, 4100, 0x01000007);
        WriteUInt32LittleEndian(bytes, 4104, 3);
        WriteUInt32LittleEndian(bytes, 4108, 1);
        return bytes;
    }

    private static byte[] TrueType() => Sfnt(0x00010000);

    private static byte[] OpenType() => Sfnt(0x4F54544F);

    private static byte[] Sfnt(uint flavor)
    {
        var bytes = new byte[29];
        WriteUInt32BigEndian(bytes, 0, flavor);
        WriteUInt16BigEndian(bytes, 4, 1);
        WriteUInt16BigEndian(bytes, 6, 16);
        new byte[] { (byte)'h', (byte)'e', (byte)'a', (byte)'d' }.CopyTo(bytes, 12);
        WriteUInt32BigEndian(bytes, 20, 28);
        WriteUInt32BigEndian(bytes, 24, 1);
        return bytes;
    }

    private static byte[] Woff()
    {
        var bytes = new byte[68];
        new byte[] { (byte)'w', (byte)'O', (byte)'F', (byte)'F' }.CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 4, 0x00010000);
        WriteUInt32BigEndian(bytes, 8, (uint)bytes.Length);
        WriteUInt16BigEndian(bytes, 12, 1);
        WriteUInt32BigEndian(bytes, 16, 32);
        new byte[] { (byte)'h', (byte)'e', (byte)'a', (byte)'d' }.CopyTo(bytes, 44);
        WriteUInt32BigEndian(bytes, 48, 64);
        WriteUInt32BigEndian(bytes, 52, 1);
        WriteUInt32BigEndian(bytes, 56, 1);
        return bytes;
    }

    private static byte[] Woff2()
    {
        var bytes = new byte[52];
        new byte[] { (byte)'w', (byte)'O', (byte)'F', (byte)'2' }.CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 4, 0x4F54544F);
        WriteUInt32BigEndian(bytes, 8, (uint)bytes.Length);
        WriteUInt16BigEndian(bytes, 12, 1);
        WriteUInt32BigEndian(bytes, 16, 32);
        WriteUInt32BigEndian(bytes, 20, 2);
        bytes[48] = 0;
        bytes[49] = 1;
        return bytes;
    }

    private static byte[] Hdf5(int offset, byte version = 2)
    {
        var bytes = new byte[offset + 128];
        new byte[] { 0x89, (byte)'H', (byte)'D', (byte)'F', 0x0D, 0x0A, 0x1A, 0x0A }.CopyTo(bytes, offset);
        bytes[offset + 8] = version;
        if (version is 0 or 1)
        {
            bytes[offset + 13] = 8;
            bytes[offset + 14] = 8;
            WriteUInt16LittleEndian(bytes, offset + 16, 4);
            WriteUInt16LittleEndian(bytes, offset + 18, 16);
            int cursor = offset + 24;
            if (version == 1)
            {
                WriteUInt16LittleEndian(bytes, offset + 24, 32);
                cursor = offset + 28;
            }
            WriteUInt64LittleEndian(bytes, cursor, (ulong)offset);
            for (int i = cursor + 8; i < cursor + 16; i++) bytes[i] = 0xFF;
            WriteUInt64LittleEndian(bytes, cursor + 16, (ulong)(bytes.Length - offset));
            for (int i = cursor + 24; i < cursor + 32; i++) bytes[i] = 0xFF;
            WriteUInt64LittleEndian(bytes, cursor + 40, 112);
        }
        else
        {
            bytes[offset + 9] = 8;
            bytes[offset + 10] = 8;
            WriteUInt64LittleEndian(bytes, offset + 12, (ulong)offset);
            for (int i = offset + 20; i < offset + 28; i++) bytes[i] = 0xFF;
            WriteUInt64LittleEndian(bytes, offset + 28, (ulong)(bytes.Length - offset));
            WriteUInt64LittleEndian(bytes, offset + 36, 48);
            WriteUInt32LittleEndian(bytes, offset + 44,
                ComputeHdf5SuperblockChecksum(new ReadOnlySpan<byte>(bytes, offset, 44)));
            System.Text.Encoding.ASCII.GetBytes("OHDR").CopyTo(bytes, offset + 48);
            bytes[offset + 52] = 2;
        }
        return bytes;
    }

    private static byte[] NetCdf(byte version = 1)
    {
        var bytes = new byte[32];
        new byte[] { (byte)'C', (byte)'D', (byte)'F', version }.CopyTo(bytes, 0);
        return bytes;
    }

    private static byte[] NetCdf5()
    {
        var bytes = new byte[48];
        new byte[] { (byte)'C', (byte)'D', (byte)'F', 5 }.CopyTo(bytes, 0);
        return bytes;
    }

    private static byte[] OpenExr() => TestHelpers.CreateMinimalOpenExr();

    private static byte[] DeepOpenExr() => TestHelpers.CreateMinimalOpenExr(0x00000800);

    private static byte[] Photoshop(ushort version) => TestHelpers.CreateMinimalPhotoshop(version);

    private static byte[] Jpeg2000(string brand) => TestHelpers.CreateMinimalJpeg2000(brand);

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

    private static void WriteUInt32LittleEndian(byte[] bytes, int offset, uint value)
    {
        bytes[offset] = (byte)value;
        bytes[offset + 1] = (byte)(value >> 8);
        bytes[offset + 2] = (byte)(value >> 16);
        bytes[offset + 3] = (byte)(value >> 24);
    }

    private static void WriteUInt16LittleEndian(byte[] bytes, int offset, ushort value)
    {
        bytes[offset] = (byte)value;
        bytes[offset + 1] = (byte)(value >> 8);
    }

    private static void WriteUInt64LittleEndian(byte[] bytes, int offset, ulong value)
    {
        for (int i = 0; i < 8; i++) bytes[offset + i] = (byte)(value >> (i * 8));
    }

    private static uint ReadUInt32LittleEndian(ReadOnlySpan<byte> bytes, int offset)
        => (uint)(bytes[offset] |
                  (bytes[offset + 1] << 8) |
                  (bytes[offset + 2] << 16) |
                  (bytes[offset + 3] << 24));

    private static uint ComputeHdf5SuperblockChecksum(ReadOnlySpan<byte> src)
    {
        unchecked
        {
            uint a = 0xDEADBEEF + (uint)src.Length;
            uint b = a;
            uint c = a;
            int cursor = 0;
            int remaining = src.Length;
            while (remaining > 12)
            {
                a += ReadUInt32LittleEndian(src, cursor);
                b += ReadUInt32LittleEndian(src, cursor + 4);
                c += ReadUInt32LittleEndian(src, cursor + 8);
                MixHdf5Checksum(ref a, ref b, ref c);
                cursor += 12;
                remaining -= 12;
            }
            switch (remaining)
            {
                case 12: c += (uint)src[cursor + 11] << 24; goto case 11;
                case 11: c += (uint)src[cursor + 10] << 16; goto case 10;
                case 10: c += (uint)src[cursor + 9] << 8; goto case 9;
                case 9: c += src[cursor + 8]; goto case 8;
                case 8: b += (uint)src[cursor + 7] << 24; goto case 7;
                case 7: b += (uint)src[cursor + 6] << 16; goto case 6;
                case 6: b += (uint)src[cursor + 5] << 8; goto case 5;
                case 5: b += src[cursor + 4]; goto case 4;
                case 4: a += (uint)src[cursor + 3] << 24; goto case 3;
                case 3: a += (uint)src[cursor + 2] << 16; goto case 2;
                case 2: a += (uint)src[cursor + 1] << 8; goto case 1;
                case 1: a += src[cursor]; break;
                case 0: return c;
            }
            FinalizeHdf5Checksum(ref a, ref b, ref c);
            return c;
        }
    }

    private static void MixHdf5Checksum(ref uint a, ref uint b, ref uint c)
    {
        unchecked
        {
            a -= c; a ^= RotateLeft(c, 4); c += b;
            b -= a; b ^= RotateLeft(a, 6); a += c;
            c -= b; c ^= RotateLeft(b, 8); b += a;
            a -= c; a ^= RotateLeft(c, 16); c += b;
            b -= a; b ^= RotateLeft(a, 19); a += c;
            c -= b; c ^= RotateLeft(b, 4); b += a;
        }
    }

    private static void FinalizeHdf5Checksum(ref uint a, ref uint b, ref uint c)
    {
        unchecked
        {
            c ^= b; c -= RotateLeft(b, 14);
            a ^= c; a -= RotateLeft(c, 11);
            b ^= a; b -= RotateLeft(a, 25);
            c ^= b; c -= RotateLeft(b, 16);
            a ^= c; a -= RotateLeft(c, 4);
            b ^= a; b -= RotateLeft(a, 14);
            c ^= b; c -= RotateLeft(b, 24);
        }
    }

    private static uint RotateLeft(uint value, int count) => (value << count) | (value >> (32 - count));
}
