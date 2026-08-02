using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

[Collection(nameof(DetectionSettingsCollection))]
public sealed class FifteenthReviewRegressionTests
{
    [Fact]
    public void MatroskaRootVoidScanHonorsTheDetectionBudget()
    {
        byte[] bytes = MatroskaWithRootVoids(4);
        int originalBudget = Settings.DetectionReadBudgetBytes;
        try
        {
            Settings.DetectionReadBudgetBytes = 128;
            var fromBytes = FileInspector.Detect(bytes);
            using var stream = new MemoryStream(bytes, writable: false);
            var fromStream = FileInspector.Detect(stream);
            Assert.Equal("matroska", fromBytes?.Extension);
            Assert.Equal("Medium", fromBytes?.Confidence);
            Assert.Contains("root-scan-budget", fromBytes?.Reason);
            Assert.Equal(fromBytes?.Reason, fromStream?.Reason);
        }
        finally
        {
            Settings.DetectionReadBudgetBytes = originalBudget;
        }
    }

    [Theory]
    [InlineData(13u)]
    [InlineData(14u)]
    public void MachOAcceptsDefinedGpuFileTypes(uint fileType)
        => AssertParity(ThinMachO(fileType), "macho", "High");

    [Fact]
    public void EvtxValidatesEveryDeclaredChunkHeader()
    {
        byte[] valid = Evtx(chunkCount: 2);
        AssertParity(valid, "evtx", "High");
        valid[4096 + 65536] = 0;
        AssertNotDetectedAs(valid, "evtx");
    }

    [Fact]
    public void JavaRejectsUndefinedModernMinorVersions()
    {
        byte[] valid = JavaClass();
        valid[4] = 0xFF;
        valid[5] = 0xFF;
        valid[6] = 0;
        valid[7] = 56;
        AssertParity(valid, "class", "High");

        valid[4] = 0;
        valid[5] = 1;
        AssertNotDetectedAs(valid, "class");
    }

    [Fact]
    public void MinidumpBoundsEveryStreamPayload()
    {
        byte[] valid = Minidump();
        AssertParity(valid, "dmp", "High");
        WriteUInt32LittleEndian(valid, 40, 60);
        AssertNotDetectedAs(valid, "dmp");
    }

    [Fact]
    public void GlbVersionTwoRequiresCompleteTrailingChunkFraming()
    {
        byte[] valid = GlbWithBinaryChunk();
        AssertParity(valid, "glb", "High");

        Array.Resize(ref valid, valid.Length + 4);
        WriteUInt32LittleEndian(valid, 8, (uint)valid.Length);
        AssertNotDetectedAs(valid, "glb");
    }

    [Fact]
    public void RegistryHiveRequiresItsDeclaredHiveBinArea()
    {
        byte[] valid = RegistryHive();
        AssertParity(valid, "hive", "High");

        Array.Resize(ref valid, 4096);
        AssertNotDetectedAs(valid, "hive");
    }

    private static void AssertParity(byte[] bytes, string extension, string confidence)
    {
        Assert.Equal(extension, FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false);
        var fromStream = FileInspector.Detect(stream);
        Assert.Equal(extension, fromStream?.Extension);
        Assert.Equal(confidence, fromStream?.Confidence);
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

    private static void AssertNotDetectedAs(byte[] bytes, string extension)
    {
        Assert.NotEqual(extension, FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false);
        Assert.NotEqual(extension, FileInspector.Detect(stream)?.Extension);
    }

    private static byte[] MatroskaWithRootVoids(int count)
    {
        byte[] minimal = TestHelpers.CreateMinimalMatroska();
        const int segmentOffset = 16;
        var bytes = new byte[minimal.Length + count * 2];
        Array.Copy(minimal, 0, bytes, 0, segmentOffset);
        for (int index = 0; index < count; index++)
        {
            bytes[segmentOffset + index * 2] = 0xEC;
            bytes[segmentOffset + index * 2 + 1] = 0x80;
        }
        Array.Copy(minimal, segmentOffset, bytes, segmentOffset + count * 2, minimal.Length - segmentOffset);
        return bytes;
    }

    private static byte[] ThinMachO(uint fileType)
    {
        var bytes = new byte[40];
        WriteUInt32LittleEndian(bytes, 0, 0xFEEDFACF);
        WriteUInt32LittleEndian(bytes, 4, 0x01000007);
        WriteUInt32LittleEndian(bytes, 12, fileType);
        WriteUInt32LittleEndian(bytes, 16, 1);
        WriteUInt32LittleEndian(bytes, 20, 8);
        WriteUInt32LittleEndian(bytes, 32, 1);
        WriteUInt32LittleEndian(bytes, 36, 8);
        return bytes;
    }

    private static byte[] Evtx(ushort chunkCount)
    {
        var bytes = new byte[4096 + chunkCount * 65536];
        Encoding.ASCII.GetBytes("ElfFile\0").CopyTo(bytes, 0);
        WriteUInt32LittleEndian(bytes, 0x20, 128);
        WriteUInt16LittleEndian(bytes, 0x24, 1);
        WriteUInt16LittleEndian(bytes, 0x26, 3);
        WriteUInt16LittleEndian(bytes, 0x28, 4096);
        WriteUInt16LittleEndian(bytes, 0x2A, chunkCount);
        for (int index = 0; index < chunkCount; index++)
            Encoding.ASCII.GetBytes("ElfChnk\0").CopyTo(bytes, 4096 + index * 65536);
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

    private static byte[] Minidump()
    {
        var bytes = new byte[56];
        Encoding.ASCII.GetBytes("MDMP").CopyTo(bytes, 0);
        WriteUInt32LittleEndian(bytes, 4, 0xA793);
        WriteUInt32LittleEndian(bytes, 8, 1);
        WriteUInt32LittleEndian(bytes, 12, 32);
        WriteUInt32LittleEndian(bytes, 32, 7);
        WriteUInt32LittleEndian(bytes, 36, 12);
        WriteUInt32LittleEndian(bytes, 40, 44);
        return bytes;
    }

    private static byte[] GlbWithBinaryChunk()
    {
        var bytes = new byte[36];
        Encoding.ASCII.GetBytes("glTF").CopyTo(bytes, 0);
        WriteUInt32LittleEndian(bytes, 4, 2);
        WriteUInt32LittleEndian(bytes, 8, (uint)bytes.Length);
        WriteUInt32LittleEndian(bytes, 12, 4);
        WriteUInt32LittleEndian(bytes, 16, 0x4E4F534A);
        Encoding.ASCII.GetBytes("{}  ").CopyTo(bytes, 20);
        WriteUInt32LittleEndian(bytes, 24, 4);
        WriteUInt32LittleEndian(bytes, 28, 0x004E4942);
        return bytes;
    }

    private static byte[] RegistryHive()
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
        uint checksum = 0;
        for (int offset = 0; offset < 0x1FC; offset += 4) checksum ^= ReadUInt32LittleEndian(bytes, offset);
        if (checksum == 0) checksum = 1;
        else if (checksum == uint.MaxValue) checksum = 0xFFFFFFFE;
        WriteUInt32LittleEndian(bytes, 0x1FC, checksum);
        return bytes;
    }

    private static uint ReadUInt32LittleEndian(byte[] bytes, int offset)
        => (uint)(bytes[offset] | bytes[offset + 1] << 8 | bytes[offset + 2] << 16 | bytes[offset + 3] << 24);

    private static void WriteUInt16LittleEndian(byte[] bytes, int offset, ushort value)
    {
        bytes[offset] = (byte)value;
        bytes[offset + 1] = (byte)(value >> 8);
    }

    private static void WriteUInt32LittleEndian(byte[] bytes, int offset, uint value)
    {
        bytes[offset] = (byte)value;
        bytes[offset + 1] = (byte)(value >> 8);
        bytes[offset + 2] = (byte)(value >> 16);
        bytes[offset + 3] = (byte)(value >> 24);
    }
}
