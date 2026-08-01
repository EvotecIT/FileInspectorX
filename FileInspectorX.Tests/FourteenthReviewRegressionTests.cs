using System;
using System.IO;
using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class FourteenthReviewRegressionTests
{
    [Fact]
    public void MachORecognizesFat64ArchitectureDirectories()
    {
        var bytes = FatMachO64();
        AssertParity(bytes, "macho");
    }

    [Fact]
    public void ThinMachORequiresEveryLoadCommandToAdvanceValidly()
    {
        var valid = ThinMachOWithCommand();
        AssertParity(valid, "macho");

        var invalid = (byte[])valid.Clone();
        Array.Clear(invalid, 32, 8);
        Assert.NotEqual("macho", FileInspector.Detect(invalid)?.Extension);
    }

    [Fact]
    public void ZipLocalHeadersBoundDeclaredAndZip64Payloads()
    {
        AssertParity(ZipLocal(zip64: false), "zip");
        AssertParity(ZipLocal(zip64: true), "zip");

        byte[] truncated = ZipLocal(zip64: false);
        Array.Resize(ref truncated, truncated.Length - 1);
        Assert.NotEqual("zip", FileInspector.Detect(truncated)?.Extension);

        byte[] truncatedZip64 = ZipLocal(zip64: true);
        Array.Resize(ref truncatedZip64, truncatedZip64.Length - 1);
        Assert.NotEqual("zip", FileInspector.Detect(truncatedZip64)?.Extension);
    }

    [Fact]
    public void DebianPackagesRequireRealTarFramingOrCompressionSignatures()
    {
        AssertParity(TestHelpers.CreateMinimalDeb(), "deb");
        Assert.NotEqual("deb", FileInspector.Detect(FakeDeb())?.Extension);
    }

    [Fact]
    public void FixedVhdRequiresPayloadAndMandatoryFooterFields()
    {
        var valid = TestHelpers.CreateMinimalVhd();
        AssertParity(valid, "vhd");
        Assert.NotEqual("vhd", FileInspector.Detect(new ReadOnlySpan<byte>(valid, 512, 512))?.Extension);

        var missingId = (byte[])valid.Clone();
        Array.Clear(missingId, 512 + 68, 16);
        FinalizeVhdFooter(missingId, 512);
        Assert.NotEqual("vhd", FileInspector.Detect(missingId)?.Extension);

        var missingDynamicHeader = (byte[])valid.Clone();
        WriteUInt32BigEndian(missingDynamicHeader, 512 + 60, 3);
        WriteUInt64BigEndian(missingDynamicHeader, 512 + 16, 512);
        FinalizeVhdFooter(missingDynamicHeader, 512);
        Assert.NotEqual("vhd", FileInspector.Detect(missingDynamicHeader)?.Extension);
    }

    [Fact]
    public void BmpBoundsItsDeclaredFileSize()
    {
        var valid = MinimalBmp();
        AssertParity(valid, "bmp");

        var invalid = (byte[])valid.Clone();
        WriteUInt32LittleEndian(invalid, 2, 100);
        Assert.NotEqual("bmp", FileInspector.Detect(invalid)?.Extension);
    }

    [Fact]
    public void MatroskaRequiresTheSegmentSizeVint()
    {
        var valid = TestHelpers.CreateMinimalMatroska();
        AssertParity(valid, "matroska");
        Array.Resize(ref valid, valid.Length - 1);
        Assert.NotEqual("matroska", FileInspector.Detect(valid)?.Extension);
    }

    [Fact]
    public void NetCdfBoundsNonRecordAndRecordVariableData()
    {
        AssertParity(NetCdfVariable(record: false, includeAllData: true), "nc");
        Assert.NotEqual("nc", FileInspector.Detect(NetCdfVariable(record: false, includeAllData: false))?.Extension);
        AssertParity(NetCdfVariable(record: true, includeAllData: true), "nc");
        Assert.NotEqual("nc", FileInspector.Detect(NetCdfVariable(record: true, includeAllData: false))?.Extension);
    }

    private static void AssertParity(byte[] bytes, string extension)
    {
        Assert.Equal(extension, FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false);
        long position = Math.Min(3, stream.Length);
        stream.Position = position;
        Assert.Equal(extension, FileInspector.Detect(stream)?.Extension);
        Assert.Equal(position, stream.Position);
    }

    private static byte[] FatMachO64()
    {
        var bytes = new byte[96];
        new byte[] { 0xCA, 0xFE, 0xBA, 0xBF }.CopyTo(bytes, 0);
        WriteUInt32BigEndian(bytes, 4, 1);
        WriteUInt32BigEndian(bytes, 8, 0x01000007);
        WriteUInt32BigEndian(bytes, 12, 3);
        WriteUInt64BigEndian(bytes, 16, 64);
        WriteUInt64BigEndian(bytes, 24, 32);
        WriteUInt32BigEndian(bytes, 32, 6);
        new byte[] { 0xCF, 0xFA, 0xED, 0xFE }.CopyTo(bytes, 64);
        WriteUInt32LittleEndian(bytes, 68, 0x01000007);
        return bytes;
    }

    private static byte[] ThinMachOWithCommand()
    {
        var bytes = new byte[40];
        new byte[] { 0xCF, 0xFA, 0xED, 0xFE }.CopyTo(bytes, 0);
        WriteUInt32LittleEndian(bytes, 4, 0x01000007);
        WriteUInt32LittleEndian(bytes, 8, 3);
        WriteUInt32LittleEndian(bytes, 12, 2);
        WriteUInt32LittleEndian(bytes, 16, 1);
        WriteUInt32LittleEndian(bytes, 20, 8);
        WriteUInt32LittleEndian(bytes, 32, 1);
        WriteUInt32LittleEndian(bytes, 36, 8);
        return bytes;
    }

    private static byte[] ZipLocal(bool zip64)
    {
        int extraLength = zip64 ? 20 : 0;
        var bytes = new byte[30 + 1 + extraLength + 4];
        WriteUInt32LittleEndian(bytes, 0, 0x04034B50);
        WriteUInt16LittleEndian(bytes, 4, zip64 ? (ushort)45 : (ushort)20);
        if (zip64)
        {
            WriteUInt32LittleEndian(bytes, 18, uint.MaxValue);
            WriteUInt32LittleEndian(bytes, 22, uint.MaxValue);
        }
        else
        {
            WriteUInt32LittleEndian(bytes, 18, 4);
            WriteUInt32LittleEndian(bytes, 22, 4);
        }
        WriteUInt16LittleEndian(bytes, 26, 1);
        WriteUInt16LittleEndian(bytes, 28, (ushort)extraLength);
        bytes[30] = (byte)'a';
        if (zip64)
        {
            WriteUInt16LittleEndian(bytes, 31, 1);
            WriteUInt16LittleEndian(bytes, 33, 16);
            WriteUInt64LittleEndian(bytes, 35, 4);
            WriteUInt64LittleEndian(bytes, 43, 4);
        }
        return bytes;
    }

    private static byte[] FakeDeb()
    {
        using var stream = new MemoryStream();
        byte[] signature = Encoding.ASCII.GetBytes("!<arch>\n");
        stream.Write(signature, 0, signature.Length);
        WriteArMember(stream, "debian-binary", Encoding.ASCII.GetBytes("2.0\n"));
        WriteArMember(stream, "control.tar.xz", new byte[] { 0 });
        WriteArMember(stream, "data.tar.xz", new byte[] { 0 });
        return stream.ToArray();
    }

    private static void WriteArMember(Stream stream, string name, byte[] data)
    {
        string header = (name + "/").PadRight(16) + "0".PadRight(12) + "0".PadRight(6) + "0".PadRight(6) +
                        "100644".PadRight(8) + data.Length.ToString(System.Globalization.CultureInfo.InvariantCulture).PadRight(10) + "`\n";
        byte[] headerBytes = Encoding.ASCII.GetBytes(header);
        stream.Write(headerBytes, 0, headerBytes.Length);
        stream.Write(data, 0, data.Length);
        if ((data.Length & 1) != 0) stream.WriteByte((byte)'\n');
    }

    private static byte[] MinimalBmp()
    {
        var bytes = new byte[26];
        Encoding.ASCII.GetBytes("BM").CopyTo(bytes, 0);
        WriteUInt32LittleEndian(bytes, 2, 26);
        WriteUInt32LittleEndian(bytes, 10, 26);
        WriteUInt32LittleEndian(bytes, 14, 12);
        return bytes;
    }

    private static byte[] NetCdfVariable(bool record, bool includeAllData)
    {
        int dataLength = record ? (includeAllData ? 8 : 4) : (includeAllData ? 4 : 0);
        var bytes = new byte[80 + dataLength];
        Encoding.ASCII.GetBytes("CDF").CopyTo(bytes, 0);
        bytes[3] = 1;
        WriteUInt32BigEndian(bytes, 4, record ? 2u : 0u);
        WriteUInt32BigEndian(bytes, 8, 10);
        WriteUInt32BigEndian(bytes, 12, 1);
        WriteUInt32BigEndian(bytes, 16, 1);
        bytes[20] = (byte)'x';
        WriteUInt32BigEndian(bytes, 24, record ? 0u : 1u);
        WriteUInt32BigEndian(bytes, 28, 0);
        WriteUInt32BigEndian(bytes, 32, 0);
        WriteUInt32BigEndian(bytes, 36, 11);
        WriteUInt32BigEndian(bytes, 40, 1);
        WriteUInt32BigEndian(bytes, 44, 1);
        bytes[48] = (byte)'v';
        WriteUInt32BigEndian(bytes, 52, 1);
        WriteUInt32BigEndian(bytes, 56, 0);
        WriteUInt32BigEndian(bytes, 60, 0);
        WriteUInt32BigEndian(bytes, 64, 0);
        WriteUInt32BigEndian(bytes, 68, 4);
        WriteUInt32BigEndian(bytes, 72, 4);
        WriteUInt32BigEndian(bytes, 76, 80);
        return bytes;
    }

    private static void FinalizeVhdFooter(byte[] bytes, int footer)
    {
        WriteUInt32BigEndian(bytes, footer + 64, 0);
        uint sum = 0;
        for (int index = 0; index < 512; index++) if (index < 64 || index >= 68) sum += bytes[footer + index];
        WriteUInt32BigEndian(bytes, footer + 64, ~sum);
    }

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

    private static void WriteUInt64LittleEndian(byte[] bytes, int offset, ulong value)
    {
        for (int index = 0; index < 8; index++) bytes[offset + index] = (byte)(value >> (8 * index));
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
        for (int index = 0; index < 8; index++) bytes[offset + index] = (byte)(value >> (8 * (7 - index)));
    }
}
