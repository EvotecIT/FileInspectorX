using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class ThirtyEighthReviewRegressionTests
{
    [Fact]
    public void Woff1WithoutDecodedTableChecksumsUsesReducedConfidence()
    {
        var result = AssertParity(MinimalWoff1(), "woff", "Medium");
        Assert.Contains("table-payloads-not-validated", result.Reason);
    }

    [Fact]
    public void DicomWithoutACompleteDataSetWalkUsesReducedConfidence()
    {
        var result = AssertParity(TestHelpers.CreateMinimalDicom(), "dcm", "Medium");
        Assert.Contains("data-set-not-fully-validated", result.Reason);
    }

    [Fact]
    public void DdsCubeRequiresSquareTwoDimensionalTextures()
    {
        AssertParity(DdsCube(width: 1, height: 1, resourceDimension: 3), "dds", "High");
        AssertNotDetectedAs(DdsCube(width: 2, height: 1, resourceDimension: 3), "dds");
        AssertNotDetectedAs(DdsCube(width: 1, height: 1, resourceDimension: 2), "dds");
    }

    [Fact]
    public void JavaConcreteMethodsWithoutCodeNeverClaimFullSemanticValidation()
    {
        var result = AssertParity(JavaClassWithConcreteMethodWithoutCode(), "class", "Medium");
        Assert.Contains("method-semantics-not-validated", result.Reason);
    }

    [Fact]
    public void OpenExrChunkFramingWithoutDecodedPayloadsUsesReducedConfidence()
    {
        var result = AssertParity(TestHelpers.CreateMinimalOpenExr(), "exr", "Medium");
        Assert.Contains("chunk-payloads-not-validated", result.Reason);
    }

    [Fact]
    public void CompressedCabWithoutPayloadDecodingUsesReducedConfidence()
    {
        var result = AssertParity(CompressedCab(), "cab", "Medium");
        Assert.Contains("payload-integrity-not-validated", result.Reason);
    }

    [Fact]
    public void DebianTarMembersRequireOnlyZeroBytesAfterTheEndMarkers()
    {
        byte[] bytes = TestHelpers.CreateMinimalDeb();
        int controlHeader = IndexOf(bytes, Encoding.ASCII.GetBytes("control.tar/"));
        Assert.True(controlHeader >= 0);
        bytes[controlHeader + 60 + 1535] = 1;
        AssertNotDetectedAs(bytes, "deb");
    }

    [Fact]
    public void BaselineJp2RequiresAColourSpecificationBox()
    {
        AssertParity(TestHelpers.CreateMinimalJpeg2000(), "jp2", "High");
        byte[] missing = TestHelpers.CreateMinimalJpeg2000();
        Encoding.ASCII.GetBytes("free").CopyTo(missing, 66);
        AssertNotDetectedAs(missing, "jp2");
    }

    [Fact]
    public void PhotoshopColorModeConstrainsChannelsDepthAndModeData()
    {
        AssertParity(TestHelpers.CreateMinimalPhotoshop(), "psd", "High");

        byte[] invalidBitmapDepth = TestHelpers.CreateMinimalPhotoshop();
        TestHelpers.WriteUInt16BigEndian(invalidBitmapDepth, 12, 1);
        TestHelpers.WriteUInt16BigEndian(invalidBitmapDepth, 24, 0);
        AssertNotDetectedAs(invalidBitmapDepth, "psd");

        byte[] indexedWithoutPalette = TestHelpers.CreateMinimalPhotoshop();
        TestHelpers.WriteUInt16BigEndian(indexedWithoutPalette, 12, 1);
        TestHelpers.WriteUInt16BigEndian(indexedWithoutPalette, 24, 2);
        AssertNotDetectedAs(indexedWithoutPalette, "psd");
    }

    [Fact]
    public void ZeroStreamMinidumpRequiresExactHeaderLengthForHighConfidence()
    {
        byte[] exact = ZeroStreamMinidump();
        AssertParity(exact, "dmp", "High");

        var withTrailingData = new byte[exact.Length + 1];
        exact.CopyTo(withTrailingData, 0);
        var result = AssertParity(withTrailingData, "dmp", "Medium");
        Assert.Contains("unreferenced-trailing-bytes", result.Reason);
    }

    private static ContentTypeDetectionResult AssertParity(byte[] bytes, string extension, string confidence)
    {
        var fromBytes = FileInspector.Detect(bytes);
        using var stream = new MemoryStream(bytes, writable: false) { Position = Math.Min(3, bytes.Length) };
        var fromStream = FileInspector.Detect(stream);
        Assert.Equal(extension, fromBytes?.Extension);
        Assert.Equal(extension, fromStream?.Extension);
        Assert.Equal(confidence, fromBytes?.Confidence);
        Assert.Equal(confidence, fromStream?.Confidence);
        Assert.Equal(Math.Min(3, bytes.Length), stream.Position);
        return fromBytes!;
    }

    private static void AssertNotDetectedAs(byte[] bytes, string extension)
    {
        Assert.NotEqual(extension, FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false);
        Assert.NotEqual(extension, FileInspector.Detect(stream)?.Extension);
    }

    private static byte[] MinimalWoff1()
    {
        var bytes = new byte[68];
        Encoding.ASCII.GetBytes("wOFF").CopyTo(bytes, 0);
        TestHelpers.WriteUInt32BigEndian(bytes, 4, 0x00010000);
        TestHelpers.WriteUInt32BigEndian(bytes, 8, (uint)bytes.Length);
        TestHelpers.WriteUInt16BigEndian(bytes, 12, 1);
        TestHelpers.WriteUInt32BigEndian(bytes, 16, 32);
        Encoding.ASCII.GetBytes("head").CopyTo(bytes, 44);
        TestHelpers.WriteUInt32BigEndian(bytes, 48, 64);
        TestHelpers.WriteUInt32BigEndian(bytes, 52, 1);
        TestHelpers.WriteUInt32BigEndian(bytes, 56, 1);
        return bytes;
    }

    private static byte[] DdsCube(uint width, uint height, uint resourceDimension)
    {
        int payloadLength = checked((int)(width * height * 4 * 6));
        var bytes = new byte[148 + payloadLength];
        Encoding.ASCII.GetBytes("DDS ").CopyTo(bytes, 0);
        TestHelpers.WriteUInt32LittleEndian(bytes, 4, 124);
        TestHelpers.WriteUInt32LittleEndian(bytes, 8, 0x1007);
        TestHelpers.WriteUInt32LittleEndian(bytes, 12, height);
        TestHelpers.WriteUInt32LittleEndian(bytes, 16, width);
        TestHelpers.WriteUInt32LittleEndian(bytes, 76, 32);
        TestHelpers.WriteUInt32LittleEndian(bytes, 80, 4);
        Encoding.ASCII.GetBytes("DX10").CopyTo(bytes, 84);
        TestHelpers.WriteUInt32LittleEndian(bytes, 108, 0x1000);
        TestHelpers.WriteUInt32LittleEndian(bytes, 128, 28);
        TestHelpers.WriteUInt32LittleEndian(bytes, 132, resourceDimension);
        TestHelpers.WriteUInt32LittleEndian(bytes, 136, 4);
        TestHelpers.WriteUInt32LittleEndian(bytes, 140, 1);
        return bytes;
    }

    private static byte[] JavaClassWithConcreteMethodWithoutCode()
    {
        using var stream = new MemoryStream();
        WriteBytes(stream, 0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52, 0, 7);
        WriteUtf8(stream, "Test");
        WriteBytes(stream, 7, 0, 1);
        WriteUtf8(stream, "java/lang/Object");
        WriteBytes(stream, 7, 0, 3);
        WriteUtf8(stream, "m");
        WriteUtf8(stream, "()V");
        WriteBytes(stream,
            0, 0x21, 0, 2, 0, 4,
            0, 0,
            0, 0,
            0, 1,
            0, 1, 0, 5, 0, 6, 0, 0,
            0, 0);
        return stream.ToArray();
    }

    private static byte[] CompressedCab()
    {
        const int dataOffset = 62;
        var bytes = new byte[dataOffset + 9];
        Encoding.ASCII.GetBytes("MSCF").CopyTo(bytes, 0);
        TestHelpers.WriteUInt32LittleEndian(bytes, 8, (uint)bytes.Length);
        TestHelpers.WriteUInt32LittleEndian(bytes, 16, 44);
        bytes[24] = 3;
        bytes[25] = 1;
        TestHelpers.WriteUInt16LittleEndian(bytes, 26, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, 28, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 36, dataOffset);
        TestHelpers.WriteUInt16LittleEndian(bytes, 40, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, 42, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 44, 1);
        bytes[60] = (byte)'a';
        TestHelpers.WriteUInt16LittleEndian(bytes, dataOffset + 4, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, dataOffset + 6, 1);
        bytes[dataOffset + 8] = 0x41;
        return bytes;
    }

    private static byte[] ZeroStreamMinidump()
    {
        var bytes = new byte[32];
        Encoding.ASCII.GetBytes("MDMP").CopyTo(bytes, 0);
        TestHelpers.WriteUInt32LittleEndian(bytes, 4, 0xA793);
        return bytes;
    }

    private static int IndexOf(byte[] source, byte[] value)
    {
        for (int offset = 0; offset <= source.Length - value.Length; offset++)
        {
            bool equal = true;
            for (int index = 0; index < value.Length; index++) equal &= source[offset + index] == value[index];
            if (equal) return offset;
        }
        return -1;
    }

    private static void WriteUtf8(Stream stream, string value)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(value);
        stream.WriteByte(1);
        stream.WriteByte((byte)(bytes.Length >> 8));
        stream.WriteByte((byte)bytes.Length);
        stream.Write(bytes, 0, bytes.Length);
    }

    private static void WriteBytes(Stream stream, params byte[] bytes)
        => stream.Write(bytes, 0, bytes.Length);
}
