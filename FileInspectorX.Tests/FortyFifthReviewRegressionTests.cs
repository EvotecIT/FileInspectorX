using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

[Collection(nameof(DetectionSettingsCollection))]
public sealed class FortyFifthReviewRegressionTests
{
    [Theory]
    [InlineData(0xFFFD, 0x0001, true)]
    [InlineData(0xFFFD, 0x0002, false)]
    [InlineData(0xFFFE, 0x0002, true)]
    [InlineData(0xFFFE, 0x0001, false)]
    [InlineData(0xFFFF, 0x0003, true)]
    [InlineData(0xFFFF, 0x0002, false)]
    public void CabContinuationFilesRequireTheCorrespondingCabinetFlags(
        ushort folderIndex, ushort flags, bool expected)
        => AssertDetectionParity(CabContinuation(folderIndex, flags), "cab", expected);

    [Fact]
    public void MatroskaRootScanBudgetCannotReplaceTheRequiredSegment()
    {
        byte[] header = TestHelpers.CreateMinimalMatroska().Take(16).ToArray();
        byte[] bytes = header.Concat(new byte[] { 0xEC, 0x80, 0xEC, 0x80 }).ToArray();
        WithReadBudget(64, () => AssertDetectionParity(bytes, "matroska", expected: false));
    }

    [Fact]
    public void MalformedShortJpegSegmentsDoNotThrow()
    {
        AssertDetectionParity(new byte[] { 0xFF, 0xD8, 0xFF, 0xC0, 0x00, 0x02 }, "jpg", expected: false);

        byte[] shortScan = TestHelpers.CreateMinimalJpeg().Take(21).ToArray();
        shortScan[17] = 0;
        shortScan[18] = 2;
        AssertDetectionParity(shortScan, "jpg", expected: false);
    }

    [Fact]
    public void JpegZeroHeightRequiresAValidDefineNumberOfLinesMarker()
    {
        byte[] withoutDnl = TestHelpers.CreateMinimalJpeg();
        withoutDnl[7] = withoutDnl[8] = 0;
        AssertDetectionParity(withoutDnl, "jpg", expected: false);

        byte[] withDnl = withoutDnl.Take(26)
            .Concat(new byte[] { 0xFF, 0xDC, 0x00, 0x04, 0x00, 0x01, 0xFF, 0xD9 }).ToArray();
        AssertDetectionParity(withDnl, "jpg", expected: true);
    }

    [Theory]
    [InlineData("070701")]
    [InlineData("070702")]
    public void RpmRecognizesUncompressedNewcPayloads(string magic)
        => AssertDetectionParity(RpmWithPayload(Encoding.ASCII.GetBytes(magic)), "rpm", expected: true);

    [Fact]
    public void Jpeg2000BoxBudgetCannotReplaceRequiredHeaderAndDataBoxes()
    {
        byte[] minimal = TestHelpers.CreateMinimalJpeg2000();
        var bytes = new byte[32 + 12 * 8];
        Array.Copy(minimal, bytes, 32);
        for (int index = 0; index < 12; index++)
        {
            int offset = 32 + index * 8;
            TestHelpers.WriteUInt32BigEndian(bytes, offset, 8);
            Encoding.ASCII.GetBytes("free").CopyTo(bytes, offset + 4);
        }
        WithReadBudget(64, () => AssertDetectionParity(bytes, "jp2", expected: false));
    }

    private static byte[] CabContinuation(ushort folderIndex, ushort flags)
    {
        int stringsLength = ((flags & 1) != 0 ? 4 : 0) + ((flags & 2) != 0 ? 4 : 0);
        int folderOffset = 36 + stringsLength;
        int filesOffset = folderOffset + 8;
        int cabinetSize = filesOffset + 18;
        var bytes = new byte[cabinetSize];
        Encoding.ASCII.GetBytes("MSCF").CopyTo(bytes, 0);
        TestHelpers.WriteUInt32LittleEndian(bytes, 8, (uint)cabinetSize);
        TestHelpers.WriteUInt32LittleEndian(bytes, 16, (uint)filesOffset);
        bytes[24] = 3;
        bytes[25] = 1;
        TestHelpers.WriteUInt16LittleEndian(bytes, 26, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, 28, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, 30, flags);
        int cursor = 36;
        if ((flags & 1) != 0) { bytes[cursor] = (byte)'p'; bytes[cursor + 2] = (byte)'d'; cursor += 4; }
        if ((flags & 2) != 0) { bytes[cursor] = (byte)'n'; bytes[cursor + 2] = (byte)'d'; cursor += 4; }
        TestHelpers.WriteUInt32LittleEndian(bytes, folderOffset, (uint)cabinetSize);
        TestHelpers.WriteUInt16LittleEndian(bytes, filesOffset + 8, folderIndex);
        bytes[filesOffset + 16] = (byte)'a';
        return bytes;
    }

    private static byte[] RpmWithPayload(byte[] payload)
    {
        var bytes = new byte[169 + payload.Length];
        new byte[] { 0xED, 0xAB, 0xEE, 0xDB, 3, 0 }.CopyTo(bytes, 0);
        TestHelpers.WriteUInt16BigEndian(bytes, 78, 5);
        WriteRpmHeader(bytes, 96);
        WriteRpmHeader(bytes, 136);
        payload.CopyTo(bytes, 169);
        return bytes;
    }

    private static void WriteRpmHeader(byte[] bytes, int offset)
    {
        new byte[] { 0x8E, 0xAD, 0xE8, 1 }.CopyTo(bytes, offset);
        TestHelpers.WriteUInt32BigEndian(bytes, offset + 8, 1);
        TestHelpers.WriteUInt32BigEndian(bytes, offset + 12, 1);
        TestHelpers.WriteUInt32BigEndian(bytes, offset + 16, 1000);
        TestHelpers.WriteUInt32BigEndian(bytes, offset + 20, 7);
        TestHelpers.WriteUInt32BigEndian(bytes, offset + 28, 1);
    }

    private static void WithReadBudget(int budget, Action assertion)
    {
        int original = Settings.DetectionReadBudgetBytes;
        try { Settings.DetectionReadBudgetBytes = budget; assertion(); }
        finally { Settings.DetectionReadBudgetBytes = original; }
    }

    private static void AssertDetectionParity(byte[] bytes, string extension, bool expected)
    {
        ContentTypeDetectionResult? fromBytes = FileInspector.Detect(bytes);
        using var stream = new MemoryStream(bytes, writable: false) { Position = Math.Min(3, bytes.Length) };
        ContentTypeDetectionResult? fromStream = FileInspector.Detect(stream);
        Assert.Equal(expected, fromBytes?.Extension == extension);
        Assert.Equal(expected, fromStream?.Extension == extension);
        Assert.Equal(Math.Min(3, bytes.Length), stream.Position);
    }
}
