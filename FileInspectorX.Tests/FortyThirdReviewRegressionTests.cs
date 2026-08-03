using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class FortyThirdReviewRegressionTests
{
    [Fact]
    public void GifLogicalScreenWithoutAValidatedDataStreamStaysAtMediumConfidence()
    {
        var bytes = new byte[13];
        Encoding.ASCII.GetBytes("GIF89a").CopyTo(bytes, 0);
        TestHelpers.WriteUInt16LittleEndian(bytes, 6, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, 8, 1);

        AssertParity(bytes, "gif", "Medium", "data-stream-not-validated");
    }

    [Fact]
    public void PdfHeaderWithoutAValidatedBodyStaysAtMediumConfidence()
        => AssertParity(Encoding.ASCII.GetBytes("%PDF-1.7\n"), "pdf", "Medium", "body-not-validated");

    [Fact]
    public void OleHeaderWithoutValidatedSectorChainsStaysAtMediumConfidence()
        => AssertParity(OleHeader(), "ole2", "Medium", "sector-chains-not-validated");

    [Fact]
    public void MsiNameHintsCannotRestoreHighConfidenceWithoutSectorChainProof()
    {
        byte[] bytes = OleHeader();
        Encoding.ASCII.GetBytes("SummaryInformation Property Directory Media").CopyTo(bytes, 100);

        Assert.Equal("Medium", FileInspector.Detect(bytes)?.Confidence);
        using var stream = new MemoryStream(bytes, writable: false) { Position = 3 };
        ContentTypeDetectionResult? fromStream = FileInspector.Detect(stream);
        Assert.Equal("msi", fromStream?.Extension);
        Assert.Equal("Medium", fromStream?.Confidence);
        Assert.Contains("sector-chains-not-validated", fromStream?.Reason ?? string.Empty, StringComparison.Ordinal);
        Assert.Equal(3, stream.Position);
    }

    [Fact]
    public void TiffIfdFieldsWithoutValidatedImageRangesStayAtMediumConfidence()
        => AssertParity(TiffWithOutOfRangeStrip(), "tif", "Medium", "image-ranges-not-validated");

    [Fact]
    public void ZipLocalAndCentralNamesMustMatchForHighConfidence()
    {
        AssertParity(SingleEntryZip((byte)'a', (byte)'a'), "zip", "High", "central-directory");
        AssertParity(SingleEntryZip((byte)'a', (byte)'b'), "zip", "Medium", "local-header-only");
    }

    private static byte[] OleHeader()
    {
        var bytes = new byte[512];
        new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 }.CopyTo(bytes, 0);
        TestHelpers.WriteUInt16LittleEndian(bytes, 26, 3);
        TestHelpers.WriteUInt16LittleEndian(bytes, 28, 0xFFFE);
        TestHelpers.WriteUInt16LittleEndian(bytes, 30, 9);
        TestHelpers.WriteUInt16LittleEndian(bytes, 32, 6);
        TestHelpers.WriteUInt32LittleEndian(bytes, 44, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 48, 2);
        return bytes;
    }

    private static byte[] TiffWithOutOfRangeStrip()
    {
        var bytes = new byte[62];
        bytes[0] = bytes[1] = (byte)'I';
        TestHelpers.WriteUInt16LittleEndian(bytes, 2, 42);
        TestHelpers.WriteUInt32LittleEndian(bytes, 4, 8);
        TestHelpers.WriteUInt16LittleEndian(bytes, 8, 4);
        WriteTiffEntry(bytes, 10, 256, 0);
        WriteTiffEntry(bytes, 22, 257, 0);
        WriteTiffEntry(bytes, 34, 273, 1000);
        WriteTiffEntry(bytes, 46, 279, 1);
        return bytes;
    }

    private static void WriteTiffEntry(byte[] bytes, int offset, ushort tag, uint value)
    {
        TestHelpers.WriteUInt16LittleEndian(bytes, offset, tag);
        TestHelpers.WriteUInt16LittleEndian(bytes, offset + 2, 4);
        TestHelpers.WriteUInt32LittleEndian(bytes, offset + 4, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, offset + 8, value);
    }

    private static byte[] SingleEntryZip(byte localName, byte centralName)
    {
        const int localLength = 31;
        const int centralLength = 47;
        var bytes = new byte[localLength + centralLength + 22];

        TestHelpers.WriteUInt32LittleEndian(bytes, 0, 0x04034B50);
        TestHelpers.WriteUInt16LittleEndian(bytes, 4, 20);
        TestHelpers.WriteUInt16LittleEndian(bytes, 26, 1);
        bytes[30] = localName;

        int central = localLength;
        TestHelpers.WriteUInt32LittleEndian(bytes, central, 0x02014B50);
        TestHelpers.WriteUInt16LittleEndian(bytes, central + 4, 20);
        TestHelpers.WriteUInt16LittleEndian(bytes, central + 6, 20);
        TestHelpers.WriteUInt16LittleEndian(bytes, central + 28, 1);
        bytes[central + 46] = centralName;

        int eocd = central + centralLength;
        TestHelpers.WriteUInt32LittleEndian(bytes, eocd, 0x06054B50);
        TestHelpers.WriteUInt16LittleEndian(bytes, eocd + 8, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, eocd + 10, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, eocd + 12, centralLength);
        TestHelpers.WriteUInt32LittleEndian(bytes, eocd + 16, localLength);
        return bytes;
    }

    private static void AssertParity(byte[] bytes, string extension, string confidence, string reason)
    {
        ContentTypeDetectionResult? fromBytes = FileInspector.Detect(bytes);
        using var stream = new MemoryStream(bytes, writable: false) { Position = Math.Min(3, bytes.Length) };
        long originalPosition = stream.Position;
        ContentTypeDetectionResult? fromStream = FileInspector.Detect(stream);
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".bin");
        try
        {
            File.WriteAllBytes(path, bytes);
            ContentTypeDetectionResult? fromPath = FileInspector.Detect(path);
            foreach (ContentTypeDetectionResult? result in new[] { fromBytes, fromStream, fromPath })
            {
                Assert.Equal(extension, result?.Extension);
                Assert.Equal(confidence, result?.Confidence);
                Assert.Contains(reason, result?.Reason ?? string.Empty, StringComparison.Ordinal);
            }
            Assert.Equal(originalPosition, stream.Position);
        }
        finally
        {
            TestHelpers.SafeDelete(path);
        }
    }
}
