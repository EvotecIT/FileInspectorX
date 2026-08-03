using Xunit;

namespace FileInspectorX.Tests;

public sealed class FortyFourthReviewRegressionTests
{
    [Fact]
    public void JpegHighConfidenceRequiresValidFrameAndScanComponentLayouts()
    {
        byte[] malformedFrame = TestHelpers.CreateMinimalJpeg();
        malformedFrame[11] = 0;
        AssertNotHigh(malformedFrame, "jpg");

        byte[] unknownScanComponent = TestHelpers.CreateMinimalJpeg();
        unknownScanComponent[20] = 2;
        AssertNotHigh(unknownScanComponent, "jpg");
    }

    [Fact]
    public void Jpeg2000TilePartIdentifierMustFitTheSizTileGrid()
    {
        byte[] invalidTile = TestHelpers.CreateMinimalJpeg2000();
        int sot = FindMarker(invalidTile, 0x90);
        Assert.True(sot >= 0);
        invalidTile[sot + 4] = 0xFF;
        invalidTile[sot + 5] = 0xFF;
        AssertNotHigh(invalidTile, "jp2");

        byte[] skippedFirstPart = TestHelpers.CreateMinimalJpeg2000();
        skippedFirstPart[sot + 10] = 1;
        skippedFirstPart[sot + 11] = 2;
        AssertNotHigh(skippedFirstPart, "jp2");
    }

    private static int FindMarker(byte[] bytes, byte marker)
    {
        for (int index = 0; index + 1 < bytes.Length; index++)
            if (bytes[index] == 0xFF && bytes[index + 1] == marker) return index;
        return -1;
    }

    private static void AssertNotHigh(byte[] bytes, string extension)
    {
        ContentTypeDetectionResult? fromBytes = FileInspector.Detect(bytes);
        using var stream = new MemoryStream(bytes, writable: false) { Position = Math.Min(2, bytes.Length) };
        ContentTypeDetectionResult? fromStream = FileInspector.Detect(stream);
        Assert.True(fromBytes?.Extension != extension || fromBytes.Confidence != "High");
        Assert.True(fromStream?.Extension != extension || fromStream.Confidence != "High");
        Assert.Equal(Math.Min(2, bytes.Length), stream.Position);
    }
}
