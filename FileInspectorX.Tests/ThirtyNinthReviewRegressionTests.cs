using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class ThirtyNinthReviewRegressionTests
{
    [Fact]
    public void EmbeddedBmpPayloadsWithoutDecodingUseReducedConfidence()
    {
        var result = AssertParity(BmpWithEmbeddedPngMarkerOnly(), "bmp", "Medium");
        Assert.Contains("embedded-payload-not-validated", result.Reason);
    }

    [Fact]
    public void Mp3SingleFrameEvidenceDoesNotValidateTheRemainingFrameChain()
    {
        byte[] firstFrameThenGarbage = TestHelpers.CreateMinimalMp3().Concat(new byte[] { 1, 2, 3, 4 }).ToArray();
        var result = AssertParity(firstFrameThenGarbage, "mp3", "Medium");
        Assert.Contains("frame-chain-not-validated", result.Reason);
    }

    [Fact]
    public void MatroskaTopLevelElementsDoNotImplyValidatedChildSemantics()
    {
        var result = AssertParity(TestHelpers.CreateMinimalMatroska(), "matroska", "Medium");
        Assert.Contains("segment-child-semantics-not-validated", result.Reason);
    }

    [Fact]
    public void FlacValidatesStreamInfoRelationshipsButKeepsPayloadConfidenceConservative()
    {
        var result = AssertParity(Flac(minimumBlockSize: 16, maximumBlockSize: 16), "flac", "Medium");
        Assert.Contains("metadata+audio-not-fully-validated", result.Reason);
        AssertNotDetectedAs(Flac(minimumBlockSize: 0, maximumBlockSize: 16), "flac");
        AssertNotDetectedAs(Flac(minimumBlockSize: 32, maximumBlockSize: 16), "flac");
    }

    [Fact]
    public void DibBackedIconsRequireXorAndAndBitmapData()
    {
        AssertParity(DibIcon(includeBitmapData: true), "ico", "High");
        AssertNotDetectedAs(DibIcon(includeBitmapData: false), "ico");
    }

    [Fact]
    public void CrxProofFramingWithoutCryptographicVerificationUsesReducedConfidence()
    {
        var result = AssertParity(TestHelpers.CreateMinimalCrx3(), "crx", "Medium");
        Assert.Contains("signature-not-verified", result.Reason);
    }

    [Fact]
    public void DynamicVhdNeedsTheLeadingFooterCopyForHighConfidence()
    {
        byte[] missingLeadingFooter = DynamicVhd();
        var reduced = AssertParity(missingLeadingFooter, "vhd", "Medium");
        Assert.Contains("leading-footer-not-validated", reduced.Reason);

        byte[] complete = (byte[])missingLeadingFooter.Clone();
        complete.AsSpan(complete.Length - 512, 512).CopyTo(complete);
        AssertParity(complete, "vhd", "High");
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

    private static byte[] BmpWithEmbeddedPngMarkerOnly()
    {
        var bytes = new byte[55];
        Encoding.ASCII.GetBytes("BM").CopyTo(bytes, 0);
        TestHelpers.WriteUInt32LittleEndian(bytes, 2, (uint)bytes.Length);
        TestHelpers.WriteUInt32LittleEndian(bytes, 10, 54);
        TestHelpers.WriteUInt32LittleEndian(bytes, 14, 40);
        TestHelpers.WriteUInt32LittleEndian(bytes, 18, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 22, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, 26, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, 28, 32);
        TestHelpers.WriteUInt32LittleEndian(bytes, 30, 5);
        TestHelpers.WriteUInt32LittleEndian(bytes, 34, 1);
        bytes[54] = 0x42;
        return bytes;
    }

    private static byte[] Flac(ushort minimumBlockSize, ushort maximumBlockSize)
    {
        var bytes = new byte[42];
        Encoding.ASCII.GetBytes("fLaC").CopyTo(bytes, 0);
        bytes[4] = 0x80;
        bytes[7] = 34;
        TestHelpers.WriteUInt16BigEndian(bytes, 8, minimumBlockSize);
        TestHelpers.WriteUInt16BigEndian(bytes, 10, maximumBlockSize);
        bytes[18] = 0x0A;
        bytes[19] = 0xC4;
        bytes[20] = 0x42;
        bytes[21] = 0xF0;
        bytes[25] = 1;
        return bytes;
    }

    private static byte[] DibIcon(bool includeBitmapData)
    {
        int payloadLength = includeBitmapData ? 48 : 40;
        var bytes = new byte[22 + payloadLength];
        TestHelpers.WriteUInt16LittleEndian(bytes, 2, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, 4, 1);
        bytes[6] = 1;
        bytes[7] = 1;
        TestHelpers.WriteUInt16LittleEndian(bytes, 10, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, 12, 32);
        TestHelpers.WriteUInt32LittleEndian(bytes, 14, (uint)payloadLength);
        TestHelpers.WriteUInt32LittleEndian(bytes, 18, 22);
        TestHelpers.WriteUInt32LittleEndian(bytes, 22, 40);
        TestHelpers.WriteUInt32LittleEndian(bytes, 26, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, 30, 2);
        TestHelpers.WriteUInt16LittleEndian(bytes, 34, 1);
        TestHelpers.WriteUInt16LittleEndian(bytes, 36, 32);
        return bytes;
    }

    private static byte[] DynamicVhd()
    {
        var bytes = new byte[2560];
        const int header = 512;
        const int table = 1536;
        const int footer = 2048;
        Encoding.ASCII.GetBytes("cxsparse").CopyTo(bytes, header);
        TestHelpers.WriteUInt64BigEndian(bytes, header + 8, ulong.MaxValue);
        TestHelpers.WriteUInt64BigEndian(bytes, header + 16, table);
        TestHelpers.WriteUInt32BigEndian(bytes, header + 24, 0x00010000);
        TestHelpers.WriteUInt32BigEndian(bytes, header + 28, 1);
        TestHelpers.WriteUInt32BigEndian(bytes, header + 32, 512 * 1024);
        FinalizeChecksum(bytes, header, 1024, header + 36);
        TestHelpers.WriteUInt32BigEndian(bytes, table, uint.MaxValue);

        Encoding.ASCII.GetBytes("conectix").CopyTo(bytes, footer);
        TestHelpers.WriteUInt32BigEndian(bytes, footer + 8, 2);
        TestHelpers.WriteUInt32BigEndian(bytes, footer + 12, 0x00010000);
        TestHelpers.WriteUInt64BigEndian(bytes, footer + 16, header);
        TestHelpers.WriteUInt64BigEndian(bytes, footer + 40, 512 * 1024);
        TestHelpers.WriteUInt64BigEndian(bytes, footer + 48, 512 * 1024);
        TestHelpers.WriteUInt32BigEndian(bytes, footer + 56, 0x00010101);
        TestHelpers.WriteUInt32BigEndian(bytes, footer + 60, 3);
        bytes[footer + 68] = 1;
        FinalizeChecksum(bytes, footer, 512, footer + 64);
        return bytes;
    }

    private static void FinalizeChecksum(byte[] bytes, int offset, int length, int checksumOffset)
    {
        uint sum = 0;
        for (int index = 0; index < length; index++)
            if (offset + index < checksumOffset || offset + index >= checksumOffset + 4) sum += bytes[offset + index];
        TestHelpers.WriteUInt32BigEndian(bytes, checksumOffset, ~sum);
    }
}
