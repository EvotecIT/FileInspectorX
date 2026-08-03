using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class ThirtyFirstReviewRegressionTests
{
    [Fact]
    public void ArrowBlocksMustFitBeforeTheFooter()
    {
        AssertNotDetectedAs(ArrowWithOutOfRangeBlock(), "arrow");
    }

    [Fact]
    public void DicomWithoutDataSetEvidenceHasReducedConfidence()
    {
        byte[] complete = TestHelpers.CreateMinimalDicom();
        byte[] metaOnly = complete.Take(complete.Length - 8).ToArray();
        AssertMediumParity(metaOnly, "dcm", "data-set-not-validated");
    }

    [Fact]
    public void ShellLinkInfoOffsetsMustResolveInsideTheBlock()
    {
        byte[] bytes = ShellLinkWithLinkInfo();
        Assert.Equal("lnk", FileInspector.Detect(bytes)?.Extension);
        TestHelpers.WriteUInt32LittleEndian(bytes, 80 + 24, 1000);
        AssertNotDetectedAs(bytes, "lnk");
    }

    [Fact]
    public void VhdxWithoutValidMetadataContentHasReducedConfidence()
    {
        byte[] bytes = TestHelpers.CreateMinimalVhdx();
        bytes[2 * 1024 * 1024] = (byte)'x';
        AssertMediumParity(bytes, "vhdx", "metadata-not-validated");
    }

    [Fact]
    public void OrdinaryJavaClassCannotUseZeroSuperClass()
    {
        byte[] bytes = JavaClass();
        int access = Find(bytes, new byte[] { 0, 0x21, 0, 2, 0, 4 });
        Assert.True(access >= 0);
        bytes[access + 4] = 0;
        bytes[access + 5] = 0;
        AssertNotDetectedAs(bytes, "class");
    }

    [Fact]
    public void OutlookNdbWithoutRootPageProofHasReducedConfidence()
    {
        AssertMediumParity(TestHelpers.CreateMinimalOutlookNdb(), "ndb", "root-pages-not-validated");
    }

    [Fact]
    public void Qcow2WithoutRefcountContentProofHasReducedConfidence()
    {
        AssertMediumParity(Qcow2(), "qcow2", "refcount-contents-not-validated");
    }

    private static void AssertMediumParity(byte[] bytes, string extension, string reason)
    {
        var fromBytes = FileInspector.Detect(bytes);
        using var stream = new MemoryStream(bytes, writable: false);
        var fromStream = FileInspector.Detect(stream);
        Assert.Equal(extension, fromBytes?.Extension);
        Assert.Equal(extension, fromStream?.Extension);
        Assert.Equal("Medium", fromBytes?.Confidence);
        Assert.Equal("Medium", fromStream?.Confidence);
        Assert.Contains(reason, fromBytes?.Reason);
        Assert.Contains(reason, fromStream?.Reason);
    }

    private static void AssertNotDetectedAs(byte[] bytes, string extension)
    {
        Assert.NotEqual(extension, FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false);
        Assert.NotEqual(extension, FileInspector.Detect(stream)?.Extension);
    }

    private static byte[] ArrowWithOutOfRangeBlock()
    {
        var footer = new byte[96];
        TestHelpers.WriteUInt32LittleEndian(footer, 0, 16);
        TestHelpers.WriteUInt16LittleEndian(footer, 4, 12);
        TestHelpers.WriteUInt16LittleEndian(footer, 6, 16);
        TestHelpers.WriteUInt16LittleEndian(footer, 8, 4);
        TestHelpers.WriteUInt16LittleEndian(footer, 10, 8);
        TestHelpers.WriteUInt16LittleEndian(footer, 14, 12);
        TestHelpers.WriteUInt32LittleEndian(footer, 16, 12);
        TestHelpers.WriteUInt32LittleEndian(footer, 24, 48);
        TestHelpers.WriteUInt32LittleEndian(footer, 28, 4);
        TestHelpers.WriteUInt32LittleEndian(footer, 32, 1);
        TestHelpers.WriteUInt64LittleEndian(footer, 36, 8);
        TestHelpers.WriteUInt32LittleEndian(footer, 44, 8);
        TestHelpers.WriteUInt64LittleEndian(footer, 52, 8);
        TestHelpers.WriteUInt16LittleEndian(footer, 64, 4);
        TestHelpers.WriteUInt16LittleEndian(footer, 66, 4);
        TestHelpers.WriteUInt32LittleEndian(footer, 72, 8);

        var bytes = new byte[8 + footer.Length + 10];
        Encoding.ASCII.GetBytes("ARROW1").CopyTo(bytes, 0);
        footer.CopyTo(bytes, 8);
        TestHelpers.WriteUInt32LittleEndian(bytes, bytes.Length - 10, (uint)footer.Length);
        Encoding.ASCII.GetBytes("ARROW1").CopyTo(bytes, bytes.Length - 6);
        return bytes;
    }

    private static byte[] ShellLinkWithLinkInfo()
    {
        var bytes = new byte[137];
        bytes[0] = 0x4C;
        new byte[] { 0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46 }.CopyTo(bytes, 4);
        TestHelpers.WriteUInt32LittleEndian(bytes, 20, 2);
        TestHelpers.WriteUInt32LittleEndian(bytes, 60, 1);
        int linkInfo = 76;
        TestHelpers.WriteUInt32LittleEndian(bytes, linkInfo, 57);
        TestHelpers.WriteUInt32LittleEndian(bytes, linkInfo + 4, 28);
        TestHelpers.WriteUInt32LittleEndian(bytes, linkInfo + 8, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, linkInfo + 12, 28);
        TestHelpers.WriteUInt32LittleEndian(bytes, linkInfo + 16, 46);
        TestHelpers.WriteUInt32LittleEndian(bytes, linkInfo + 24, 50);
        TestHelpers.WriteUInt32LittleEndian(bytes, linkInfo + 28, 18);
        TestHelpers.WriteUInt32LittleEndian(bytes, linkInfo + 32, 3);
        TestHelpers.WriteUInt32LittleEndian(bytes, linkInfo + 36, 1);
        TestHelpers.WriteUInt32LittleEndian(bytes, linkInfo + 40, 16);
        bytes[linkInfo + 44] = (byte)'V';
        bytes[linkInfo + 46] = (byte)'C'; bytes[linkInfo + 47] = (byte)':'; bytes[linkInfo + 48] = (byte)'\\';
        Encoding.ASCII.GetBytes("file").CopyTo(bytes, linkInfo + 50);
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

    private static byte[] Qcow2()
    {
        var bytes = new byte[2048];
        new byte[] { (byte)'Q', (byte)'F', (byte)'I', 0xFB }.CopyTo(bytes, 0);
        TestHelpers.WriteUInt32BigEndian(bytes, 4, 3);
        TestHelpers.WriteUInt32BigEndian(bytes, 20, 9);
        TestHelpers.WriteUInt64BigEndian(bytes, 24, 32768);
        TestHelpers.WriteUInt32BigEndian(bytes, 36, 1);
        TestHelpers.WriteUInt64BigEndian(bytes, 40, 512);
        TestHelpers.WriteUInt64BigEndian(bytes, 48, 1024);
        TestHelpers.WriteUInt32BigEndian(bytes, 56, 1);
        TestHelpers.WriteUInt32BigEndian(bytes, 100, 104);
        return bytes;
    }

    private static int Find(byte[] bytes, byte[] pattern)
    {
        for (int index = 0; index <= bytes.Length - pattern.Length; index++)
        {
            int part = 0;
            while (part < pattern.Length && bytes[index + part] == pattern[part]) part++;
            if (part == pattern.Length) return index;
        }
        return -1;
    }
}
