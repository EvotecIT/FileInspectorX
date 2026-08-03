using System.Diagnostics;
using System.Text;
using Xunit;

namespace FileInspectorX.Tests;

public sealed class ArrowBlockPerformanceRegressionTests
{
    [Fact]
    public void LargeArrowBlockVectorsAreValidatedWithinALinearithmicBudget()
    {
        byte[] bytes = ArrowWithRecordBatches(20_000, overlap: false);
        var stopwatch = Stopwatch.StartNew();
        ContentTypeDetectionResult? result = FileInspector.Detect(bytes);
        stopwatch.Stop();

        Assert.Equal("arrow", result?.Extension);
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(5), $"Arrow validation took {stopwatch.Elapsed}.");
        AssertNotDetectedAs(ArrowWithRecordBatches(2, overlap: true), "arrow");
    }

    private static byte[] ArrowWithRecordBatches(int count, bool overlap)
    {
        int vectorEnd = 36 + count * 24;
        int schemaVtable = vectorEnd;
        int schemaTable = schemaVtable + 8;
        int footerLength = schemaTable + 12;
        var footer = new byte[footerLength];
        TestHelpers.WriteUInt32LittleEndian(footer, 0, 16);
        TestHelpers.WriteUInt16LittleEndian(footer, 4, 12);
        TestHelpers.WriteUInt16LittleEndian(footer, 6, 16);
        TestHelpers.WriteUInt16LittleEndian(footer, 8, 4);
        TestHelpers.WriteUInt16LittleEndian(footer, 10, 8);
        TestHelpers.WriteUInt16LittleEndian(footer, 14, 12);
        TestHelpers.WriteUInt32LittleEndian(footer, 16, 12);
        TestHelpers.WriteUInt32LittleEndian(footer, 24, (uint)(schemaTable - 24));
        TestHelpers.WriteUInt32LittleEndian(footer, 28, 4);
        TestHelpers.WriteUInt32LittleEndian(footer, 32, (uint)count);
        for (int index = 0; index < count; index++)
        {
            int block = 36 + index * 24;
            ulong offset = (ulong)(8 + (overlap && index == 1 ? 0 : index) * 8);
            TestHelpers.WriteUInt64LittleEndian(footer, block, offset);
            TestHelpers.WriteUInt32LittleEndian(footer, block + 8, 8);
        }
        TestHelpers.WriteUInt16LittleEndian(footer, schemaVtable, 8);
        TestHelpers.WriteUInt16LittleEndian(footer, schemaVtable + 2, 8);
        TestHelpers.WriteUInt16LittleEndian(footer, schemaVtable + 6, 4);
        TestHelpers.WriteUInt32LittleEndian(footer, schemaTable, 8);
        TestHelpers.WriteUInt32LittleEndian(footer, schemaTable + 4, 4);

        int footerStart = Math.Max(8 + count * 8, 8);
        var bytes = new byte[footerStart + footer.Length + 10];
        Encoding.ASCII.GetBytes("ARROW1").CopyTo(bytes, 0);
        footer.CopyTo(bytes, footerStart);
        TestHelpers.WriteUInt32LittleEndian(bytes, bytes.Length - 10, (uint)footer.Length);
        Encoding.ASCII.GetBytes("ARROW1").CopyTo(bytes, bytes.Length - 6);
        return bytes;
    }

    private static void AssertNotDetectedAs(byte[] bytes, string extension)
    {
        Assert.NotEqual(extension, FileInspector.Detect(bytes)?.Extension);
        using var stream = new MemoryStream(bytes, writable: false);
        Assert.NotEqual(extension, FileInspector.Detect(stream)?.Extension);
    }
}
