#if NET8_0_OR_GREATER
using Xunit;

namespace FileInspectorX.Tests;

public sealed class ReportSnapshotOwnershipTests
{
    [Fact]
    public void CancellationAtFinalEofCleansSpilledSnapshotAndDoesNotReturnAReport()
    {
        var directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N")); Directory.CreateDirectory(directory);
        try
        {
            using var cancellation = new CancellationTokenSource();
            using var input = new ObservedStream(new byte[20000], (count, stream) => { if (count == 0) cancellation.Cancel(); });
            var options = new InspectionReportOptions { SnapshotDirectory = directory, MaxMemorySnapshotBytes = 1024,
                Detection = new FileInspector.DetectionOptions { CancellationToken = cancellation.Token } };
            Assert.Throws<OperationCanceledException>(() => FileInspector.AnalyzeReport(input, "sample.bin", options));
            Assert.True(input.CanRead); Assert.Equal(0, input.Position); Assert.Empty(Directory.GetFiles(directory));
        }
        finally { Directory.Delete(directory, true); }
    }

    [Fact]
    public void RestoreFailureStillDisposesTheCapturedSnapshot()
    {
        var directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N")); Directory.CreateDirectory(directory);
        try
        {
            using var input = new RestoreFailureStream(new byte[20000]); input.Position = 5;
            Assert.Throws<IOException>(() => FileInspector.AnalyzeReport(input, "sample.bin",
                new InspectionReportOptions { SnapshotDirectory = directory, MaxMemorySnapshotBytes = 1024 }));
            Assert.True(input.CanRead); Assert.Empty(Directory.GetFiles(directory));
        }
        finally { Directory.Delete(directory, true); }
    }

    [Fact]
    public void ActiveUnixSnapshotIsOwnerOnlyAndRemovedAfterAnalysis()
    {
        if (OperatingSystem.IsWindows()) return;
        var directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N")); Directory.CreateDirectory(directory);
        bool observed = false;
        try
        {
            using var input = new ObservedStream(new byte[20000], (_, _) =>
            {
                var files = Directory.GetFiles(directory); if (files.Length == 0) return;
                observed = true; var mode = File.GetUnixFileMode(Assert.Single(files));
                Assert.Equal((UnixFileMode)0, mode & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.OtherRead | UnixFileMode.OtherWrite));
            });
            FileInspector.AnalyzeReport(input, "sample.bin", new InspectionReportOptions { SnapshotDirectory = directory, MaxMemorySnapshotBytes = 1024 });
            Assert.True(observed); Assert.Empty(Directory.GetFiles(directory));
        }
        finally { Directory.Delete(directory, true); }
    }

    private sealed class ObservedStream(byte[] bytes, Action<int, Stream> observer) : MemoryStream(bytes)
    {
        public override int Read(byte[] buffer, int offset, int count)
        { var read = base.Read(buffer, offset, count); observer(read, this); return read; }
    }
    private sealed class RestoreFailureStream(byte[] bytes) : MemoryStream(bytes)
    {
        public override long Position
        {
            get => base.Position;
            set { if (value == 5 && base.Position > 5) throw new IOException("Restore interrupted."); base.Position = value; }
        }
    }
}
#endif
