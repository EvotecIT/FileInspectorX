using Xunit;
using System.IO.Compression;

namespace FileInspectorX.Tests;

public sealed class StreamDetectionTests
{
    [Fact]
    public void Detect_ReadsUntilHeaderIsFilled_WhenStreamReturnsShortReads()
    {
        var bytes = new byte[]
        {
            (byte)'%', (byte)'P', (byte)'D', (byte)'F', (byte)'-', (byte)'1', (byte)'.', (byte)'7',
            (byte)'\n', 0, 0, 0, 0, 0, 0, 0
        };
        using var stream = new ShortReadStream(bytes, maximumReadSize: 1);
        stream.Position = 7;

        var result = FileInspector.Detect(stream);

        Assert.Equal("pdf", result?.Extension);
        Assert.Equal(7, stream.Position);
    }

    [Fact]
    public void Detect_DoesNotMaterializeZipFromNonSeekableStream()
    {
        using var archiveBytes = new MemoryStream();
        using (var archive = new ZipArchive(archiveBytes, ZipArchiveMode.Create, leaveOpen: true))
        {
            var entry = archive.CreateEntry("payload.bin", CompressionLevel.NoCompression);
            using var entryStream = entry.Open();
            var payload = new byte[2 * 1024 * 1024];
            new Random(42).NextBytes(payload);
            entryStream.Write(payload, 0, payload.Length);
        }

        using var stream = new NonSeekableReadStream(archiveBytes.ToArray());
        var result = FileInspector.Detect(stream);

        Assert.Equal("zip", result?.Extension);
        Assert.InRange(stream.BytesRead, 1, Math.Max(256, Math.Min(Settings.HeaderReadBytes, 1 << 20)) + 1);
    }

    private sealed class ShortReadStream : Stream
    {
        private readonly MemoryStream _inner;
        private readonly int _maximumReadSize;

        internal ShortReadStream(byte[] bytes, int maximumReadSize)
        {
            _inner = new MemoryStream(bytes, writable: false);
            _maximumReadSize = maximumReadSize;
        }

        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => _inner.Length;
        public override long Position { get => _inner.Position; set => _inner.Position = value; }
        public override void Flush() => _inner.Flush();
        public override long Seek(long offset, SeekOrigin origin) => _inner.Seek(offset, origin);
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, Math.Min(count, _maximumReadSize));

        protected override void Dispose(bool disposing)
        {
            if (disposing) _inner.Dispose();
            base.Dispose(disposing);
        }
    }

    private sealed class NonSeekableReadStream : Stream
    {
        private readonly MemoryStream _inner;

        internal NonSeekableReadStream(byte[] bytes) => _inner = new MemoryStream(bytes, writable: false);

        internal int BytesRead { get; private set; }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count)
        {
            var read = _inner.Read(buffer, offset, count);
            BytesRead += read;
            return read;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) _inner.Dispose();
            base.Dispose(disposing);
        }
    }
}
