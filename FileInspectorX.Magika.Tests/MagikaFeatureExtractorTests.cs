using System.Text;

namespace FileInspectorX.Magika.Tests;

public sealed class MagikaFeatureExtractorTests
{
    [Fact]
    public void Extract_StripsAndPadsBeginningAndEndLikeUpstream()
    {
        var config = new MagikaModelConfig
        {
            BeginningSize = 4,
            MiddleSize = 0,
            EndSize = 4,
            BlockSize = 4096,
            PaddingToken = 256
        };

        var features = MagikaFeatureExtractor.Extract(
            Encoding.ASCII.GetBytes("  abc  "),
            config);

        Assert.Equal(new[] { 97, 98, 99, 32, 32, 97, 98, 99 }, features);
    }

    [Fact]
    public void Extract_RestoresStreamPosition()
    {
        var config = new MagikaModelConfig
        {
            BeginningSize = 4,
            MiddleSize = 0,
            EndSize = 4,
            BlockSize = 4096,
            PaddingToken = 256
        };
        using var stream = new MemoryStream(Encoding.ASCII.GetBytes("abcdefgh"));
        stream.Position = 3;

        _ = MagikaFeatureExtractor.Extract(stream, config);

        Assert.Equal(3, stream.Position);
    }

    [Fact]
    public void Extract_DoesNotTreatUnreadBytesAsContentAfterTruncation()
    {
        var config = new MagikaModelConfig
        {
            BeginningSize = 4,
            MiddleSize = 0,
            EndSize = 4,
            BlockSize = 4096,
            PaddingToken = 256
        };
        using var stream = new ReportedLengthStream(
            Encoding.ASCII.GetBytes("abc"),
            reportedLength: 8);

        var features = MagikaFeatureExtractor.Extract(stream, config);

        Assert.Equal(new[] { 97, 98, 99, 256, 256, 97, 98, 99 }, features);
    }

    private sealed class ReportedLengthStream : Stream
    {
        private readonly MemoryStream _inner;
        private readonly long _reportedLength;

        internal ReportedLengthStream(byte[] content, long reportedLength)
        {
            _inner = new MemoryStream(content, writable: false);
            _reportedLength = reportedLength;
        }

        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => _reportedLength;
        public override long Position
        {
            get => _inner.Position;
            set => _inner.Position = value;
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count)
            => _inner.Read(buffer, offset, count);

        public override long Seek(long offset, SeekOrigin origin)
            => _inner.Seek(offset, origin);

        public override void SetLength(long value)
            => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
            => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
                _inner.Dispose();
            base.Dispose(disposing);
        }
    }
}
