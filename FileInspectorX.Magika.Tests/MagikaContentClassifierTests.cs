using System.Text;

namespace FileInspectorX.Magika.Tests;

public sealed class MagikaContentClassifierTests
{
    [Fact]
    public void Predict_ClassifiesCSharpWithoutUsingAFileName()
    {
        const string source = """
            using System;
            namespace Demo;
            public sealed class Sample
            {
                public static void Main() => Console.WriteLine("hello");
            }
            """;
        using var classifier = new MagikaContentClassifier();

        var prediction = classifier.Predict(Encoding.UTF8.GetBytes(source));

        Assert.IsAssignableFrom<IConcurrentLearnedContentClassifier>(classifier);
        Assert.Equal("cs", prediction.RawLabel);
        Assert.Equal("cs", prediction.OutputLabel);
        Assert.Equal("cs", prediction.Extension);
        Assert.Contains("cs", prediction.ExtensionAliases);
        Assert.Contains("csx", prediction.ExtensionAliases);
        Assert.True(prediction.Probability >= 0.5);
    }

    [Fact]
    public void Predict_UsesRuleForTinyUtf8Input()
    {
        using var classifier = new MagikaContentClassifier();

        var prediction = classifier.Predict(Encoding.UTF8.GetBytes("hello"));

        Assert.Equal("undefined", prediction.RawLabel);
        Assert.Equal("txt", prediction.OutputLabel);
        Assert.Equal(1, prediction.Probability);
    }

    [Fact]
    public void Predict_UsesUndefinedRawLabelForEmptyInput()
    {
        using var classifier = new MagikaContentClassifier();

        var prediction = classifier.Predict(ReadOnlyMemory<byte>.Empty);

        Assert.Equal("undefined", prediction.RawLabel);
        Assert.Equal("empty", prediction.OutputLabel);
    }

    [Fact]
    public void Predict_ShortStreamReadsUntilEofBeforeUtf8Rule()
    {
        var bytes = new byte[] { 0x41, 0x42, 0x43, 0xC3, 0x28, 0x44, 0x45 };
        using var classifier = new MagikaContentClassifier();
        using var stream = new ShortReadSeekableStream(bytes, maximumReadSize: 1);
        stream.Position = 2;

        var prediction = classifier.Predict(stream);

        Assert.Equal("undefined", prediction.RawLabel);
        Assert.Equal("unknown", prediction.OutputLabel);
        Assert.Equal(2, stream.Position);
    }

    [Fact]
    public void Predict_UsesEmptyRuleWhenShortStreamIsTruncatedBeforeReading()
    {
        using var classifier = new MagikaContentClassifier();
        using var stream = new TruncatedSeekableStream(reportedLength: 8);

        var prediction = classifier.Predict(stream);

        Assert.Equal("undefined", prediction.RawLabel);
        Assert.Equal("empty", prediction.OutputLabel);
    }

    [Fact]
    public void Predict_UsesModelWhenMeaningfulContentFollowsWhitespacePrefix()
    {
        var source = new string('\n', 4096) +
                     "using System; public sealed class Demo { public static void Main() { } }";
        using var classifier = new MagikaContentClassifier();

        var prediction = classifier.Predict(Encoding.UTF8.GetBytes(source));

        Assert.Equal("cs", prediction.RawLabel);
        Assert.NotEqual(1, prediction.Probability);
    }

    [Fact]
    public void Predict_RestoresStreamPosition()
    {
        using var classifier = new MagikaContentClassifier();
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(
            "function greet(name) { console.log(`hello ${name}`); }\ngreet('world');"));
        stream.Position = 7;

        var prediction = classifier.Predict(stream);

        Assert.Equal(7, stream.Position);
        Assert.Equal("javascript", prediction.RawLabel);
    }

    private sealed class ShortReadSeekableStream : Stream
    {
        private readonly MemoryStream _inner;
        private readonly int _maximumReadSize;

        internal ShortReadSeekableStream(byte[] content, int maximumReadSize)
        {
            _inner = new MemoryStream(content, writable: false);
            _maximumReadSize = maximumReadSize;
        }

        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => _inner.Length;
        public override long Position
        {
            get => _inner.Position;
            set => _inner.Position = value;
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count)
            => _inner.Read(buffer, offset, Math.Min(count, _maximumReadSize));

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

    private sealed class TruncatedSeekableStream(long reportedLength) : Stream
    {
        private long _position;

        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => reportedLength;
        public override long Position
        {
            get => _position;
            set => _position = value;
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count)
            => 0;

        public override long Seek(long offset, SeekOrigin origin)
        {
            _position = origin switch
            {
                SeekOrigin.Begin => offset,
                SeekOrigin.Current => _position + offset,
                SeekOrigin.End => reportedLength + offset,
                _ => throw new ArgumentOutOfRangeException(nameof(origin))
            };
            return _position;
        }

        public override void SetLength(long value)
            => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
            => throw new NotSupportedException();
    }
}
