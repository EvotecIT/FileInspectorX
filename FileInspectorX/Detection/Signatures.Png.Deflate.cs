namespace FileInspectorX;

/// <summary>
/// PNG-specific stream helpers used to preserve exact DEFLATE framing evidence.
/// </summary>
internal static partial class Signatures
{
    /// <summary>
    /// Prevents <see cref="System.IO.Compression.DeflateStream"/> from reading ahead
    /// across the logical end of a DEFLATE stream, so trailing compressed bytes remain
    /// observable to the PNG validator.
    /// </summary>
    private sealed class SingleByteReadStream : Stream
    {
        private readonly Stream _inner;

        internal SingleByteReadStream(Stream inner) => _inner = inner;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
            => count == 0 ? 0 : _inner.Read(buffer, offset, 1);

        public override int ReadByte() => _inner.ReadByte();
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
