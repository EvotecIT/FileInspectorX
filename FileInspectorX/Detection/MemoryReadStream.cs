namespace FileInspectorX;

/// <summary>A seekable, read-only adapter that keeps complete in-memory input without copying it.</summary>
internal sealed class MemoryReadStream : Stream
{
    private readonly ReadOnlyMemory<byte> _memory;
    private long _position;

    internal MemoryReadStream(ReadOnlyMemory<byte> memory) => _memory = memory;
    public override bool CanRead => true;
    public override bool CanSeek => true;
    public override bool CanWrite => false;
    public override long Length => _memory.Length;
    public override long Position { get => _position; set { if (value < 0) throw new ArgumentOutOfRangeException(nameof(value)); _position = value; } }
    public override int Read(byte[] buffer, int offset, int count)
    {
        if (buffer == null) throw new ArgumentNullException(nameof(buffer));
        if (offset < 0 || count < 0 || offset > buffer.Length - count) throw new ArgumentOutOfRangeException(nameof(count));
        int available = (int)Math.Min(count, Math.Max(0, Length - _position));
        if (available > 0) _memory.Span.Slice((int)_position, available).CopyTo(buffer.AsSpan(offset, available));
        _position += available;
        return available;
    }
    public override long Seek(long offset, SeekOrigin origin)
    {
        Position = checked(offset + (origin == SeekOrigin.Begin ? 0 : origin == SeekOrigin.Current ? Position : origin == SeekOrigin.End ? Length : throw new ArgumentOutOfRangeException(nameof(origin))));
        return Position;
    }
    public override void Flush() { }
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
