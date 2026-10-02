namespace FileInspectorX.Tests;

// A seekable ZIP with a logical gap before its directory. This exercises real
// 64-bit offsets through ZipArchive without creating a multi-gigabyte file.
internal sealed class SparseZipTestStream : Stream
{
    private readonly byte[] _bytes;
    private readonly long _directoryStart;
    private readonly long _gap = (long)uint.MaxValue + 1;
    private long _position;
    private bool _disposed;

    internal SparseZipTestStream(byte[] classic)
    {
        using var reader = new BinaryReader(new MemoryStream(classic));
        reader.BaseStream.Position = classic.Length - 6;
        _directoryStart = reader.ReadUInt32();
        _bytes = ZipTestArchive.WithZip64Footer(classic);
        var record = _bytes.Length - 98;
        ZipTestArchive.Write64(_bytes, record + 48, (ulong)(_directoryStart + _gap));
        ZipTestArchive.Write64(_bytes, _bytes.Length - 34, (ulong)(record + _gap));
    }

    public override bool CanRead => !_disposed;
    public override bool CanSeek => !_disposed;
    public override bool CanWrite => false;
    public override long Length => _bytes.Length + _gap;
    public override long Position { get => _position; set => _position = value >= 0 ? value : throw new ArgumentOutOfRangeException(nameof(value)); }
    public override int Read(byte[] buffer, int offset, int count)
    {
        if (_disposed) throw new ObjectDisposedException(nameof(SparseZipTestStream));
        int read = (int)Math.Min(count, Math.Max(0, Length - _position));
        int remaining = read;
        while (remaining > 0)
        {
            int available;
            if (_position < _directoryStart)
            {
                available = (int)Math.Min(remaining, _directoryStart - _position);
                Buffer.BlockCopy(_bytes, (int)_position, buffer, offset, available);
            }
            else if (_position < _directoryStart + _gap)
            {
                available = (int)Math.Min(remaining, _directoryStart + _gap - _position);
                Array.Clear(buffer, offset, available);
            }
            else
            {
                available = remaining;
                Buffer.BlockCopy(_bytes, (int)(_position - _gap), buffer, offset, available);
            }
            offset += available;
            remaining -= available;
            _position += available;
        }
        return read;
    }
    public override long Seek(long offset, SeekOrigin origin) => Position = checked(offset + (origin == SeekOrigin.Begin ? 0 : origin == SeekOrigin.Current ? Position : Length));
    public override void Flush() { }
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    protected override void Dispose(bool disposing) { _disposed = true; base.Dispose(disposing); }
}
