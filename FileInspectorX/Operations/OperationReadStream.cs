using System.Threading;

namespace FileInspectorX;

// Leaves seek/position available after cancellation so the facade can restore borrowed streams.
internal sealed class OperationReadStream : Stream
{
    private readonly Stream _inner;
    private readonly CancellationToken _token;
    private readonly bool _leaveOpen;

    internal OperationReadStream(Stream inner, CancellationToken token, bool leaveOpen)
    { _inner = inner; _token = token; _leaveOpen = leaveOpen; }

    internal static Stream Borrow(Stream stream, CancellationToken token)
        => token.CanBeCanceled ? new OperationReadStream(stream, token, leaveOpen: true) : stream;

    internal static Stream Open(string path)
    {
        InspectionOperation.CheckCancellation();
        var stream = File.OpenRead(path);
        var token = InspectionOperation.Current?.Options.CancellationToken ?? default;
        return token.CanBeCanceled ? new OperationReadStream(stream, token, leaveOpen: false) : stream;
    }

    public override bool CanRead => _inner.CanRead;
    public override bool CanSeek => _inner.CanSeek;
    public override bool CanWrite => false;
    public override long Length => _inner.Length;
    public override long Position { get => _inner.Position; set => _inner.Position = value; }
    public override long Seek(long offset, SeekOrigin origin) => _inner.Seek(offset, origin);
    public override int Read(byte[] buffer, int offset, int count)
    {
        _token.ThrowIfCancellationRequested();
        int read = _inner.Read(buffer, offset, count);
        _token.ThrowIfCancellationRequested();
        return read;
    }
    public override int ReadByte()
    {
        _token.ThrowIfCancellationRequested();
        int value = _inner.ReadByte();
        _token.ThrowIfCancellationRequested();
        return value;
    }
#if NET8_0_OR_GREATER
    public override int Read(Span<byte> buffer)
    {
        _token.ThrowIfCancellationRequested();
        int read = _inner.Read(buffer);
        _token.ThrowIfCancellationRequested();
        return read;
    }
#endif
    protected override void Dispose(bool disposing)
    {
        if (disposing && !_leaveOpen) _inner.Dispose();
        base.Dispose(disposing);
    }
    public override void Flush() { }
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
