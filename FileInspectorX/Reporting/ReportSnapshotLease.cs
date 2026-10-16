using System.Threading;
using System.Threading.Tasks;

namespace FileInspectorX;

/// <summary>Neutral stream facade that expires without disposing the snapshot owner or revealing its concrete type.</summary>
internal sealed class ReportSnapshotLease : Stream
{
    private Stream? _snapshot;
    private readonly CancellationToken _cancellationToken;
    private readonly Func<bool> _requestExpired;
    private readonly long _originalPosition;
    private readonly bool _ownsSnapshot;
    private readonly object _operationGate = new();
    private bool _expired;

    internal ReportSnapshotLease(Stream snapshot, CancellationToken cancellationToken, Func<bool> requestExpired,
        bool ownsSnapshot = false)
    {
        _snapshot = snapshot;
        _cancellationToken = cancellationToken;
        _requestExpired = requestExpired;
        _originalPosition = snapshot.Position;
        _ownsSnapshot = ownsSnapshot;
        snapshot.Position = 0;
    }

    internal static Stream OpenDetached(byte[] content) => new ReportSnapshotLease(
        new MemoryStream(content, writable: false), CancellationToken.None, () => false, ownsSnapshot: true);

    public override bool CanRead { get { lock (_operationGate) return IsAvailable && _snapshot!.CanRead; } }
    public override bool CanSeek { get { lock (_operationGate) return IsAvailable && _snapshot!.CanSeek; } }
    public override bool CanWrite => false;
    public override long Length { get { lock (_operationGate) { Check(); return _snapshot!.Length; } } }
    public override long Position
    {
        get { lock (_operationGate) { Check(); return _snapshot!.Position; } }
        set { lock (_operationGate) { Check(); _snapshot!.Position = value; Check(); } }
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        lock (_operationGate)
        {
            Check();
            var read = _snapshot!.Read(buffer, offset, count);
            Check();
            return read;
        }
    }

    public override int ReadByte()
    {
        lock (_operationGate)
        {
            Check();
            var read = _snapshot!.ReadByte();
            Check();
            return read;
        }
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        lock (_operationGate)
        {
            Check();
            var position = _snapshot!.Seek(offset, origin);
            Check();
            return position;
        }
    }

    public override void Flush() { lock (_operationGate) Check(); }
    public override void SetLength(long value) { lock (_operationGate) { Check(); throw ReadOnly(); } }
    public override void Write(byte[] buffer, int offset, int count) { lock (_operationGate) { Check(); throw ReadOnly(); } }
    public override void WriteByte(byte value) { lock (_operationGate) { Check(); throw ReadOnly(); } }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var read = Read(buffer, offset, count);
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(read);
    }

#if NET8_0_OR_GREATER
    public override int Read(Span<byte> buffer)
    {
        lock (_operationGate)
        {
            Check();
            var read = _snapshot!.Read(buffer);
            Check();
            return read;
        }
    }

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var read = Read(buffer.Span);
        cancellationToken.ThrowIfCancellationRequested();
        return new ValueTask<int>(read);
    }

    public override void Write(ReadOnlySpan<byte> buffer) { lock (_operationGate) { Check(); throw ReadOnly(); } }
#endif

    internal void Expire()
    {
        lock (_operationGate)
        {
            if (_expired) return;
            _expired = true;
            var snapshot = _snapshot;
            _snapshot = null;
            if (snapshot is null) return;
            try { snapshot.Position = _originalPosition; }
            finally { if (_ownsSnapshot) snapshot.Dispose(); }
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) Expire();
        base.Dispose(disposing);
    }

    private bool IsAvailable => !_expired && !_requestExpired() && !_cancellationToken.IsCancellationRequested;

    private void Check()
    {
        _cancellationToken.ThrowIfCancellationRequested();
        if (_expired || _requestExpired()) throw new ObjectDisposedException(nameof(ReportSnapshotLease), "Snapshot access has expired.");
    }

    private static NotSupportedException ReadOnly() => new("Snapshot access is read-only.");
}
