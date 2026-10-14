using System.Threading;

namespace FileInspectorX.OfficeIMO;

/// <summary>Counts actual source reads without exposing or owning the callback lease.</summary>
internal sealed class NativeReadStream : Stream
{
    private readonly Stream _source;
    private readonly long _maximum;
    private readonly CancellationToken _token;
    internal NativeReadStream(Stream source, long maximum, CancellationToken token) { _source = source; _maximum = maximum; _token = token; }
    internal long BytesRead { get; private set; }
    public override bool CanRead => _source.CanRead;
    public override bool CanSeek => _source.CanSeek;
    public override bool CanWrite => false;
    public override long Length => _source.Length;
    public override long Position { get => _source.Position; set { _token.ThrowIfCancellationRequested(); _source.Position = value; } }
    public override int Read(byte[] buffer, int offset, int count)
    {
        _token.ThrowIfCancellationRequested();
        if (count > 0 && BytesRead == _maximum && _source.Position < _source.Length) throw Exceeded();
        int admitted = (int)Math.Min(count, _maximum - BytesRead);
        int read = _source.Read(buffer, offset, admitted);
        BytesRead = checked(BytesRead + read);
        _token.ThrowIfCancellationRequested();
        return read;
    }
    public override int ReadByte()
    {
        _token.ThrowIfCancellationRequested();
        if (BytesRead == _maximum && _source.Position < _source.Length) throw Exceeded();
        int value = _source.ReadByte();
        if (value >= 0) BytesRead = checked(BytesRead + 1);
        _token.ThrowIfCancellationRequested();
        return value;
    }
    public override long Seek(long offset, SeekOrigin origin) { _token.ThrowIfCancellationRequested(); return _source.Seek(offset, origin); }
    public override void Flush() { }
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    private InspectionContentLimitException Exceeded() => new(InspectionContentLimitDomain.Resource,
        "officeimo:native-read-limit", "NativeReadBytes", _maximum, BytesRead + 1);
}
