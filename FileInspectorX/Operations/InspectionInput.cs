namespace FileInspectorX;

/// <summary>Retains content separately from the optional filesystem path and name hint.</summary>
internal sealed class InspectionInput : IDisposable
{
    private readonly Stream? _stream;
    private long? _originalPosition;
    private ZipInspectionContext? _zip;
    private bool _disposed;
    internal string? Path { get; }
    internal string Name { get; }
    internal bool HasPath => Path != null;

    private InspectionInput(string? path, Stream? stream, string? name)
    {
        Path = path; _stream = stream; Name = name ?? string.Empty;
    }

    internal static InspectionInput FromPath(string path) => new(path, null, path);

    internal static InspectionInput FromStream(Stream stream, string? fileName, bool requireSeek = true)
    {
        if (stream == null) throw new ArgumentNullException(nameof(stream));
        if (!stream.CanRead) throw new ArgumentException("Inspection requires a readable stream.", nameof(stream));
        if (requireSeek && !stream.CanSeek)
            throw new NotSupportedException("Full analysis requires a seekable stream. Use Detect or detection-only Inspect for forward-only input.");
        return new(null, stream, fileName);
    }

    internal Stream OpenRead()
    {
        InspectionOperation.CheckCancellation();
        if (HasPath) return OperationReadStream.Open(Path!);
        var token = InspectionOperation.Current?.Options.CancellationToken ?? default;
        return _stream!.CanSeek
            ? OperationReadStream.BorrowRetained(_stream, token)
            : OperationReadStream.Borrow(_stream, token);
    }

    internal void RetainPosition()
    {
        if (!_originalPosition.HasValue && _stream?.CanSeek == true)
            _originalPosition = _stream.Position;
    }

    internal bool TryOpenZip(ArchiveInspectionBudget budget, out System.IO.Compression.ZipArchive? archive, out int? declaredEntryCount)
    {
        _zip ??= new ZipInspectionContext(this, budget);
        return _zip.TryOpen(budget, out archive, out declaredEntryCount);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try { _zip?.Dispose(); }
        finally
        {
            if (_originalPosition.HasValue)
                try { _stream!.Seek(_originalPosition.Value, SeekOrigin.Begin); } catch { }
        }
    }
}
