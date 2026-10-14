using System.Threading;

namespace FileInspectorX;

/// <summary>Immutable source identity and bounded, callback-scoped access to one snapshot.</summary>
public sealed class InspectionContentReadRequest
{
    private Stream? _snapshot;
    private readonly CancellationToken _cancellationToken;
    private readonly object _leaseGate = new();
    private ReportSnapshotLease? _activeLease;
    private int _expired;

    internal InspectionContentReadRequest(Stream snapshot, string snapshotSha256, long sizeBytes, string displayName,
        string? detectedExtension, string? detectedMimeType, ContentKind kind, int depth,
        InspectionContentBudgets budgets, CancellationToken cancellationToken)
    {
        _snapshot = snapshot ?? throw new ArgumentNullException(nameof(snapshot));
        if (!snapshot.CanRead || !snapshot.CanSeek) throw new ArgumentException("Snapshot must support reading and seeking.", nameof(snapshot));
        SnapshotSha256 = snapshotSha256 ?? throw new ArgumentNullException(nameof(snapshotSha256));
        if (sizeBytes < 0) throw new ArgumentOutOfRangeException(nameof(sizeBytes));
        if (depth < 0) throw new ArgumentOutOfRangeException(nameof(depth));
        SizeBytes = sizeBytes;
        DisplayName = displayName ?? throw new ArgumentNullException(nameof(displayName));
        DetectedExtension = detectedExtension;
        DetectedMimeType = detectedMimeType;
        Kind = kind;
        Depth = depth;
        Budgets = budgets ?? throw new ArgumentNullException(nameof(budgets));
        _cancellationToken = cancellationToken;
    }

    /// <summary>SHA-256 of the complete analyzed snapshot.</summary>
    public string SnapshotSha256 { get; }
    /// <summary>Complete source length in bytes.</summary>
    public long SizeBytes { get; }
    /// <summary>Display name without a host filesystem path.</summary>
    public string DisplayName { get; }
    /// <summary>Detected extension, independent of the display name.</summary>
    public string? DetectedExtension { get; }
    /// <summary>Detected MIME type.</summary>
    public string? DetectedMimeType { get; }
    /// <summary>Detected source category.</summary>
    public ContentKind Kind { get; }
    /// <summary>Current report depth; the root is zero.</summary>
    public int Depth { get; }
    /// <summary>Remaining per-source and root allowances; zero is a hard limit.</summary>
    public InspectionContentBudgets Budgets { get; }

    /// <summary>Read the snapshot through a neutral, seekable, read-only stream starting at zero.</summary>
    /// <remarks>The stream expires when the callback ends. Concurrent or reentrant callbacks are rejected.
    /// Snapshot access expires when the reader returns or throws. The owner stream remains open and its position is restored.</remarks>
    public T OpenRead<T>(Func<Stream, T> read)
    {
        if (read is null) throw new ArgumentNullException(nameof(read));
        ReportSnapshotLease lease;
        lock (_leaseGate)
        {
            ThrowIfUnavailable();
            if (_activeLease is not null) throw new InvalidOperationException("A snapshot read callback is already active.");
            lease = new ReportSnapshotLease(_snapshot!, _cancellationToken, () => Volatile.Read(ref _expired) != 0);
            _activeLease = lease;
        }
        try
        {
            var result = read(lease);
            ThrowIfUnavailable();
            return result;
        }
        finally
        {
            lock (_leaseGate)
            {
                lease.Expire();
                _activeLease = null;
            }
        }
    }

    internal void Expire()
    {
        lock (_leaseGate)
        {
            Volatile.Write(ref _expired, 1);
            try { _activeLease?.Expire(); }
            finally { _snapshot = null; }
        }
    }

    private void ThrowIfUnavailable()
    {
        _cancellationToken.ThrowIfCancellationRequested();
        if (Volatile.Read(ref _expired) != 0) throw new ObjectDisposedException(nameof(InspectionContentReadRequest), "Snapshot access has expired.");
    }
}

/// <summary>Immutable finite allowances for one optional-reader invocation. Zero never means unlimited.</summary>
public sealed class InspectionContentBudgets
{
    internal InspectionContentBudgets(long maxInputBytes, int maxTextCharacters, int maxFacts, int maxFactCharacters,
        int maxArchiveEntries, long maxEntryBytes, long remainingExpandedBytes, int remainingContentCharacters,
        int remainingNestedReports, int remainingNestedDepth, int maxEntryNameCharacters, int maxDocumentUnits,
        int maxDiagnostics, long nativeExpandedBytes, long nativeReadBytes, long decompressionWorkBytes, int maxIdentifierCharacters = 1024)
    {
        MaxInputBytes = Nonnegative(maxInputBytes, nameof(maxInputBytes));
        MaxTextCharacters = Nonnegative(maxTextCharacters, nameof(maxTextCharacters));
        MaxFacts = Nonnegative(maxFacts, nameof(maxFacts));
        MaxFactCharacters = Nonnegative(maxFactCharacters, nameof(maxFactCharacters));
        MaxArchiveEntries = Nonnegative(maxArchiveEntries, nameof(maxArchiveEntries));
        MaxEntryBytes = Nonnegative(maxEntryBytes, nameof(maxEntryBytes));
        RemainingExpandedBytes = Nonnegative(remainingExpandedBytes, nameof(remainingExpandedBytes));
        RemainingContentCharacters = Nonnegative(remainingContentCharacters, nameof(remainingContentCharacters));
        RemainingNestedReports = Nonnegative(remainingNestedReports, nameof(remainingNestedReports));
        RemainingNestedDepth = Nonnegative(remainingNestedDepth, nameof(remainingNestedDepth));
        MaxEntryNameCharacters = Nonnegative(maxEntryNameCharacters, nameof(maxEntryNameCharacters));
        MaxIdentifierCharacters = Nonnegative(maxIdentifierCharacters, nameof(maxIdentifierCharacters));
        MaxDocumentUnits = Nonnegative(maxDocumentUnits, nameof(maxDocumentUnits));
        MaxDiagnostics = Nonnegative(maxDiagnostics, nameof(maxDiagnostics));
        NativeExpandedBytes = Nonnegative(nativeExpandedBytes, nameof(nativeExpandedBytes));
        NativeReadBytes = Nonnegative(nativeReadBytes, nameof(nativeReadBytes));
        DecompressionWorkBytes = Nonnegative(decompressionWorkBytes, nameof(decompressionWorkBytes));
    }

    /// <summary>Maximum complete bytes for this source.</summary>
    public long MaxInputBytes { get; }
    /// <summary>Maximum retained primary-text characters.</summary>
    public int MaxTextCharacters { get; }
    /// <summary>Maximum retained facts and dictionary entries.</summary>
    public int MaxFacts { get; }
    /// <summary>Maximum characters in one fact or bounded scalar field.</summary>
    public int MaxFactCharacters { get; }
    /// <summary>Maximum inventory entries visited.</summary>
    public int MaxArchiveEntries { get; }
    /// <summary>Maximum complete bytes for one selected member.</summary>
    public long MaxEntryBytes { get; }
    /// <summary>Remaining aggregate selected-member bytes.</summary>
    public long RemainingExpandedBytes { get; }
    /// <summary>Remaining aggregate source-derived characters across the root.</summary>
    public int RemainingContentCharacters { get; }
    /// <summary>Remaining descendant reports across the root.</summary>
    public int RemainingNestedReports { get; }
    /// <summary>Remaining descendant depth.</summary>
    public int RemainingNestedDepth { get; }
    /// <summary>Maximum retained characters in a member name.</summary>
    public int MaxEntryNameCharacters { get; }
    /// <summary>Maximum complete reader, member, field or logical-location identifier characters.</summary>
    public int MaxIdentifierCharacters { get; }
    /// <summary>Maximum retained logical unit outcomes.</summary>
    public int MaxDocumentUnits { get; }
    /// <summary>Maximum retained diagnostics and omissions.</summary>
    public int MaxDiagnostics { get; }
    /// <summary>Reserved native model/source expansion allowance.</summary>
    public long NativeExpandedBytes { get; }
    /// <summary>Reserved cumulative native source-read allowance.</summary>
    public long NativeReadBytes { get; }
    /// <summary>Reserved cumulative decompression-work allowance.</summary>
    public long DecompressionWorkBytes { get; }

    private static int Nonnegative(int value, string name) => value >= 0 ? value : throw new ArgumentOutOfRangeException(name);
    private static long Nonnegative(long value, string name) => value >= 0 ? value : throw new ArgumentOutOfRangeException(name);
}
