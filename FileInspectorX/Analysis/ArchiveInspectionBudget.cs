using System.IO.Compression;

namespace FileInspectorX;

/// <summary>
/// Enforces the expanded-data limits for one archive inspection. A separate
/// instance is used per analysis so concurrent callers do not share counters.
/// </summary>
internal sealed partial class ArchiveInspectionBudget
{
    private readonly int _maxEntries;
    private readonly long _maxCentralDirectoryBytes;
    private readonly long _maxEntryReadBytes;
    private readonly long _maxTotalReadBytes;
    private readonly double _maxCompressionRatio;
    private readonly HashSet<string> _issues = new(StringComparer.Ordinal);
    private int _entriesVisited;
    private long _bytesRead;

    internal ArchiveInspectionBudget(
        int maxEntries,
        long maxCentralDirectoryBytes,
        long maxEntryReadBytes,
        long maxTotalReadBytes,
        double maxCompressionRatio)
    {
        _maxEntries = Math.Max(1, maxEntries);
        _maxCentralDirectoryBytes = Math.Max(1, maxCentralDirectoryBytes);
        _maxEntryReadBytes = Math.Max(1, maxEntryReadBytes);
        _maxTotalReadBytes = Math.Max(1, maxTotalReadBytes);
        _maxCompressionRatio = Math.Max(1, maxCompressionRatio);
    }

    internal bool IsComplete => _issues.Count == 0;
    internal IReadOnlyList<string> Issues => _issues.OrderBy(issue => issue, StringComparer.Ordinal).ToArray();

    internal static ArchiveInspectionBudget FromSettings()
    {
        // Snapshot all mutable settings together for this operation. Later
        // changes affect the next analysis, not an archive already in flight.
        return new ArchiveInspectionBudget(
            OperationSettings.ArchiveMaxEntries,
            OperationSettings.ArchiveMaxCentralDirectoryBytes,
            OperationSettings.ArchiveMaxEntryReadBytes,
            OperationSettings.ArchiveMaxTotalReadBytes,
            OperationSettings.ArchiveMaxCompressionRatio);
    }

    internal bool TryVisitEntry()
    {
        InspectionOperation.CheckCancellation();
        _entriesVisited++;
        if (_entriesVisited <= _maxEntries)
        {
            InspectionOperation.Current?.Metrics?.VisitArchiveEntry();
            return true;
        }

        AddIssue("archive:entry-count-limit");
        return false;
    }

    internal Stream? OpenEntry(ZipArchiveEntry entry, int requestedMaxBytes)
    {
        if (!HasAcceptableCompressionRatio(entry))
        {
            AddIssue("archive:compression-ratio-limit");
            return null;
        }

        var allowance = GetReadAllowance(entry.Length, requestedMaxBytes);
        return allowance.HasValue
            ? new BudgetedReadStream(entry.Open(), allowance.Value, CountPayloadRead)
            : null;
    }

    internal Stream? OpenTarPayload(Stream source, long payloadLength, int requestedMaxBytes)
    {
        var allowance = GetReadAllowance(payloadLength, requestedMaxBytes);
        return allowance.HasValue
            ? new BudgetedReadStream(source, Math.Min(payloadLength, allowance.Value), CountPayloadRead, leaveOpen: true)
            : null;
    }

    internal byte[]? ReadTarMetadata(Stream source, long payloadLength)
    {
        using var stream = OpenTarPayload(source, payloadLength, (int)Math.Min(int.MaxValue, payloadLength));
        if (stream == null) return null;
        using var output = new MemoryStream();
        stream.CopyTo(output);
        return output.ToArray();
    }

    private long? GetReadAllowance(long payloadLength, int requestedMaxBytes)
    {
        var remainingTotal = _maxTotalReadBytes - _bytesRead;
        if (remainingTotal <= 0)
        {
            AddIssue("archive:total-read-limit");
            return null;
        }

        var requested = Math.Max(1L, requestedMaxBytes);
        var allowance = Math.Min(requested, Math.Min(_maxEntryReadBytes, remainingTotal));
        if (allowance <= 0)
            return null;

        if (payloadLength > allowance)
        {
            if (allowance == remainingTotal)
                AddIssue("archive:total-read-limit");
            else if (requested >= _maxEntryReadBytes && allowance == _maxEntryReadBytes)
                AddIssue("archive:entry-read-limit");
        }

        return allowance;
    }

    internal string? ReadText(ZipArchiveEntry entry)
    {
        using var stream = OpenEntry(entry, checked((int)Math.Min(int.MaxValue, _maxEntryReadBytes)));
        if (stream == null)
            return null;
        using var reader = new StreamReader(stream, detectEncodingFromByteOrderMarks: true);
        return reader.ReadToEnd();
    }

    internal byte[]? ReadBytes(ZipArchiveEntry entry)
    {
        using var stream = OpenEntry(entry, checked((int)Math.Min(int.MaxValue, _maxEntryReadBytes)));
        if (stream == null)
            return null;
        using var output = new MemoryStream();
        stream.CopyTo(output);
        return output.ToArray();
    }

    internal void AddIssue(string issue)
    {
        if (!string.IsNullOrWhiteSpace(issue) && _issues.Add(issue) && issue.EndsWith("-limit", StringComparison.Ordinal))
            InspectionOperation.Current?.Metrics?.HitArchiveLimit();
    }

    private void CountPayloadRead(int bytes)
    {
        _bytesRead += bytes;
        InspectionOperation.Current?.Metrics?.ReadArchivePayload(bytes);
    }

    private bool HasAcceptableCompressionRatio(ZipArchiveEntry entry)
    {
        if (entry.Length <= 0)
            return true;
        if (entry.CompressedLength <= 0)
            return false;
        return entry.Length / (double)entry.CompressedLength <= _maxCompressionRatio;
    }

    private sealed class BudgetedReadStream : Stream
    {
        private readonly Stream _inner;
        private readonly Action<int> _onRead;
        private readonly bool _leaveOpen;
        private long _remaining;

        internal BudgetedReadStream(Stream inner, long allowance, Action<int> onRead, bool leaveOpen = false)
        {
            _inner = inner;
            _remaining = allowance;
            _onRead = onRead;
            _leaveOpen = leaveOpen;
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override int Read(byte[] buffer, int offset, int count)
        {
            InspectionOperation.CheckCancellation();
            if (_remaining <= 0)
                return 0;
            var allowed = (int)Math.Min(count, _remaining);
            var read = _inner.Read(buffer, offset, allowed);
            InspectionOperation.CheckCancellation();
            if (read > 0)
            {
                _remaining -= read;
                _onRead(read);
            }
            return read;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && !_leaveOpen)
                _inner.Dispose();
            base.Dispose(disposing);
        }
    }
}

public static partial class FileInspector
{
    private static IReadOnlyList<string>? MergeAnalysisIssues(
        IReadOnlyList<string>? existing,
        IEnumerable<string>? additional)
    {
        if (additional == null)
            return existing;

        var merged = new HashSet<string>(existing ?? Array.Empty<string>(), StringComparer.Ordinal);
        foreach (var issue in additional)
        {
            if (!string.IsNullOrWhiteSpace(issue))
                merged.Add(issue);
        }
        return merged.Count == 0 ? null : merged.OrderBy(issue => issue, StringComparer.Ordinal).ToArray();
    }

    private static void ApplyArchiveInspectionBudget(FileAnalysis analysis, ArchiveInspectionBudget budget)
    {
        if (budget.IsComplete)
            return;
        analysis.AnalysisComplete = false;
        analysis.AnalysisIssues = MergeAnalysisIssues(analysis.AnalysisIssues, budget.Issues);
    }
}
