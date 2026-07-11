using System.IO.Compression;

namespace FileInspectorX;

/// <summary>
/// Enforces the expanded-data limits for one archive inspection. A separate
/// instance is used per analysis so concurrent callers do not share counters.
/// </summary>
internal sealed class ArchiveInspectionBudget
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
            Settings.ArchiveMaxEntries,
            Settings.ArchiveMaxCentralDirectoryBytes,
            Settings.ArchiveMaxEntryReadBytes,
            Settings.ArchiveMaxTotalReadBytes,
            Settings.ArchiveMaxCompressionRatio);
    }

    internal bool CheckCentralDirectory(Stream stream, out int? declaredEntryCount)
    {
        declaredEntryCount = null;
        if (!stream.CanSeek)
        {
            AddIssue("archive:seek-required");
            return false;
        }
        if (stream.Length < 22)
        {
            AddIssue("archive:central-directory-invalid");
            return false;
        }

        var originalPosition = stream.Position;
        try
        {
            var bytesToRead = (int)Math.Min(stream.Length, 65_557L);
            var tail = new byte[bytesToRead];
            stream.Position = stream.Length - bytesToRead;
            var read = ReadFully(stream, tail, 0, tail.Length);

            for (var offset = read - 22; offset >= 0; offset--)
            {
                if (ReadUInt32(tail, offset) != 0x06054b50)
                    continue;

                var commentLength = ReadUInt16(tail, offset + 20);
                if (offset + 22 + commentLength != read)
                    continue;

                var diskNumber = ReadUInt16(tail, offset + 4);
                var directoryDisk = ReadUInt16(tail, offset + 6);
                var entriesOnDisk = ReadUInt16(tail, offset + 8);
                var entryCount = ReadUInt16(tail, offset + 10);
                var directoryBytes = ReadUInt32(tail, offset + 12);
                declaredEntryCount = entryCount;

                if (diskNumber != 0 || directoryDisk != 0 || entriesOnDisk != entryCount)
                {
                    AddIssue("archive:multi-disk-unsupported");
                    return false;
                }

                // Sentinel values indicate ZIP64. Refuse to materialize its
                // entries unless a future ZIP64 preflight reads and validates
                // the 64-bit directory metadata first.
                if (entryCount == ushort.MaxValue || directoryBytes == uint.MaxValue)
                {
                    AddIssue("archive:zip64-preflight-limit");
                    return false;
                }

                if (entryCount > _maxEntries)
                    AddIssue("archive:entry-count-limit");
                if (directoryBytes > _maxCentralDirectoryBytes)
                    AddIssue("archive:directory-size-limit");
                if (!IsComplete)
                    return false;

                var eocdPosition = stream.Length - read + offset;
                if (!ValidateCentralDirectoryLayout(stream, eocdPosition, directoryBytes, entryCount))
                    continue;

                return true;
            }

            AddIssue("archive:central-directory-invalid");
            return false;
        }
        finally
        {
            stream.Position = originalPosition;
        }
    }

    internal bool TryVisitEntry()
    {
        _entriesVisited++;
        if (_entriesVisited <= _maxEntries)
            return true;

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

        if (entry.Length > allowance)
        {
            if (allowance == remainingTotal)
                AddIssue("archive:total-read-limit");
            else if (requested >= _maxEntryReadBytes && allowance == _maxEntryReadBytes)
                AddIssue("archive:entry-read-limit");
        }

        return new BudgetedReadStream(entry.Open(), allowance, bytes => _bytesRead += bytes);
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
        if (!string.IsNullOrWhiteSpace(issue))
            _issues.Add(issue);
    }

    private bool HasAcceptableCompressionRatio(ZipArchiveEntry entry)
    {
        if (entry.Length <= 0)
            return true;
        if (entry.CompressedLength <= 0)
            return false;
        return entry.Length / (double)entry.CompressedLength <= _maxCompressionRatio;
    }

    private static int ReadFully(Stream stream, byte[] buffer, int offset, int count)
    {
        var total = 0;
        while (total < count)
        {
            var read = stream.Read(buffer, offset + total, count - total);
            if (read <= 0) break;
            total += read;
        }
        return total;
    }

    private static bool ValidateCentralDirectoryLayout(Stream stream, long eocdPosition, uint directoryBytes, ushort entryCount)
    {
        if (directoryBytes == 0)
            return entryCount == 0;
        if (entryCount == 0 || directoryBytes > eocdPosition)
            return false;

        var directoryStart = eocdPosition - directoryBytes;
        var header = new byte[46];
        long consumed = 0;
        stream.Position = directoryStart;

        for (var index = 0; index < entryCount; index++)
        {
            if (directoryBytes - consumed < header.Length || ReadFully(stream, header, 0, header.Length) != header.Length)
                return false;
            if (ReadUInt32(header, 0) != 0x02014b50)
                return false;

            var variableLength = (long)ReadUInt16(header, 28) + ReadUInt16(header, 30) + ReadUInt16(header, 32);
            consumed += header.Length + variableLength;
            if (consumed > directoryBytes)
                return false;
            stream.Seek(variableLength, SeekOrigin.Current);
        }

        if (consumed == directoryBytes)
            return true;

        // The optional central-directory digital-signature record is six bytes
        // plus its declared payload and must consume the exact remainder.
        var signatureHeader = new byte[6];
        if (directoryBytes - consumed < signatureHeader.Length || ReadFully(stream, signatureHeader, 0, signatureHeader.Length) != signatureHeader.Length)
            return false;
        if (ReadUInt32(signatureHeader, 0) != 0x05054b50)
            return false;
        consumed += signatureHeader.Length + ReadUInt16(signatureHeader, 4);
        return consumed == directoryBytes;
    }

    private static ushort ReadUInt16(byte[] buffer, int offset)
    {
        return (ushort)(buffer[offset] | (buffer[offset + 1] << 8));
    }

    private static uint ReadUInt32(byte[] buffer, int offset)
    {
        return (uint)(buffer[offset] |
            (buffer[offset + 1] << 8) |
            (buffer[offset + 2] << 16) |
            (buffer[offset + 3] << 24));
    }

    private sealed class BudgetedReadStream : Stream
    {
        private readonly Stream _inner;
        private readonly Action<int> _onRead;
        private long _remaining;

        internal BudgetedReadStream(Stream inner, long allowance, Action<int> onRead)
        {
            _inner = inner;
            _remaining = allowance;
            _onRead = onRead;
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
            if (_remaining <= 0)
                return 0;
            var allowed = (int)Math.Min(count, _remaining);
            var read = _inner.Read(buffer, offset, allowed);
            if (read > 0)
            {
                _remaining -= read;
                _onRead(read);
            }
            return read;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
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
