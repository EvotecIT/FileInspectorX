using System.Diagnostics;

namespace FileInspectorX.Prototypes.FileSystem;

/// <summary>Bulk sector reads are separate from the retained logical-record diagnostic reader.</summary>
public enum MftReadMode { Bulk, RecordApi }

/// <summary>Bounded NTFS metadata and long-name link snapshot acquired through Windows file-record controls.</summary>
public sealed class MftSnapshot
{
    private readonly Dictionary<ulong, List<NtfsLink>> _children;
    private readonly Dictionary<ulong, NtfsFileRecord> _records;
    public string VolumeRoot { get; }
    public DateTime CapturedUtc { get; }
    public long MftBytes { get; }
    public int RecordCount { get; }
    /// <summary>Conservative index accounting, including adjacency overhead; not a managed heap measurement.</summary>
    public long EstimatedIndexBytes { get; }
    public long NativeBytesRead { get; }
    public int LinkCount { get; }
    public int ExtensionRecordCount { get; }
    public int IncompleteRecordCount { get; }
    /// <summary>Identity-checked live link-count probes used to validate contradictory file-record header hints.</summary>
    public int LinkCountProbeCount { get; }
    public string MetadataSource { get; }
    public string ReadRoute { get; }
    public int VolumeReadError { get; }
    public long BulkReadCalls { get; }
    public long RawSlots { get; }
    public double BulkReadMilliseconds { get; }
    public double ParseMilliseconds { get; }

    private MftSnapshot(string volumeRoot, long mftBytes, Dictionary<ulong, List<NtfsLink>> children,
        Dictionary<ulong, NtfsFileRecord> records, int count, int links, int extensions, int incomplete,
        long estimatedBytes, long nativeBytesRead, int linkCountProbes, WindowsMftVolume volume, MftReadMode readMode)
    {
        VolumeRoot = volumeRoot; MftBytes = mftBytes; _children = children; RecordCount = count;
        EstimatedIndexBytes = estimatedBytes; NativeBytesRead = nativeBytesRead; CapturedUtc = DateTime.UtcNow;
        _records = records; LinkCount = links; ExtensionRecordCount = extensions; IncompleteRecordCount = incomplete;
        LinkCountProbeCount = linkCountProbes;
        MetadataSource = readMode == MftReadMode.Bulk ? "BulkMftExtents" : "FSCTL_GET_NTFS_FILE_RECORD";
        ReadRoute = volume.ReadRoute; VolumeReadError = volume.VolumeReadError; BulkReadCalls = volume.BulkReadCalls;
        RawSlots = volume.RawSlots; BulkReadMilliseconds = volume.BulkReadMilliseconds; ParseMilliseconds = volume.ParseMilliseconds;
    }

    /// <summary>Reads every in-use base and extension record, merging by full sequence-qualified identity.</summary>
    /// <remarks>Cancellation and timeout are checked between synchronous control calls and parsed records, not inside a kernel call.</remarks>
    public static Task<MftSnapshot> CaptureAsync(string root, CancellationToken cancellationToken,
        long maximumMftBytes = 512L * 1024 * 1024, int maximumIndexRecords = 4_000_000,
        long maximumIndexBytes = 2L * 1024 * 1024 * 1024, TimeSpan? maximumCaptureTime = null, MftReadMode readMode = MftReadMode.Bulk)
    {
        cancellationToken.ThrowIfCancellationRequested();
        CheckRoot(root);
        var volumeRoot = Path.GetPathRoot(Path.GetFullPath(root))!;
        var drive = new DriveInfo(volumeRoot);
        if (drive.DriveType == DriveType.Network || !string.Equals(drive.DriveFormat, "NTFS", StringComparison.OrdinalIgnoreCase))
            throw new NotSupportedException("MFT capture requires a local NTFS volume.");
        if (maximumIndexRecords <= 0 || maximumIndexBytes <= 0) throw new ArgumentOutOfRangeException(nameof(maximumIndexRecords));
        var timeLimit = maximumCaptureTime ?? TimeSpan.FromMinutes(2);
        if (timeLimit <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(maximumCaptureTime));
        if (readMode != MftReadMode.Bulk && readMode != MftReadMode.RecordApi) throw new ArgumentOutOfRangeException(nameof(readMode));
        using var volume = new WindowsMftVolume(volumeRoot, maximumMftBytes);
        var records = new Dictionary<ulong, NtfsFileRecord>();
        var extensions = new List<NtfsFileRecord>();
        var timer = Stopwatch.StartNew();
        int count = 0;
        long estimatedBytes = 0;
        foreach (var record in readMode == MftReadMode.Bulk ? volume.EnumerateBulk(volumeRoot, cancellationToken, CheckBudget) : volume.EnumerateFileRecords(cancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (timer.Elapsed > timeLimit) throw new NotSupportedException("MFT capture exceeded its explicit time budget.");
            estimatedBytes = checked(estimatedBytes + 512L);
            foreach (var link in record.Links) estimatedBytes = checked(estimatedBytes + 192L + 2L * link.Name.Length);
            if (++count > maximumIndexRecords || estimatedBytes > maximumIndexBytes)
                throw new NotSupportedException("MFT metadata index exceeded its explicit budget: records=" + count + ", estimated bytes=" + estimatedBytes + ".");
            if (record.BaseId == 0) records.Add(record.Id, record);
            else extensions.Add(record);
        }
        foreach (var extension in extensions)
        {
            CheckBudget();
            if (!records.TryGetValue(extension.BaseId, out var owner))
                throw new IOException("Extension base identity disappeared during MFT acquisition. Extension " +
                    extension.Id.ToString("X16") + ", base " + extension.BaseId.ToString("X16") + ".");
            owner.Merge(extension);
        }
        var children = new Dictionary<ulong, List<NtfsLink>>();
        int links = 0, incomplete = 0, linkCountProbes = 0;
        foreach (var record in records.Values)
        {
            CheckBudget();
            if (record.Directory) record.Attributes |= FileAttributes.Directory;
            // Index-only NTFS files can have no unnamed DATA stream; their default-stream length is zero.
            if (!record.HasStandardInformation) record.Incomplete = "Missing required standard information in captured file records.";
            else if (record.NameAttributeCount != record.LinkCount)
            {
                linkCountProbes++;
                if (!volume.TryGetLinkCount(record.Id, out uint liveLinks, out var failure)) record.Incomplete = failure;
                else if (liveLinks != record.Links.Count)
                    record.Incomplete = "Captured long-name count " + record.Links.Count + " differs from live hardlink count " + liveLinks + ".";
            }
            if (record.Incomplete != null) incomplete++;
            var seen = record.Links.Count > 1 ? new HashSet<string>(StringComparer.Ordinal) : null;
            foreach (var link in record.Links)
            {
                if (seen != null && !seen.Add(link.ParentId.ToString("X16") + ":" + link.Name))
                    throw new IOException("Duplicate FILE_NAME link in a captured record.");
                link.Owner = record;
                if (!children.TryGetValue(link.ParentId, out var siblings)) children.Add(link.ParentId, siblings = new List<NtfsLink>());
                siblings.Add(link); links++;
            }
        }
        cancellationToken.ThrowIfCancellationRequested();
        if (timer.Elapsed > timeLimit) throw new NotSupportedException("MFT capture exceeded its explicit time budget.");
        return Task.FromResult(new MftSnapshot(volumeRoot, volume.MftBytes, children, records, count,
            links, extensions.Count, incomplete, estimatedBytes, volume.BytesRead, linkCountProbes, volume, readMode));

        void CheckBudget()
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (timer.Elapsed > timeLimit) throw new NotSupportedException("MFT capture exceeded its explicit time budget.");
        }
    }

    internal static void CheckRoot(string root)
    {
        if (!System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
            throw new PlatformNotSupportedException("Windows MFT APIs require Windows.");
        for (var current = Path.GetFullPath(root); current != null; current = Path.GetDirectoryName(current))
            if ((System.IO.File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new NotSupportedException("MFT queries through a reparse root or ancestor use normal enumeration.");
    }

    internal IEnumerable<FileSystemEntry> Enumerate(string root, QueryOptions options)
    {
        if (!string.Equals(Path.GetPathRoot(root), VolumeRoot, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Snapshot belongs to a different volume.", nameof(root));
        var pending = new Stack<(ulong Id, string Path, int Depth)>();
        ulong rootId = WindowsMftVolume.GetDirectoryId(root);
        if (!_records.TryGetValue(rootId, out var rootRecord) || !rootRecord.Directory)
            throw new IOException("Query directory identity was not captured; reacquire the snapshot.");
        pending.Push((rootId, root, 0));
        var visited = new HashSet<ulong>();
        while (pending.Count != 0)
        {
            options.CancellationToken.ThrowIfCancellationRequested();
            var parent = pending.Pop();
            if (!visited.Add(parent.Id)) throw new IOException("Repeated directory identity in the MFT name index.");
            if (!_children.TryGetValue(parent.Id, out var nodes)) continue;
            foreach (var node in nodes)
            {
                options.CancellationToken.ThrowIfCancellationRequested();
                var record = node.Owner;
                if (record.Id == parent.Id) continue; // The volume-root record points to itself.
                if (record.Incomplete != null) throw new NotSupportedException(record.Incomplete + " Record " + record.Id.ToString("X16"));
                var path = Path.Combine(parent.Path, node.Name);
                var entry = record.Entry(path);
                bool visible = options.Force || (entry.Attributes & (FileAttributes.Hidden | FileAttributes.System)) == 0;
                if (options.Accept(entry, parent.Depth)) yield return entry;
                if (visible && entry.PSIsContainer && options.Recurse && parent.Depth < options.Depth &&
                    (entry.Attributes & FileAttributes.ReparsePoint) == 0)
                    pending.Push((record.Id, path, parent.Depth + 1));
            }
        }
    }
}
