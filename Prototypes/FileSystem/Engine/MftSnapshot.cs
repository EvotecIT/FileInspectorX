using System.Diagnostics;

namespace FileInspectorX.Prototypes.FileSystem;

/// <summary>Bounded Windows MFT name index. Metadata is hydrated live through ordinary file APIs during each query.</summary>
public sealed class MftSnapshot
{
    private readonly Dictionary<ulong, List<UsnNode>> _children;
    public string VolumeRoot { get; }
    public DateTime CapturedUtc { get; }
    public long MftBytes { get; }
    public int RecordCount { get; }
    /// <summary>Conservative index accounting, including adjacency overhead; not a managed heap measurement.</summary>
    public long EstimatedIndexBytes { get; }
    public long NativeBytesRead { get; }

    private MftSnapshot(string volumeRoot, long mftBytes, Dictionary<ulong, List<UsnNode>> children,
        int count, long estimatedBytes, long nativeBytesRead)
    {
        VolumeRoot = volumeRoot; MftBytes = mftBytes; _children = children; RecordCount = count;
        EstimatedIndexBytes = estimatedBytes; NativeBytesRead = nativeBytesRead; CapturedUtc = DateTime.UtcNow;
    }

    /// <summary>Inventories one local NTFS volume through FSCTL_ENUM_USN_DATA. No sector reads or persistent index.</summary>
    /// <remarks>Cancellation and timeout are checked between synchronous control calls and parsed records, not inside a kernel call.</remarks>
    public static Task<MftSnapshot> CaptureAsync(string root, CancellationToken cancellationToken,
        long maximumMftBytes = 512L * 1024 * 1024, int maximumIndexRecords = 4_000_000,
        long maximumIndexBytes = 2L * 1024 * 1024 * 1024, TimeSpan? maximumCaptureTime = null)
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
        using var volume = new WindowsMftVolume(volumeRoot, maximumMftBytes);
        var children = new Dictionary<ulong, List<UsnNode>>();
        var timer = Stopwatch.StartNew();
        int count = 0;
        long estimatedBytes = 0;
        foreach (var node in volume.Enumerate(cancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (timer.Elapsed > timeLimit) throw new NotSupportedException("MFT capture exceeded its explicit time budget.");
            estimatedBytes = checked(estimatedBytes + 256L + 2L * node.Name.Length);
            if (++count > maximumIndexRecords || estimatedBytes > maximumIndexBytes)
                throw new NotSupportedException("MFT name index exceeded its explicit budget: records=" + count + ", estimated bytes=" + estimatedBytes + ".");
            if (!children.TryGetValue(node.ParentId, out var siblings)) children.Add(node.ParentId, siblings = new List<UsnNode>());
            siblings.Add(node);
        }
        cancellationToken.ThrowIfCancellationRequested();
        if (timer.Elapsed > timeLimit) throw new NotSupportedException("MFT capture exceeded its explicit time budget.");
        return Task.FromResult(new MftSnapshot(volumeRoot, volume.MftBytes, children, count, estimatedBytes, volume.BytesRead));
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
        pending.Push((WindowsMftVolume.GetDirectoryId(root), root, 0));
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
                if (node.Id == parent.Id) continue; // The volume-root record points to itself.
                var path = Path.Combine(parent.Path, node.Name);
                FileSystemInfo info = (node.Attributes & FileAttributes.Directory) != 0
                    ? (FileSystemInfo)new DirectoryInfo(path) : new FileInfo(path);
                info.Refresh();
                if (!info.Exists) throw new IOException("Indexed path disappeared or became inaccessible: " + path);
                var entry = FileSystemEntry.FromInfo(info);
                entry.Backend = "Mft";
                bool visible = options.Force || (entry.Attributes & (FileAttributes.Hidden | FileAttributes.System)) == 0;
                if (options.Accept(entry, parent.Depth)) yield return entry;
                if (visible && entry.PSIsContainer && options.Recurse && parent.Depth < options.Depth &&
                    (entry.Attributes & FileAttributes.ReparsePoint) == 0)
                    pending.Push((node.Id, path, parent.Depth + 1));
            }
        }
    }
}
