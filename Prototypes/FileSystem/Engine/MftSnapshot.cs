using System.IO.Filesystem.Ntfs;

namespace FileInspectorX.Prototypes.FileSystem;

/// <summary>Explicit in-memory volume snapshot for an unqualified comparison reader. No persistent index is created.</summary>
public sealed class MftSnapshot
{
    private readonly NtfsReader _reader;
    public string VolumeRoot { get; }
    public DateTime CapturedUtc { get; }
    public long MftBytes { get; }

    private MftSnapshot(NtfsReader reader, string volumeRoot, long mftBytes)
    {
        _reader = reader;
        VolumeRoot = volumeRoot;
        CapturedUtc = DateTime.UtcNow;
        MftBytes = mftBytes;
    }

    /// <summary>Reads the whole local NTFS volume; elevation is required. Cancellation reaches the reader.</summary>
    public static async Task<MftSnapshot> CaptureAsync(string root, CancellationToken cancellationToken, long maximumMftBytes = 512L * 1024 * 1024)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
            throw new PlatformNotSupportedException("MFT capture requires Windows.");
        CheckRoot(root);
        var volumeRoot = Path.GetPathRoot(Path.GetFullPath(root))!;
        var drive = new DriveInfo(volumeRoot);
        if (drive.DriveType == DriveType.Network || !string.Equals(drive.DriveFormat, "NTFS", StringComparison.OrdinalIgnoreCase))
            throw new NotSupportedException("MFT capture requires a local NTFS volume.");
        long mftBytes = VolumePreflight.Check(volumeRoot, maximumMftBytes);
        var reader = await NtfsReader.CreateAsync(drive, RetrieveMode.StandardInformations, cancellationToken).ConfigureAwait(false);
        // Querying the in-memory node table needs no volume handle. Release it before handing off the snapshot.
        reader.Dispose();
        return new MftSnapshot(reader, volumeRoot, mftBytes);
    }

    internal static void CheckRoot(string root)
    {
        for (var current = Path.GetFullPath(root); current != null; current = Path.GetDirectoryName(current))
            if ((System.IO.File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new NotSupportedException("MFT queries through a reparse root or ancestor use normal enumeration.");
    }

    internal IEnumerable<FileSystemEntry> Enumerate(string root, QueryOptions options)
    {
        if (!string.Equals(Path.GetPathRoot(root), VolumeRoot, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Snapshot belongs to a different volume.", nameof(root));
        var prefix = root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        // The library uses a prefix query; the trailing separator prevents sibling-prefix leakage.
        var nodes = _reader.GetNodes(prefix);
        var excluded = new HashSet<string>(nodes.Where(node => (node.Attributes & System.IO.Filesystem.Ntfs.Attributes.Directory) != 0 &&
            (((FileAttributes)(uint)node.Attributes & FileAttributes.ReparsePoint) != 0 ||
             !options.Force && ((FileAttributes)(uint)node.Attributes & (FileAttributes.Hidden | FileAttributes.System)) != 0))
            .Select(node => node.FullName.TrimEnd(Path.DirectorySeparatorChar)), StringComparer.OrdinalIgnoreCase);
        foreach (var node in nodes)
        {
            options.CancellationToken.ThrowIfCancellationRequested();
            var fullName = node.FullName;
            if (!fullName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) continue;
            bool excludedAncestor = false;
            for (var parent = Path.GetDirectoryName(fullName); parent != null && parent.Length >= prefix.Length; parent = Path.GetDirectoryName(parent))
                if (excluded.Contains(parent)) { excludedAncestor = true; break; }
            if (excludedAncestor) continue;
            var relative = fullName.Substring(prefix.Length);
            if (relative.Length == 0) continue;
            int depth = relative.Count(character => character == Path.DirectorySeparatorChar);
            var attributes = (FileAttributes)(uint)node.Attributes;
            var entry = new FileSystemEntry
            {
                FullName = fullName, Attributes = attributes,
                Length = (attributes & FileAttributes.Directory) != 0 ? (long?)null : checked((long)node.Size),
                // Version 0.1.0 passes (creation, fileChange, lastAccess) to a constructor declared
                // (creation, lastAccess, lastChange). Keep this pinned-reader correction explicit.
                CreationTimeUtc = node.CreationTime, LastWriteTimeUtc = node.LastAccessTime,
                LastAccessTimeUtc = node.LastChangeTime, Backend = "Mft"
            };
            if (options.Accept(entry, depth)) yield return entry;
        }
    }
}
