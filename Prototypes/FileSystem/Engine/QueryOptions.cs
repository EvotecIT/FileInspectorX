namespace FileInspectorX.Prototypes.FileSystem;

/// <summary>Enumeration strategy for the evaluation-only filesystem query.</summary>
public enum EnumerationBackend { Auto, Walk, Mft }

/// <summary>Supported filesystem subset of Get-ChildItem. Caller delegates run in C#, not scriptblocks.</summary>
public sealed class QueryOptions
{
    public string Root { get; set; } = "";
    public EnumerationBackend Backend { get; set; }
    public bool Recurse { get; set; }
    public int Depth { get; set; } = int.MaxValue;
    public bool File { get; set; }
    public bool Directory { get; set; }
    public bool Force { get; set; }
    public string Filter { get; set; } = "*";
    public bool AllowVolumeInventory { get; set; }
    public MftReadMode MftReadMode { get; set; } = MftReadMode.Bulk;
    public long MaximumMftBytes { get; set; } = 512L * 1024 * 1024;
    public int MaximumIndexRecords { get; set; } = 4_000_000;
    public long MaximumIndexBytes { get; set; } = 2L * 1024 * 1024 * 1024;
    public TimeSpan MaximumCaptureTime { get; set; } = TimeSpan.FromMinutes(2);
    public CancellationToken CancellationToken { get; set; }
    /// <summary>Optional directory-enumeration error sink. Without a sink, errors remain fatal.</summary>
    public Action<Exception, string>? OnError { get; set; }

    internal QueryOptions WithErrorHandler(Action<Exception, string> handler)
    {
        var copy = (QueryOptions)MemberwiseClone();
        copy.OnError = handler;
        return copy;
    }

    internal bool Accept(FileSystemEntry entry, int depth)
    {
        if (depth > (Recurse ? Depth : 0)) return false;
        if (File && entry.PSIsContainer || Directory && !entry.PSIsContainer) return false;
        if (!Force && (entry.Attributes & (FileAttributes.Hidden | FileAttributes.System)) != 0) return false;
        return true;
    }

    internal string ResolveRoot()
    {
        CancellationToken.ThrowIfCancellationRequested();
        if (Depth < 0) throw new ArgumentOutOfRangeException(nameof(Depth));
        var full = Path.GetFullPath(Root);
        if (!System.IO.Directory.Exists(full)) throw new DirectoryNotFoundException(full);
        var volumeRoot = Path.GetPathRoot(full)!;
        return full.Length == volumeRoot.Length ? volumeRoot : full.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
    }
}
