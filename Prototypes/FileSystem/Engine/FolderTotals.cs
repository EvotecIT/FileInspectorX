namespace FileInspectorX.Prototypes.FileSystem;

/// <summary>Logical file-path totals. Hardlinks count once per path; allocated space is a different contract.</summary>
public sealed class FolderTotal
{
    public string Path { get; internal set; } = "";
    public long Files { get; internal set; }
    public long Directories { get; internal set; }
    public long LogicalBytes { get; internal set; }
}

/// <summary>C# consumer that retains only folder summaries and never sends individual entries through PowerShell.</summary>
public static class FolderTotals
{
    public static async Task<FolderTotal[]> MeasureAsync(QueryOptions options, MftSnapshot? snapshot = null, int maximumFolders = 1_000_000)
    {
        if (maximumFolders <= 0) throw new ArgumentOutOfRangeException(nameof(maximumFolders));
        if (!options.Recurse || options.Depth != int.MaxValue || options.File || options.Directory || options.Filter != "*")
            throw new ArgumentException("Folder totals require an unfiltered recursive tree.", nameof(options));
        var query = await FileSystemQuery.OpenAsync(options, snapshot).ConfigureAwait(false);
        string root = options.ResolveRoot();
        // Exact path spelling matters in NTFS case-sensitive directories.
        var folders = new Dictionary<string, FolderTotal>(StringComparer.Ordinal);
        folders.Add(root, new FolderTotal { Path = root });
        foreach (var entry in query.Entries)
        {
            options.CancellationToken.ThrowIfCancellationRequested();
            string parent = System.IO.Path.GetDirectoryName(entry.FullName)!;
            var parentTotal = Get(parent);
            if (entry.PSIsContainer) { parentTotal.Directories = checked(parentTotal.Directories + 1); Get(entry.FullName); }
            else { parentTotal.Files = checked(parentTotal.Files + 1); parentTotal.LogicalBytes = checked(parentTotal.LogicalBytes + entry.Length!.Value); }
        }
        // Children are always deeper than their parents, regardless of traversal order.
        var result = folders.Values.OrderByDescending(folder => folder.Path.Length).ToArray();
        foreach (var folder in result)
        {
            options.CancellationToken.ThrowIfCancellationRequested();
            if (folder.Path == root) continue;
            string parent = System.IO.Path.GetDirectoryName(folder.Path)!;
            if (!folders.TryGetValue(parent, out var owner)) throw new IOException("Folder summary has no enumerated parent.");
            owner.Files = checked(owner.Files + folder.Files);
            owner.Directories = checked(owner.Directories + folder.Directories);
            owner.LogicalBytes = checked(owner.LogicalBytes + folder.LogicalBytes);
        }
        return result;

        FolderTotal Get(string path)
        {
            if (!folders.TryGetValue(path, out var value))
            {
                if (folders.Count >= maximumFolders) throw new NotSupportedException("Folder-summary budget exceeded.");
                folders.Add(path, value = new FolderTotal { Path = path });
            }
            return value;
        }
    }
}
