namespace FileInspectorX.Prototypes.FileSystem;

/// <summary>Streaming normal-enumeration fallback. Does not follow directory reparse points.</summary>
internal static class WalkEnumerator
{
    internal static IEnumerable<FileSystemEntry> Enumerate(string root, QueryOptions options)
    {
        var pending = new Stack<KeyValuePair<string, int>>();
        pending.Push(new KeyValuePair<string, int>(root, 0));
        while (pending.Count != 0)
        {
            options.CancellationToken.ThrowIfCancellationRequested();
            var current = pending.Pop();
            var directory = new DirectoryInfo(current.Key);
            foreach (var info in directory.EnumerateFileSystemInfos(options.Filter))
            {
                options.CancellationToken.ThrowIfCancellationRequested();
                var attributes = info.Attributes;
                bool visible = options.Force || (attributes & (FileAttributes.Hidden | FileAttributes.System)) == 0;
                if (options.Filter == "*" && visible && options.Recurse && current.Value < options.Depth &&
                    (attributes & FileAttributes.Directory) != 0 && (attributes & FileAttributes.ReparsePoint) == 0)
                    pending.Push(new KeyValuePair<string, int>(info.FullName, current.Value + 1));
                if (!visible) continue;
                var entry = FileSystemEntry.FromInfo(info);
                if (options.Accept(entry, current.Value)) yield return entry;
            }
            // A provider-native filter must not stop traversal through nonmatching directories.
            if (options.Filter != "*" && options.Recurse && current.Value < options.Depth)
                foreach (var child in directory.EnumerateDirectories())
                {
                    options.CancellationToken.ThrowIfCancellationRequested();
                    if ((child.Attributes & FileAttributes.ReparsePoint) == 0 &&
                        (options.Force || (child.Attributes & (FileAttributes.Hidden | FileAttributes.System)) == 0))
                        pending.Push(new KeyValuePair<string, int>(child.FullName, current.Value + 1));
                }
        }
    }
}
