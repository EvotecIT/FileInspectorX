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
            foreach (var info in EnumerateDirectory(directory, options.Filter, options))
            {
                options.CancellationToken.ThrowIfCancellationRequested();
                FileSystemEntry entry;
                try { entry = FileSystemEntry.FromInfo(info); }
                catch (Exception exception) when (CanReport(exception, options)) { options.OnError!(exception, info.FullName); continue; }
                var attributes = entry.Attributes;
                bool visible = options.Force || (attributes & (FileAttributes.Hidden | FileAttributes.System)) == 0;
                if (options.Filter == "*" && visible && options.Recurse && current.Value < options.Depth &&
                    (attributes & FileAttributes.Directory) != 0 && (attributes & FileAttributes.ReparsePoint) == 0)
                    pending.Push(new KeyValuePair<string, int>(info.FullName, current.Value + 1));
                if (!visible) continue;
                if (options.Accept(entry, current.Value)) yield return entry;
            }
            // A provider-native filter must not stop traversal through nonmatching directories.
            if (options.Filter != "*" && options.Recurse && current.Value < options.Depth)
                foreach (var child in EnumerateDirectory(directory, "*", options).OfType<DirectoryInfo>())
                {
                    options.CancellationToken.ThrowIfCancellationRequested();
                    if ((child.Attributes & FileAttributes.ReparsePoint) == 0 &&
                        (options.Force || (child.Attributes & (FileAttributes.Hidden | FileAttributes.System)) == 0))
                        pending.Push(new KeyValuePair<string, int>(child.FullName, current.Value + 1));
                }
        }
    }

    private static IEnumerable<FileSystemInfo> EnumerateDirectory(DirectoryInfo directory, string filter, QueryOptions options)
    {
        IEnumerator<FileSystemInfo> iterator;
        try { iterator = directory.EnumerateFileSystemInfos(filter).GetEnumerator(); }
        catch (Exception exception) when (CanReport(exception, options)) { options.OnError!(exception, directory.FullName); yield break; }
        using (iterator)
            while (true)
            {
                options.CancellationToken.ThrowIfCancellationRequested();
                bool next;
                try { next = iterator.MoveNext(); }
                catch (Exception exception) when (CanReport(exception, options)) { options.OnError!(exception, directory.FullName); yield break; }
                if (!next) yield break;
                yield return iterator.Current;
            }
    }

    private static bool CanReport(Exception exception, QueryOptions options) =>
        options.OnError != null && (exception is IOException || exception is UnauthorizedAccessException);
}
