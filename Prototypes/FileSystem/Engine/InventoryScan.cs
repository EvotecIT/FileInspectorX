namespace FileInspectorX.Prototypes.FileSystem;

/// <summary>Bounded diagnostic errors for C# consumers; never classifies partial coverage as complete.</summary>
public sealed class InventoryErrors
{
    public long Count { get; private set; }
    public string? FirstException { get; private set; }
    public Action<Exception, string> Handler => Record;
    public void Record(Exception exception, string path)
    {
        Count++;
        FirstException ??= exception.GetType().FullName;
    }
}

/// <summary>Streaming metadata fingerprint without PowerShell delivery or a retained path inventory.</summary>
public static class InventoryScan
{
    public static async Task<InventorySummary> MeasureAsync(QueryOptions options, MftSnapshot? snapshot = null)
    {
        var summary = new InventorySummary();
        var callerSink = options.OnError;
        var queryOptions = callerSink == null ? options : options.WithErrorHandler((exception, path) =>
        {
            summary.AddError();
            callerSink(exception, path);
        });
        var query = await FileSystemQuery.OpenAsync(queryOptions, snapshot).ConfigureAwait(false);
        foreach (var entry in query.Entries)
            summary.Add(entry.FullName, (int)entry.Attributes, entry.Length ?? 0, entry.CreationTimeUtc.Ticks, entry.LastWriteTimeUtc.Ticks);
        return summary;
    }
}
