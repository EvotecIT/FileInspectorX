using System.ComponentModel;

namespace FileInspectorX.Prototypes.FileSystem;

/// <summary>Describes selected backend and explicit visibility/compatibility limits before output starts.</summary>
public sealed class QueryResult
{
    public string Backend { get; internal set; } = "";
    public string? FallbackReason { get; internal set; }
    public string Compatibility { get; internal set; } = "FilesystemSubset";
    public IEnumerable<FileSystemEntry> Entries { get; internal set; } = Array.Empty<FileSystemEntry>();
}

/// <summary>Owns query routing. Automatic fallback occurs before output, only for unavailable MFT capability.</summary>
public static class FileSystemQuery
{
    public static async Task<QueryResult> OpenAsync(QueryOptions options, MftSnapshot? snapshot = null)
    {
        var root = options.ResolveRoot();
        if (options.Backend == EnumerationBackend.Walk)
            return Walk(root, options, null);
        if (options.Backend == EnumerationBackend.Auto && !options.AllowVolumeInventory)
            return Walk(root, options, "Caller-visible enumeration requested; experimental raw-volume visibility was not enabled.");
        try
        {
            if (options.Filter != "*") throw new NotSupportedException("Prototype MFT filtering supports only '*'; native wildcard filtering uses normal enumeration.");
            if (options.Backend == EnumerationBackend.Auto)
                throw new NotSupportedException("MFT snapshot visibility and freshness are not caller-visible enumeration semantics. Auto keeps normal enumeration; forced Mft is an explicit experimental inventory.");
            MftSnapshot.CheckRoot(root);
            snapshot ??= await MftSnapshot.CaptureAsync(root, options.CancellationToken, options.MaximumMftBytes,
                options.MaximumIndexRecords, options.MaximumIndexBytes, options.MaximumCaptureTime).ConfigureAwait(false);
            return new QueryResult
            {
                Backend = "Mft", Compatibility = "ExperimentalVolumeInventory",
                Entries = snapshot.Enumerate(root, options)
            };
        }
        catch (Exception exception) when (options.Backend == EnumerationBackend.Auto && IsUnavailable(exception))
        {
            options.CancellationToken.ThrowIfCancellationRequested();
            return Walk(root, options, exception.GetType().Name + ": " + exception.Message);
        }
    }

    private static bool IsUnavailable(Exception exception) =>
        exception is UnauthorizedAccessException || exception is PlatformNotSupportedException ||
        exception is NotSupportedException || exception is Win32Exception win32 && (win32.NativeErrorCode == 5 || win32.NativeErrorCode == 50) ||
        exception is IOException io && (io.HResult & 0xFFFF) == 50;

    private static QueryResult Walk(string root, QueryOptions options, string? reason) => new()
    {
        Backend = "Walk", FallbackReason = reason, Entries = WalkEnumerator.Enumerate(root, options)
    };
}
