using System.Runtime.CompilerServices;

namespace FileInspectorX;

/// <summary>
/// Directory enumeration and async scanning helpers over the <see cref="FileInspector"/> facade.
/// </summary>
public static partial class FileInspector {
    /// <summary>
    /// Lazily analyzes all files under a directory (non-recursive by default).
    /// </summary>
    /// <param name="path">Root directory path.</param>
    /// <param name="searchOption">TopDirectoryOnly or AllDirectories.</param>
    /// <param name="filter">Optional file filter predicate (receives full path).</param>
    /// <param name="options">Detection enrichment options.</param>
    public static IEnumerable<FileAnalysis> AnalyzeDirectory(
        string path,
        SearchOption searchOption = SearchOption.TopDirectoryOnly,
        Func<string, bool>? filter = null,
        DetectionOptions? options = null) {
        if (!Directory.Exists(path)) yield break;
        var files = EnumerateFilesSafe(path, searchOption);
        foreach (var f in files) {
            if (filter != null && !filter(f)) continue;
            FileAnalysis? analysis = null;
            try { analysis = Analyze(f, options); } catch { }
            if (analysis != null) yield return analysis;
        }
    }

#if NET8_0_OR_GREATER
    /// <summary>
    /// Asynchronously analyzes a sequence of files, yielding results as they are produced.
    /// </summary>
    /// <param name="paths">File paths to analyze.</param>
    /// <param name="options">Detection enrichment options.</param>
    /// <param name="ct">Cancellation token.</param>
    public static async IAsyncEnumerable<FileAnalysis> AnalyzeFilesAsync(
        IEnumerable<string> paths,
        DetectionOptions? options = null,
        [EnumeratorCancellation] CancellationToken ct = default) {
        foreach (var p in paths) {
            ct.ThrowIfCancellationRequested();
            // Synchronous compute; returned as async stream for ergonomic consumption.
            yield return Analyze(p, options);
            await Task.Yield();
        }
    }

    /// <summary>
    /// Asynchronously analyzes all files under a directory using small parallelism.
    /// </summary>
    /// <param name="path">Root directory path.</param>
    /// <param name="searchOption">TopDirectoryOnly or AllDirectories.</param>
    /// <param name="filter">Optional predicate to include files.</param>
    /// <param name="options">Detection enrichment options.</param>
    /// <param name="maxDegreeOfParallelism">Limit for parallel workers; defaults to logical processors.</param>
    /// <param name="ct">Cancellation token.</param>
    public static async IAsyncEnumerable<FileAnalysis> AnalyzeDirectoryAsync(
        string path,
        SearchOption searchOption = SearchOption.TopDirectoryOnly,
        Func<string, bool>? filter = null,
        DetectionOptions? options = null,
        int maxDegreeOfParallelism = 0,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct = default) {
        if (!Directory.Exists(path)) yield break;

        var files = EnumerateFilesSafe(path, searchOption);
        if (filter != null) files = files.Where(filter);

        var degree = maxDegreeOfParallelism > 0 ? maxDegreeOfParallelism : Environment.ProcessorCount;
        var channel = System.Threading.Channels.Channel.CreateBounded<FileAnalysis>(degree * 2);

        var producer = Task.Run(async () => {
            try {
                await Parallel.ForEachAsync(files, new ParallelOptions { MaxDegreeOfParallelism = degree, CancellationToken = ct }, async (file, token) => {
                    FileAnalysis? result = null;
                    try { result = Analyze(file, options); } catch { }
                    if (result != null)
                        await channel.Writer.WriteAsync(result, token);
                });
            } catch (OperationCanceledException) {
                // ignore
            } finally {
                channel.Writer.TryComplete();
            }
        }, ct);

        await foreach (var item in channel.Reader.ReadAllAsync(ct)) yield return item;
        await producer;
    }
#endif

    private static IEnumerable<string> EnumerateFilesSafe(string path, SearchOption searchOption)
        => EnumerateFilesSafeCore(
            path,
            searchOption,
            current => Directory.EnumerateFiles(current, "*", SearchOption.TopDirectoryOnly),
            current => Directory.EnumerateDirectories(current, "*", SearchOption.TopDirectoryOnly));

    internal static IEnumerable<string> EnumerateFilesSafeForTest(
        string path,
        SearchOption searchOption,
        Func<string, IEnumerable<string>> enumerateFiles,
        Func<string, IEnumerable<string>> enumerateDirectories)
        => EnumerateFilesSafeCore(path, searchOption, enumerateFiles, enumerateDirectories);

    private static IEnumerable<string> EnumerateFilesSafeCore(
        string path,
        SearchOption searchOption,
        Func<string, IEnumerable<string>> enumerateFiles,
        Func<string, IEnumerable<string>> enumerateDirectories)
    {
        var pending = new Stack<string>();
        pending.Push(path);

        while (pending.Count > 0)
        {
            var current = pending.Pop();
            IEnumerable<string> files;
            try
            {
                files = enumerateFiles(current);
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or DirectoryNotFoundException)
            {
                continue;
            }

            foreach (var file in files)
            {
                yield return file;
            }

            if (searchOption != SearchOption.AllDirectories) continue;

            IEnumerable<string> directories;
            try
            {
                directories = enumerateDirectories(current);
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or DirectoryNotFoundException)
            {
                continue;
            }

            foreach (var directory in directories)
            {
                pending.Push(directory);
            }
        }
    }
}
