using System.Runtime.CompilerServices;

namespace FileInspectorX;

/// <summary>
/// Directory enumeration and async scanning helpers over the <see cref="FileInspector"/> facade.
/// </summary>
public static partial class FileInspector {
    /// <summary>
    /// Lazily analyzes all files under a directory (non-recursive by default). Recursive scans skip directory links.
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
        options = InspectionOperation.Capture(options);
        options.CancellationToken.ThrowIfCancellationRequested();
        ValidateLearnedClassificationMode(options);
        if (!Directory.Exists(path)) yield break;
        var files = EnumerateFilesSafe(path, searchOption, options.CancellationToken);
        foreach (var f in files) {
            options.CancellationToken.ThrowIfCancellationRequested();
            if (filter != null && !filter(f)) continue;
            options.CancellationToken.ThrowIfCancellationRequested();
            FileAnalysis? analysis = null;
            try { analysis = Analyze(f, options); }
            catch (LearnedClassificationException) { throw; }
            catch (Exception ex) when (ex is not OutOfMemoryException and not OperationCanceledException) { }
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
        options = InspectionOperation.Capture(options);
        using var operation = CancellationTokenSource.CreateLinkedTokenSource(ct, options.CancellationToken);
        options.CancellationToken = operation.Token;
        operation.Token.ThrowIfCancellationRequested();
        foreach (var p in paths) {
            operation.Token.ThrowIfCancellationRequested();
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
        options = InspectionOperation.Capture(options);
        using var operation = CancellationTokenSource.CreateLinkedTokenSource(ct, options.CancellationToken);
        options.CancellationToken = operation.Token;
        operation.Token.ThrowIfCancellationRequested();
        ValidateLearnedClassificationMode(options);
        if (!Directory.Exists(path)) yield break;

        var files = EnumerateFilesSafe(path, searchOption, operation.Token);
        if (filter != null) files = files.Where(filter);

        var degree = maxDegreeOfParallelism > 0 ? maxDegreeOfParallelism : Environment.ProcessorCount;
        var channel = System.Threading.Channels.Channel.CreateBounded<FileAnalysis>(degree * 2);

        var producer = Task.Run(async () => {
            Exception? failure = null;
            try {
                await Parallel.ForEachAsync(files, new ParallelOptions { MaxDegreeOfParallelism = degree, CancellationToken = operation.Token }, async (file, token) => {
                    FileAnalysis? result = null;
                    var workerOptions = options.Copy();
                    workerOptions.CancellationToken = token;
                    try { result = Analyze(file, workerOptions); }
                    catch (LearnedClassificationException) { throw; }
                    catch (Exception ex) when (ex is not OutOfMemoryException and not OperationCanceledException) { }
                    if (result != null)
                        await channel.Writer.WriteAsync(result, token);
                });
            } catch (OperationCanceledException) when (operation.IsCancellationRequested) {
                // The reader or caller ended this operation.
            } catch (Exception ex) {
                failure = ex;
            } finally {
                channel.Writer.TryComplete(failure);
            }
        });

        try {
            await foreach (var item in channel.Reader.ReadAllAsync(operation.Token)) yield return item;
        } finally {
            operation.Cancel();
            await producer;
        }
    }
#endif

    private static IEnumerable<string> EnumerateFilesSafe(string path, SearchOption searchOption, System.Threading.CancellationToken cancellationToken = default)
        => EnumerateFilesSafeCore(
            path,
            searchOption,
            current => Directory.EnumerateFiles(current, "*", SearchOption.TopDirectoryOnly),
            current => Directory.EnumerateDirectories(current, "*", SearchOption.TopDirectoryOnly).Where(IsOrdinaryDirectory),
            cancellationToken);

    private static bool IsOrdinaryDirectory(string path)
    {
        try { return FileSystemLinks.IsLink(path, File.GetAttributes(path)) == false; }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException) { return false; }
    }

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
        Func<string, IEnumerable<string>> enumerateDirectories,
        System.Threading.CancellationToken cancellationToken = default)
    {
        var pending = new Stack<string>();
        pending.Push(path);

        while (pending.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var current = pending.Pop();
            foreach (var file in EnumerateSafely(() => enumerateFiles(current)))
            {
                cancellationToken.ThrowIfCancellationRequested();
                yield return file;
            }

            if (searchOption != SearchOption.AllDirectories) continue;

            foreach (var directory in EnumerateSafely(() => enumerateDirectories(current)))
            {
                cancellationToken.ThrowIfCancellationRequested();
                pending.Push(directory);
            }
        }
    }

    private static IEnumerable<string> EnumerateSafely(Func<IEnumerable<string>> enumerableFactory)
    {
        IEnumerator<string>? enumerator;
        try
        {
            enumerator = enumerableFactory().GetEnumerator();
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or DirectoryNotFoundException)
        {
            yield break;
        }

        using (enumerator)
        {
            while (true)
            {
                bool moved;
                string current;
                try
                {
                    moved = enumerator.MoveNext();
                    if (!moved) yield break;
                    current = enumerator.Current;
                }
                catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or DirectoryNotFoundException)
                {
                    yield break;
                }
                yield return current;
            }
        }
    }
}
