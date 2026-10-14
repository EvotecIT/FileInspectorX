namespace FileInspectorX;

/// <summary>One observed input or traversal failure. Failed inputs are retained rather than silently dropped.</summary>
public sealed class ReportBatchItem
{
    /// <summary>Caller-provided input for explicit lists, or a path relative to the supplied scan root.</summary>
    public string Source { get; set; } = string.Empty;
    /// <summary>Report when readable and within the configured whole-input limit.</summary>
    public InspectionReport? Report { get; set; }
    /// <summary>Stable diagnostic code when report production or traversal could not complete.</summary>
    public string? Issue { get; set; }
}

public static partial class FileInspector
{
    /// <summary>Reports each supplied path, including stable failures. Cancellation and provider configuration errors propagate.</summary>
    public static IEnumerable<ReportBatchItem> AnalyzeReports(IEnumerable<string> paths, InspectionReportOptions? options = null)
    {
        if (paths == null) throw new ArgumentNullException(nameof(paths));
        foreach (var path in paths)
        {
            options?.Detection?.CancellationToken.ThrowIfCancellationRequested();
            yield return ReportItem(path, path, options);
        }
    }

    /// <summary>Scans a directory and reports enumeration/read failures. Recursive traversal skips directory links with an explicit diagnostic.
    /// The root itself must be an ordinary directory. Sources in returned items are relative to the supplied root.</summary>
    public static IEnumerable<ReportBatchItem> AnalyzeDirectoryReports(string path, SearchOption searchOption = SearchOption.TopDirectoryOnly, InspectionReportOptions? options = null)
    {
        var root = Path.GetFullPath(path);
        var pending = new Stack<string>(); pending.Push(root);
        while (pending.Count > 0)
        {
            options?.Detection?.CancellationToken.ThrowIfCancellationRequested();
            var directory = pending.Pop();
            var relative = directory == root ? "." : directory.Substring(root.TrimEnd(Path.DirectorySeparatorChar).Length + 1);
            string? issue = null;
            IEnumerable<string>? children = null;
            try
            {
                var attributes = File.GetAttributes(directory);
                if (FileSystemLinks.IsLink(directory, attributes) != false) issue = "batch:directory-link-skipped";
                else children = Directory.EnumerateFileSystemEntries(directory);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { issue = "batch:directory-unavailable"; }
            if (issue != null) { yield return new ReportBatchItem { Source = relative, Issue = issue }; continue; }
            IEnumerator<string>? enumerator = null;
            try { enumerator = children!.GetEnumerator(); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { issue = "batch:enumeration-failed"; }
            if (issue != null) { yield return new ReportBatchItem { Source = relative, Issue = issue }; continue; }
            using (enumerator)
            {
                while (true)
                {
                    options?.Detection?.CancellationToken.ThrowIfCancellationRequested();
                    string? current = null;
                    try { if (enumerator!.MoveNext()) current = enumerator.Current; }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { issue = "batch:enumeration-failed"; }
                    if (issue != null) { yield return new ReportBatchItem { Source = relative, Issue = issue }; break; }
                    if (current == null) break;
                    var source = current.Substring(root.TrimEnd(Path.DirectorySeparatorChar).Length + 1);
                    FileAttributes attributes = 0;
                    try { attributes = File.GetAttributes(current); }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { issue = "batch:entry-unavailable"; }
                    if (issue != null) { yield return new ReportBatchItem { Source = source, Issue = issue }; issue = null; continue; }
                    if ((attributes & FileAttributes.Directory) != 0)
                    { if (searchOption == SearchOption.AllDirectories) pending.Push(current); }
                    else if (FileSystemLinks.IsLink(current, attributes) != false) yield return new ReportBatchItem { Source = source, Issue = "batch:file-link-skipped" };
                    else yield return ReportItem(current, source, options);
                }
            }
        }
    }

    private static ReportBatchItem ReportItem(string path, string source, InspectionReportOptions? options)
    {
        try { return new ReportBatchItem { Source = source, Report = AnalyzeReport(path, options) }; }
        catch (InspectionInputSizeLimitException) { return new ReportBatchItem { Source = source, Issue = "batch:input-size-limit" }; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return new ReportBatchItem { Source = source, Issue = "batch:input-unavailable" }; }
    }
}
