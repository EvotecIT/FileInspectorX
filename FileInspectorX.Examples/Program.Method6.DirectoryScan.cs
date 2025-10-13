using FileInspectorX;

/// <summary>
/// Example 6: Scanning directories (sync + async) and simple filtering by flags.
/// </summary>
internal static partial class Program
{
    public static void Method6_DirectoryScan(string path)
    {
        Console.WriteLine("[6] Directory Scan\n-------------------");
        var dir = System.IO.Path.GetDirectoryName(path) ?? ".";

        // Sync
        foreach (var fa in FileInspector.AnalyzeDirectory(dir, System.IO.SearchOption.TopDirectoryOnly))
        {
            if ((fa.Flags & ContentFlags.ContainerContainsExecutables) != 0 || fa.Kind == ContentKind.Executable)
                Console.WriteLine($"[EXEC] {fa.Detection?.Extension} {fa.Detection?.MimeType} {fa.Assessment?.Decision} {fa.Assessment?.Score}");
        }

        // Async
        Console.WriteLine("Async scan:");
        var t = ScanAsync(dir);
        t.GetAwaiter().GetResult();
    }

    private static async Task ScanAsync(string dir)
    {
        await foreach (var fa in FileInspector.AnalyzeDirectoryAsync(dir, System.IO.SearchOption.TopDirectoryOnly))
        {
            if ((fa.Flags & ContentFlags.OfficeExternalLinks) != 0)
                Console.WriteLine($"[XL] {fa.OfficeExternalLinksCount} external links in {fa.Detection?.Extension}");
        }
    }
}

