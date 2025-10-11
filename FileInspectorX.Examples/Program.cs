using FileInspectorX;

/// <summary>
/// FileInspectorX.Examples – simple console app that demonstrates three usage patterns:
/// 1) Detection-only (Detect + Inspect with DetectOnly)
/// 2) Full analysis (Inspect/Analyze)
/// 3) Projection to flattened views (Summary/Permissions/Signature)
///
/// Run: dotnet run --project FileInspectorX.Examples -- <path-to-file>
/// If no path is provided, examples try README.MD in repo root.
/// </summary>
internal static class Program
{
    private static int Main(string[] args)
    {
        var path = args.Length > 0 ? args[0] : ResolveDefault();
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            Console.Error.WriteLine("Please pass a valid path: dotnet run --project FileInspectorX.Examples -- <file>");
            return 1;
        }

        Console.WriteLine($"== Examples on: {path}");
        Console.WriteLine();

        DetectionExample.Run(path);
        Console.WriteLine();
        AnalysisExample.Run(path);
        Console.WriteLine();
        ViewsExample.Run(path);

        return 0;
    }

    private static string ResolveDefault()
    {
        var candidates = new[] {
            Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "README.MD"),
            Path.Combine(Directory.GetCurrentDirectory(), "README.MD"),
        };
        foreach (var c in candidates)
        {
            try { var p = Path.GetFullPath(c); if (File.Exists(p)) return p; } catch { }
        }
        return string.Empty;
    }
}

/// <summary>
/// Example 1: Detection-only – minimal classification via Detect and Inspect(DetectOnly=true).
/// </summary>
internal static class DetectionExample
{
    public static void Run(string path)
    {
        Console.WriteLine("[1] Detection-only\n-------------------");

        var det = FileInspector.Detect(path, new FileInspector.DetectionOptions { MagicHeaderBytes = 16 });
        Console.WriteLine($"Detect → ext={det?.Extension}, mime={det?.MimeType}, reason={det?.Reason}, magic={det?.MagicHeaderHex}");

        var detFa = FileInspector.Inspect(path, new FileInspector.DetectionOptions { DetectOnly = true, MagicHeaderBytes = 8 });
        Console.WriteLine($"Inspect(DetectOnly) → kind={detFa.Kind}, det.ext={detFa.Detection?.Extension}, bytes={detFa.Detection?.BytesInspected}");
    }
}

/// <summary>
/// Example 2: Full analysis – one call to Inspect() builds the FileAnalysis payload with flags and hints.
/// </summary>
internal static class AnalysisExample
{
    public static void Run(string path)
    {
        Console.WriteLine("[2] Full analysis\n------------------");
        var fa = FileInspector.Inspect(path, new FileInspector.DetectionOptions { ComputeSha256 = true });
        Console.WriteLine($"Analyze → kind={fa.Kind}, flags={fa.Flags}, det.ext={fa.Detection?.Extension}, sha256={(fa.Detection?.Sha256Hex ?? "").PadRight(16).Substring(0, Math.Min(16, fa.Detection?.Sha256Hex?.Length ?? 0))}...");

        if (fa.ContainerEntryCount is not null)
            Console.WriteLine($"Container: entries={fa.ContainerEntryCount}, top={string.Join(',', fa.ContainerTopExtensions ?? Array.Empty<string>())}, subtype={fa.ContainerSubtype}");
        if (fa.Authenticode?.Present == true)
            Console.WriteLine($"Authenticode: chainValid={fa.Authenticode.ChainValid}, fileHashMatches={fa.Authenticode.FileHashMatches}");
        if (!string.IsNullOrEmpty(fa.TextSubtype))
            Console.WriteLine($"Text: subtype={fa.TextSubtype}, estLines={fa.EstimatedLineCount}");
    }
}

/// <summary>
/// Example 3: Views – project to compact, display-friendly records.
/// </summary>
internal static class ViewsExample
{
    public static void Run(string path)
    {
        Console.WriteLine("[3] Views\n----------");

        var options = new FileInspector.DetectionOptions { ComputeSha256 = true };
        var fa = FileInspector.Inspect(path, options);

        var summary = fa.ToSummaryView(path);
        Console.WriteLine($"Summary: {summary.Path} | {summary.Kind} | {summary.Extension} | {summary.MimeType} | {summary.Reason}");

        var perms = fa.ToPermissionsView(path);
        Console.WriteLine($"Perms: owner={perms.Owner} ({perms.OwnerId}) mode={perms.ModeSymbolic} exec={perms.IsExecutable} everyoneWrite={perms.EveryoneWriteAllowed}");

        // Show signature view only for PE files (exe/dll/sys)
        var ext = (fa.Detection?.Extension ?? string.Empty).ToLowerInvariant();
        if (ext is "exe" or "dll" or "sys")
        {
            var sig = fa.ToSignatureView(path);
            Console.WriteLine($"Sign: present={sig.Present}, chainValid={sig.ChainValid}, fileHashOk={(fa.Authenticode?.FileHashMatches == true)}");
        }
    }
}

