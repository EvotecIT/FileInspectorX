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
internal static partial class Program
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

        Method1(path);
        Console.WriteLine();
        Method2(path);
        Console.WriteLine();
        Method3(path);

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
