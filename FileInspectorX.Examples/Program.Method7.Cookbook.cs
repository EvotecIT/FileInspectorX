using FileInspectorX;

/// <summary>
/// Example 7: Cookbook – compact, copy/paste-friendly snippets to learn the API fast.
/// </summary>
internal static partial class Program
{
    public static void Method7_Cookbook(string path)
    {
        Console.WriteLine("[7] Cookbook\n-------------");

        // 1) Detection only (fast, minimal I/O)
        var det = FileInspector.Detect(path, new FileInspector.DetectionOptions { MagicHeaderBytes = 16 });
        Console.WriteLine($"[detect] ext={det?.Extension} mime={det?.MimeType} conf={det?.Confidence} reason={det?.Reason}");

        // 2) Full analysis (defaults)
        var full = FileInspector.Analyze(path);
        Console.WriteLine($"[analyze] kind={full.Kind} flags={full.Flags}");

        // 3) Views for display (each view carries Raw with the full object)
        var summary = full.ToSummaryView(path);
        Console.WriteLine($"[summary] {summary.Extension} {summary.MimeType} {summary.Flags}");

        // 4) Include/Exclude toggles (build lean object)
        var lean = FileInspector.Analyze(path, new FileInspector.DetectionOptions {
            IncludePermissions = false,
            IncludeReferences = false,
            IncludeInstaller = true,
            IncludeAssessment = true
        });
        Console.WriteLine($"[lean] hasSec={(lean.Security!=null)} hasRefs={(lean.References!=null)} inst={lean.Installer?.Kind}");

        // 5) Assessment + vendor allow-list
        Settings.AllowedVendors = new[] { "Microsoft", "YourCompany" };
        Settings.VendorMatchMode = VendorMatchMode.Contains;
        var assess = lean.Assessment ?? FileInspector.Assess(lean);
        Console.WriteLine($"[assess] {assess.Decision} score={assess.Score} codes={string.Join(",", assess.Codes)}");

        // 6) Directory scan (sync)
        var dir = System.IO.Path.GetDirectoryName(path) ?? ".";
        foreach (var a in FileInspector.AnalyzeDirectory(dir, System.IO.SearchOption.TopDirectoryOnly))
            if ((a.Flags & ContentFlags.ContainerContainsExecutables) != 0)
                Console.WriteLine($"[dir] exec in container: {a.Detection?.Extension}");
    }
}

