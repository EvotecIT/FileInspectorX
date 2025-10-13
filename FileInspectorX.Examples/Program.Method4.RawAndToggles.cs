using FileInspectorX;

/// <summary>
/// Example 4: Show Raw (full object) and include/exclude toggles.
/// </summary>
internal static partial class Program
{
    public static void Method4_RawAndToggles(string path)
    {
        Console.WriteLine("[4] Raw + Toggles\n-------------------");

        var full = FileInspector.Analyze(path, new FileInspector.DetectionOptions { ComputeSha256 = true });
        Console.WriteLine($"Kind={full.Kind} Ext={full.Detection?.Extension} Flags={full.Flags}");
        Console.WriteLine($"Assessment: {full.Assessment?.Decision} Score={full.Assessment?.Score}");

        // Build a lean object without permissions and references
        var lean = FileInspector.Analyze(path, new FileInspector.DetectionOptions {
            IncludePermissions = false,
            IncludeReferences = false,
            IncludeInstaller = true,
            IncludeAuthenticode = true,
            IncludeAssessment = true
        });
        Console.WriteLine($"Lean: hasSecurity={(lean.Security!=null)} hasRefs={(lean.References!=null)} installer={lean.Installer?.Kind}");
    }
}

