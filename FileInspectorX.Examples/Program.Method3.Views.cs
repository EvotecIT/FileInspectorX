using FileInspectorX;

/// <summary>
/// Example 3: Views – project to compact, display-friendly records.
/// </summary>
internal static partial class Program
{
    // Example 3: Views – project to compact, display-friendly records.
    public static void Method3(string path)
    {
        Console.WriteLine("[3] Views\n----------");

        var options = new FileInspector.DetectionOptions { ComputeSha256 = true };
        var fa = FileInspector.Inspect(path, options);

        var summary = fa.ToSummaryView(path);
        Console.WriteLine($"Summary: {summary.Path} | {summary.Kind} | {summary.Extension} | {summary.MimeType} | {summary.Reason}");

        var perms = fa.ToPermissionsView(path);
        Console.WriteLine($"Perms: owner={perms.Owner} ({perms.OwnerId}) mode={perms.ModeSymbolic} exec={perms.IsExecutable} everyoneWrite={perms.EveryoneWriteAllowed}");

        var ext = (fa.Detection?.Extension ?? string.Empty).ToLowerInvariant();
        if (ext is "exe" or "dll" or "sys")
        {
            var sig = fa.ToSignatureView(path);
            Console.WriteLine($"Sign: present={sig.Present}, chainValid={sig.ChainValid}, fileHashOk={(fa.Authenticode?.FileHashMatches == true)}");
        }

        if (fa.References != null && fa.References.Count > 0)
        {
            Console.WriteLine($"Refs: {fa.References.Count} items");
            foreach (var rv in fa.ToReferencesView(path))
            {
                Console.WriteLine($"  - {rv.Kind}: {rv.Value} exists={rv.Exists} issues={rv.Issues} src={rv.Source}");
            }
        }

        var assess = fa.ToAssessmentView(path);
        Console.WriteLine($"Assess: score={assess.Score} decision={assess.Decision} codes={assess.Codes}");
    }
}

