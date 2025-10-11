using FileInspectorX;

/// <summary>
/// Example program demonstrating the use of FileInspectorX.
/// </summary>
internal static partial class Program
{
    // Example 2: Full analysis – one call to Inspect() builds the FileAnalysis payload with flags and hints.
    public static void Method2(string path)
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

