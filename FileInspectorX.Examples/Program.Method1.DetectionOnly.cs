using FileInspectorX;

/// <summary>
///
/// </summary>
internal static partial class Program {
    // Example 1: Detection-only – minimal classification via Detect and Inspect(DetectOnly=true).
    public static void Method1(string path) {
        Console.WriteLine("[1] Detection-only\n-------------------");

        var det = FileInspector.Detect(path, new FileInspector.DetectionOptions { MagicHeaderBytes = 16 });
        Console.WriteLine($"Detect → ext={det?.Extension}, mime={det?.MimeType}, reason={det?.Reason}, magic={det?.MagicHeaderHex}");

        var detFa = FileInspector.Inspect(path, new FileInspector.DetectionOptions { DetectOnly = true, MagicHeaderBytes = 8 });
        Console.WriteLine($"Inspect(DetectOnly) → kind={detFa.Kind}, det.ext={detFa.Detection?.Extension}, bytes={detFa.Detection?.BytesInspected}");
    }
}

