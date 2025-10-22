namespace FileInspectorX;

/// <summary>
/// Describes a single legend entry used to humanize analysis signals or heuristic codes.
/// </summary>
public sealed class LegendEntry
{
    /// <summary>Stable code (e.g., "Macros", "ZipEnc", "ps:encoded").</summary>
    public string Code { get; }
    /// <summary>Short label, compact for inline displays.</summary>
    public string Short { get; }
    /// <summary>Long description, suitable for legends and tooltips.</summary>
    public string Long { get; }
    /// <summary>Optional category grouping (e.g., "PDF", "OOXML", "Archive", "Script").</summary>
    public string? Category { get; }
    /// <summary>Optional rough severity (0–100) for ordering; neutral when null.</summary>
    public int? Severity { get; }

    /// <summary>Create a new legend entry.</summary>
    public LegendEntry(string code, string @short, string @long, string? category = null, int? severity = null)
    {
        Code = code; Short = @short; Long = @long; Category = category; Severity = severity;
    }
}

/// <summary>
/// Presentation style for humanizing lists.
/// </summary>
/// <summary>
/// Output verbosity for humanized text.
/// </summary>
public enum HumanizeStyle {
    /// <summary>Concise labels for inline displays (e.g., lists, tables).</summary>
    Short,
    /// <summary>Descriptive labels for legends/tooltips (full sentences).</summary>
    Long
}

/// <summary>
/// Script language legend helpers.
/// </summary>
public static class ScriptLanguageLegend
{
    private static readonly Dictionary<string, LegendEntry> s = new(StringComparer.OrdinalIgnoreCase)
    {
        ["powershell"] = new("powershell", "PowerShell", "PowerShell script (ps1/psm1/psd1).", "Script", 40),
        ["shell"]      = new("shell",      "Shell",      "POSIX shell script (sh/bash/zsh).", "Script", 30),
        ["batch"]      = new("batch",      "Batch",      "Windows batch script (.bat/.cmd).", "Script", 25),
        ["python"]     = new("python",     "Python",     "Python script.", "Script", 35),
        ["ruby"]       = new("ruby",       "Ruby",       "Ruby script.", "Script", 30),
        ["lua"]        = new("lua",        "Lua",        "Lua script.", "Script", 25),
        ["javascript"] = new("javascript", "JavaScript", "JavaScript (Node/WSH).", "Script", 30)
    };

    /// <summary>Returns a typed legend for known script languages.</summary>
    public static IReadOnlyList<LegendEntry> GetLegend() => s.Values.ToList();
    /// <summary>Humanizes a language key to short or long text.</summary>
    public static string Humanize(string? key, HumanizeStyle style = HumanizeStyle.Short)
    {
        if (string.IsNullOrWhiteSpace(key)) return string.Empty;
        if (s.TryGetValue(key, out var e)) return style == HumanizeStyle.Long ? e.Long : e.Short;
        return key!;
    }
}
