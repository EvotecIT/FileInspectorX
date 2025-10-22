using System;
using System.Collections.Generic;
using System.Linq;

namespace FileInspectorX;

/// <summary>
/// Provides typed, reusable humanization and legend data for FileInspectorX codes.
/// Hosts can call these helpers to render short or long strings in UIs/emails.
/// </summary>
public static class Legend
{
    private static readonly Dictionary<string, LegendEntry> s_flagLegend = new(StringComparer.OrdinalIgnoreCase)
    {
        // Core flags used by ReportView.FlagsCsv
        ["Macros"]   = new("Macros",   "Contains Macros",             "OOXML document contains vbaProject.bin (macros).",              "OOXML", 60),
        ["HasExe"]   = new("HasExe",   "Contains Executables",       "Archive includes executable modules (.exe/.dll/.msi).",         "Archive", 70),
        ["HasScript"]= new("HasScript","Contains Scripts",           "Archive includes script files (.ps1/.sh/.bat/.js/.py/.rb).",     "Archive", 50),
        ["PdfJS"]    = new("PdfJS",    "PDF JavaScript",             "PDF contains JavaScript (/JS or /JavaScript markers).",         "PDF", 65),
        ["PdfOpen"]  = new("PdfOpen",  "PDF OpenAction",             "PDF defines an /OpenAction entry (auto-run on open).",          "PDF", 55),
        ["PdfAA"]    = new("PdfAA",    "PDF Additional Actions",     "PDF declares /AA (AdditionalActions).",                        "PDF", 45),
        ["DotNet"]   = new("DotNet",   ".NET Assembly",               "Managed PE file (COM descriptor present).",                     "PE", 20),
        ["SigPresent"]= new("SigPresent","Authenticode Present",     "PE has an Authenticode signature blob (WIN_CERTIFICATE).",      "PE", 10),
        ["ZipEnc"]   = new("ZipEnc",   "Archive Encrypted Entries",   "Archive contains password-protected items.",                    "Archive", 75),
        ["OoxmlEnc"] = new("OoxmlEnc", "OOXML Encrypted",             "Office document is encrypted (requires password).",            "OOXML", 80),
        ["DisgExec"] = new("DisgExec", "Disguised Executables",       "Container holds executables disguised by extension.",          "Archive", 70),
    };

    private static readonly Dictionary<string, LegendEntry> s_heuristicsLegend = new(StringComparer.OrdinalIgnoreCase)
    {
        // Common script/security cues (SecurityFindings and InnerFindings tokens)
        ["ps:encoded"]  = new("ps:encoded",  "PowerShell encoded payload", "PowerShell encodedCommand/base64 indicators.",          "Script", 70),
        ["ps:iex"]      = new("ps:iex",      "PowerShell IEX",            "Invoke-Expression usage (dynamic execution).",           "Script", 60),
        ["ps:web-dl"]   = new("ps:web-dl",   "PowerShell web download",    "Invoke-WebRequest/Invoke-RestMethod/file download.",    "Script", 55),
        ["ps:reflection"] = new("ps:reflection","PowerShell reflection",   "Reflection/Add-Type usage (dynamic code).",             "Script", 50),
        ["js:activex"]  = new("js:activex",  "JavaScript ActiveX",         "ActiveX/COM usage (e.g., WScript.Shell, ADODB.Stream).","Script", 55),
        ["js:mshta"]    = new("js:mshta",    "JavaScript mshta",           "mshta usage (HTML application execution).",             "Script", 55),
        ["js:fromcharcode"] = new("js:fromcharcode", "Suspicious string assembly", "Long chains of String.fromCharCode().",     "Script", 45),
        ["bat:certutil"] = new("bat:certutil", "certutil usage",            "certutil -decode or similar file decode activity.",    "Script", 45),
        ["py:exec-b64"] = new("py:exec-b64", "Python base64 exec",         "Python exec with base64-decoded strings.",             "Script", 60),
        ["lua:exec"]    = new("lua:exec",    "Lua exec",                   "Lua code execution helpers.",                           "Script", 40),
        ["rb:eval"]     = new("rb:eval",     "Ruby eval",                  "Ruby eval/dynamic execution.",                          "Script", 40),
        // Pattern-based notes (rendered via HumanizeFindings):
        // tool:<name> and toolhash:<name> are handled dynamically.
    };

    /// <summary>Returns legend for analysis flags.</summary>
    public static IReadOnlyList<LegendEntry> GetAnalysisFlagLegend()
        => s_flagLegend.Values.OrderByDescending(e => e.Severity ?? 0).ThenBy(e => e.Short, StringComparer.OrdinalIgnoreCase).ToList();

    /// <summary>Returns legend for known heuristic/security findings.</summary>
    public static IReadOnlyList<LegendEntry> GetHeuristicsLegend()
        => s_heuristicsLegend.Values.OrderByDescending(e => e.Severity ?? 0).ThenBy(e => e.Short, StringComparer.OrdinalIgnoreCase).ToList();

    /// <summary>
    /// Humanizes a CSV of analysis flag codes (e.g., "Macros,ZipEnc") using short or long labels.
    /// </summary>
    public static string HumanizeFlagsCsv(string? flagsCsv, HumanizeStyle style = HumanizeStyle.Short, string separator = ", ")
    {
        if (string.IsNullOrWhiteSpace(flagsCsv)) return string.Empty;
        var parts = flagsCsv
            .Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(s => s.Trim());
        var labels = new List<string>();
        foreach (var p in parts)
        {
            if (s_flagLegend.TryGetValue(p, out var entry))
                labels.Add(style == HumanizeStyle.Long ? entry.Long : entry.Short);
            else
                labels.Add(p);
        }
        return string.Join(separator, labels);
    }

    /// <summary>
    /// Humanizes inner/heuristic findings. Recognizes tool:/toolhash: patterns and known codes in the heuristics legend.
    /// </summary>
    public static string HumanizeFindings(IEnumerable<string>? findings, HumanizeStyle style = HumanizeStyle.Short, int limit = 6, string separator = ", ")
    {
        if (findings == null) return string.Empty;
        var friendly = new List<string>();
        foreach (var f in findings)
        {
            if (string.IsNullOrWhiteSpace(f)) continue;
            if (f.StartsWith("toolhash:", StringComparison.OrdinalIgnoreCase))
            {
                var val = f.Substring("toolhash:".Length);
                var shortTxt = $"Tool (hash): {val}";
                var longTxt  = $"Known tool matched by hash: {val}";
                friendly.Add(style == HumanizeStyle.Long ? longTxt : shortTxt);
            }
            else if (f.StartsWith("tool:", StringComparison.OrdinalIgnoreCase))
            {
                var val = f.Substring("tool:".Length);
                var shortTxt = $"Tool: {val}";
                var longTxt  = $"Known tool detected by name: {val}";
                friendly.Add(style == HumanizeStyle.Long ? longTxt : shortTxt);
            }
            else if (s_heuristicsLegend.TryGetValue(f, out var entry))
            {
                friendly.Add(style == HumanizeStyle.Long ? entry.Long : entry.Short);
            }
            else
            {
                friendly.Add(f);
            }
        }
        if (friendly.Count == 0) return string.Empty;
        if (limit > 0 && friendly.Count > limit)
        {
            var head = friendly.Take(limit);
            var more = friendly.Count - limit;
            return string.Join(separator, head) + $" (+{more} more)";
        }
        return string.Join(separator, friendly);
    }
}
