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
        ["PdfEnc"]   = new("PdfEnc",   "PDF Encrypted",               "PDF is encrypted (requires password).",                         "PDF", 80),
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
        // Container encryption notes
        ["rar5:headers-encrypted"] = new("rar5:headers-encrypted", "RAR5 encrypted headers", "RAR v5 archive has encrypted headers; entry counting unavailable without password.", "Archive", 55),
        ["7z:headers-encrypted"]   = new("7z:headers-encrypted",   "7z encrypted headers",   "7z archive uses encrypted headers; entry counting unavailable without password.",   "Archive", 55),
        // Containers (best-effort notes)
        ["7z:headers-encrypted"]   = new("7z:headers-encrypted",   "7z encrypted headers",   "7z archive uses encrypted headers; entry counting unavailable without password.",   "Archive", 55),
        ["7z:files="]              = new("7z:files=",              "7z files (count)",      "7z archive file count (best‑effort when headers unencoded).",   "Archive", 10),
        ["rar5:headers-encrypted"] = new("rar5:headers-encrypted", "RAR5 encrypted headers", "RAR v5 archive has encrypted headers; entry counting unavailable without password.", "Archive", 55),
        // Citrix
        ["citrix:ica"]             = new("citrix:ica",           "Citrix ICA file",        "Citrix ICA connection file (INI-like).",                           "Config", 5),
        ["citrix:receiver-config"] = new("citrix:receiver-config","Citrix Receiver config", "Citrix Receiver/Workspace configuration (XML).",                    "Config", 5),
        // Logs and enterprise artifacts
        ["log:iis-w3c"] = new("log:iis-w3c", "IIS W3C log", "Text matches IIS W3C log format (#Fields/#Version headers).", "Logs", 15),
        ["log:dns"]    = new("log:dns",    "Windows DNS Server log", "DNS Server text log detected.", "Logs", 20),
        ["log:firewall"] = new("log:firewall", "Windows Firewall log", "pfirewall.log style Windows Firewall text log detected.", "Logs", 20),
        ["log:netlogon"] = new("log:netlogon", "Windows Netlogon log", "Netlogon service text log detected.", "Logs", 20),
        ["event-xml"]   = new("event-xml",   "Windows Event XML", "XML export of Windows events detected.", "Logs", 20),
        ["event:txt"]   = new("event:txt",   "Windows Event text log", "Text export of Windows Event Viewer detected.", "Logs", 20),
        ["sysmon"]      = new("sysmon",      "Sysmon XML", "Sysmon event XML detected.", "Logs", 25),
        ["log:dhcp"]    = new("log:dhcp",    "Windows DHCP Server log", "DHCP Server audit log detected.", "Logs", 20),
        ["exchange:msgtrack"] = new("exchange:msgtrack", "Exchange message tracking log", "Exchange Message Tracking log detected.", "Exchange", 25),
        ["defender:txt"] = new("defender:txt", "Windows Defender log", "Windows Defender textual log detected.", "Security", 25),
        ["sql:errorlog"] = new("sql:errorlog", "SQL Server ERRORLOG", "SQL Server error log detected.", "Database", 25),
        ["nps:radius"]  = new("nps:radius",  "NPS/RADIUS log", "Network Policy Server (RADIUS) text log detected.", "Network", 25),
        ["sql:agent"]   = new("sql:agent",   "SQL Server Agent log", "SQL Server Agent textual log detected.", "Database", 20),
        ["ldif"]        = new("ldif",        "LDIF text", "LDAP Data Interchange Format detected (ldif-version/dn:).", "AD", 25),
        ["aad:signin"]  = new("aad:signin",  "AAD Sign-in log", "Azure AD sign-in log JSON detected (userPrincipalName/appId).", "Cloud", 25),
        ["aad:audit"]   = new("aad:audit",   "AAD Audit log", "Azure AD audit log JSON detected.", "Cloud", 25),
        ["mde:alert"]   = new("mde:alert",   "Defender alert/log", "Microsoft Defender alert/log JSON detected (AlertId/ThreatName).", "Security", 35),
        ["ps:transcript"] = new("ps:transcript", "PowerShell transcript", "PowerShell transcript log file.", "Logs", 10),
        // Domain Controllers / Registry artifacts
        ["ad:ntds-dit"] = new("ad:ntds-dit", "AD DS database", "ESE database named NTDS.DIT (Active Directory).", "AD", 70),
        ["reg:sam"]      = new("reg:sam",      "SAM hive", "Windows SAM registry hive (local accounts).", "Registry", 60),
        ["reg:system"]   = new("reg:system",   "SYSTEM hive", "Windows SYSTEM registry hive (boot keys).", "Registry", 60),
        ["reg:security"] = new("reg:security", "SECURITY hive", "Windows SECURITY registry hive.", "Registry", 50),
        // Browsers
        ["browser:login-data"] = new("browser:login-data", "Chromium Login Data", "Chromium-based browser password store (SQLite).", "Browsers", 65),
        ["browser:web-data"]   = new("browser:web-data",   "Chromium Web Data",   "Chromium-based browser web data (autofill/addresses).", "Browsers", 25),
        ["browser:history"]    = new("browser:history",    "Browser History",     "Browser history database (SQLite).", "Browsers", 20),
        ["browser:key-store"]  = new("browser:key-store",  "Firefox key store",   "Firefox key store (key4.db).", "Browsers", 35),
        ["browser:logins-json"] = new("browser:logins-json","Firefox logins.json","Firefox saved logins JSON.", "Browsers", 55),
        // GPO/SYSVOL
        ["gpo:backup"]   = new("gpo:backup",   "GPO backup", "Archive contains Group Policy backup artifacts (gpt.ini/Registry.pol).", "AD", 30),
        ["sysvol:policy"] = new("sysvol:policy", "SYSVOL policy/scripts", "Archive contains SYSVOL policy/scripts folder paths.", "AD", 25),
        // Secrets (categories only)
        ["secret:privkey"]   = new("secret:privkey",   "Private key material", "File appears to contain private key PEM material.", "Secrets", 90),
        ["secret:jwt"]       = new("secret:jwt",       "JWT-like token", "File contains tokens resembling JSON Web Tokens.", "Secrets", 60),
        ["secret:keypattern"] = new("secret:keypattern", "Key/secret pattern", "File contains long high-entropy key= or secret= values.", "Secrets", 50),
        ["secret:token"]     = new("secret:token",     "Token-family secret", "File contains known API token-family formats (e.g., GitHub/AWS/Slack-like).", "Secrets", 70),
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
        var val = flagsCsv ?? string.Empty;
        if (val.Length == 0) return string.Empty;
        var parts = val
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
            else if (s_heuristicsLegend.TryGetValue(f, out var entry) && entry is not null)
            {
                var e = entry;
                friendly.Add(style == HumanizeStyle.Long ? e.Long : e.Short);
            }
            else if (f.StartsWith("rar4:enc=", StringComparison.OrdinalIgnoreCase))
            {
                var val = f.Substring("rar4:enc=".Length);
                var shortTxt = $"RAR4 encrypted files: {val}";
                var longTxt  = $"RAR v4 archive contains password-protected entries: {val}.";
                friendly.Add(style == HumanizeStyle.Long ? longTxt : shortTxt);
            }
            else if (f.StartsWith("pe:exports=", StringComparison.OrdinalIgnoreCase))
            {
                var val = f.Substring("pe:exports=".Length);
                var shortTxt = $"Exports: {val}";
                var longTxt  = $"DLL/EXE exports {val} symbols.";
                friendly.Add(style == HumanizeStyle.Long ? longTxt : shortTxt);
            }
            else if (f.StartsWith("pe:top=", StringComparison.OrdinalIgnoreCase))
            {
                var val = f.Substring("pe:top=".Length);
                var shortTxt = $"Top exports: {val}";
                var longTxt  = $"Top exported names: {val}.";
                friendly.Add(style == HumanizeStyle.Long ? longTxt : shortTxt);
            }
            else if (string.Equals(f, "pe:regsvr", StringComparison.OrdinalIgnoreCase))
            {
                friendly.Add(style == HumanizeStyle.Long ? "COM registration exports present (DllRegisterServer/DllInstall)." : "COM registration exports present");
            }
            else if (string.Equals(f, "pe:servicemain", StringComparison.OrdinalIgnoreCase))
            {
                friendly.Add(style == HumanizeStyle.Long ? "Service entry indicator found (ServiceMain)." : "ServiceMain string present");
            }
            else if (f.StartsWith("7z:files=", StringComparison.OrdinalIgnoreCase))
            {
                var val = f.Substring("7z:files=".Length);
                var shortTxt = $"7z files: {val}";
                var longTxt  = $"7z archive file count: {val} (best‑effort).";
                friendly.Add(style == HumanizeStyle.Long ? longTxt : shortTxt);
            }
            else if (f.StartsWith("rar4:enc=", StringComparison.OrdinalIgnoreCase))
            {
                var val = f.Substring("rar4:enc=".Length);
                var shortTxt = $"RAR4 encrypted files: {val}";
                var longTxt  = $"RAR v4 archive contains password-protected entries: {val}.";
                friendly.Add(style == HumanizeStyle.Long ? longTxt : shortTxt);
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
