using System;
using System.Collections.Generic;
using System.Linq;

namespace FileInspectorX;

internal sealed class ScriptFindingRule
{
    public ScriptFindingRule(
        string code,
        string shortText,
        string longText,
        string category,
        int severity,
        string assessmentCode,
        int assessmentWeight,
        string assessmentShort,
        string assessmentLong,
        int assessmentSeverity,
        IReadOnlyList<string> behaviorTags,
        IReadOnlyList<string> any,
        IReadOnlyList<string>? requiredAny = null,
        IReadOnlyList<string>? requiredAll = null,
        IReadOnlyList<string>? excludedAny = null,
        int minHitsInFile = 1,
        bool collectSnippets = true)
    {
        Code = code;
        ShortText = shortText;
        LongText = longText;
        Category = category;
        Severity = severity;
        AssessmentCode = assessmentCode;
        AssessmentWeight = assessmentWeight;
        AssessmentShort = assessmentShort;
        AssessmentLong = assessmentLong;
        AssessmentSeverity = assessmentSeverity;
        BehaviorTags = behaviorTags;
        Any = any;
        RequiredAny = requiredAny;
        RequiredAll = requiredAll;
        ExcludedAny = excludedAny;
        MinHitsInFile = minHitsInFile;
        CollectSnippets = collectSnippets;
    }

    public string Code { get; }
    public string ShortText { get; }
    public string LongText { get; }
    public string Category { get; }
    public int Severity { get; }
    public string AssessmentCode { get; }
    public int AssessmentWeight { get; }
    public string AssessmentShort { get; }
    public string AssessmentLong { get; }
    public int AssessmentSeverity { get; }
    public IReadOnlyList<string> BehaviorTags { get; }
    public IReadOnlyList<string> Any { get; }
    public IReadOnlyList<string>? RequiredAny { get; }
    public IReadOnlyList<string>? RequiredAll { get; }
    public IReadOnlyList<string>? ExcludedAny { get; }
    public int MinHitsInFile { get; }
    public bool CollectSnippets { get; }

    public LegendEntry ToFindingLegend()
        => new(Code, ShortText, LongText, Category, Severity);

    public LegendEntry ToAssessmentLegend()
        => new(AssessmentCode, AssessmentShort, AssessmentLong, "Content", AssessmentSeverity);
}

internal static class ScriptFindingRuleCatalog
{
    private static readonly IReadOnlyList<ScriptFindingRule> s_rules = new[]
    {
        Rule("ps:encoded", "PowerShell encoded payload", "PowerShell encodedCommand/base64 indicators.", 70, "Script.Encoded", 25, "Encoded script invocation", "Script includes encoded-command or base64 decode patterns associated with payload staging.", 55, Tags("Obfuscation", "Execution"), Any("frombase64string(", "encodedcommand", "-enc ")),
        Rule("ps:iex", "PowerShell IEX", "Invoke-Expression usage (dynamic execution).", 60, "Script.IEX", 20, "Dynamic expression execution", "Script invokes expression-style runtime execution.", 50, Tags("Execution"), Any("invoke-expression", "iex ")),
        Rule("ps:web-dl", "PowerShell web download", "Invoke-WebRequest/Invoke-RestMethod/file download.", 55, "Script.WebDownload", 15, "Web download behavior", "Script downloads content from web endpoints at runtime.", 45, Tags("NetworkStaging"), Any("invoke-webrequest", "invoke-restmethod", "downloadstring(", "new-object system.net.webclient")),
        Rule("ps:reflection", "PowerShell reflection", "Reflection/Add-Type usage (dynamic code).", 50, "Script.Reflection", 10, "Reflection-based loading", "Script uses reflection or runtime type loading patterns.", 40, Tags("Execution", "Evasion"), Any("add-type", "reflection.assembly", "[reflection.assembly]::load")),
        Rule("py:exec-b64", "Python base64 exec", "Python exec with base64-decoded strings.", 60, "Script.PyExecB64", 20, "Python base64 execution", "Python script combines runtime execution with base64 decoding.", 50, Tags("Obfuscation", "Execution"), Any("base64.b64decode(", "b64decode("), Any("exec(")),
        Rule("py:exec", "Python process execution", "Python script launches commands or subprocesses.", 40, "Script.PyExec", 10, "Python process execution", "Python script launches commands or subprocesses.", 40, Tags("Execution"), Any("subprocess.popen(", "os.system(")),
        Rule("rb:eval", "Ruby eval", "Ruby eval/dynamic execution.", 40, "Script.RbEval", 10, "Ruby eval or exec", "Ruby script uses eval, exec, or remote open patterns.", 40, Tags("Execution"), Any("eval(", "kernel.exec(", "open-uri")),
        Rule("lua:exec", "Lua exec", "Lua code execution helpers.", 40, "Script.LuaExec", 10, "Lua runtime execution", "Lua script uses loadstring or operating-system command execution.", 40, Tags("Execution"), Any("loadstring(", "os.execute(")),
        Rule("bat:certutil", "certutil usage", "certutil -decode or similar file decode activity.", 45, "Script.CertutilDecode", 15, "certutil decode", "Script uses certutil decode behavior associated with payload reconstruction.", 45, Tags("Obfuscation", "Execution"), Any("certutil -decode", "certutil.exe -decode")),
        Rule("js:activex", "JavaScript ActiveX", "ActiveX/COM usage (e.g., WScript.Shell, ADODB.Stream).", 55, "Script.ActiveX", 15, "ActiveX/COM script", "Script uses ActiveX or COM automation patterns associated with payload delivery.", 50, Tags("Execution"), Any("wscript.shell", "activexobject", "adodb.stream")),
        Rule("js:mshta", "JavaScript mshta", "mshta usage (HTML application execution).", 55, "Script.Mshta", 20, "mshta execution", "Script references mshta-style HTML application execution.", 55, Tags("Execution"), Any("mshta ", "mshta.exe")),
        Rule("js:fromcharcode", "Suspicious string assembly", "Long chains of String.fromCharCode().", 45, "Script.FromCharCode", 10, "String assembly obfuscation", "Script builds long strings through repeated character-code assembly.", 40, Tags("Obfuscation"), Any("fromcharcode("), minHitsInFile: 21),
        Rule("script:bitsadmin-transfer", "BITS transfer", "Script starts a BITS transfer job.", 45, "Script.BitsadminTransfer", 15, "BITS transfer", "Script starts a BITS transfer job.", 45, Tags("NetworkStaging"), Any("bitsadmin.exe", "bitsadmin "), Any("/transfer")),
        Rule("script:bitsadmin-transfer", "BITS transfer", "Script starts a BITS transfer job.", 45, "Script.BitsadminTransfer", 15, "BITS transfer", "Script starts a BITS transfer job.", 45, Tags("NetworkStaging"), Any("start-bitstransfer")),
        Rule("script:amsi-bypass", "AMSI bypass indicator", "Script references AMSI bypass internals.", 75, "Script.AmsiBypass", 30, "AMSI bypass indicator", "Script references AMSI bypass internals.", 75, Tags("DefenseEvasion"), Any("amsiutils", "amsiinitfailed", "amsicontext")),
        Rule("script:keylogging-api", "Keyboard capture API", "Script references keyboard hook or key-state APIs.", 85, "Script.KeyloggingApi", 35, "Keyboard capture API", "Script references keyboard hook or key-state APIs.", 85, Tags("CredentialAccess", "Collection"), Any("setwindowshookex", "wh_keyboard_ll", "getasynckeystate", "getkeyboardstate", "registerrawinputdevices")),
        Rule("script:pinvoke", "Native API invocation", "Script uses P/Invoke or native Windows API loading.", 45, "Script.PInvoke", 10, "Native API invocation", "Script uses P/Invoke or native Windows API loading.", 45, Tags("Execution"), Any("dllimport", "loadlibrary")),
        Rule("script:pinvoke", "Native API invocation", "Script uses P/Invoke or native Windows API loading.", 45, "Script.PInvoke", 10, "Native API invocation", "Script uses P/Invoke or native Windows API loading.", 45, Tags("Execution"), Any("user32.dll", "kernel32.dll"), Any("dllimport", "loadlibrary", "add-type")),
        Rule("script:foreground-window", "Window text inspection", "Script reads foreground window or window text state.", 35, "Script.ForegroundWindowRead", 6, "Window text inspection", "Script reads foreground window or window text state.", 35, Tags("Collection"), Any("getforegroundwindow", "getwindowtext")),
        Rule("script:registry-run-key", "Registry run key", "Script modifies Windows autorun registry paths.", 65, "Script.Persistence", 25, "Persistence mechanism", "Script modifies autorun keys, scheduled tasks, or startup-folder persistence.", 65, Tags("Persistence"), Any("currentversion\\run"), Any("reg add", "reg.exe add", "new-itemproperty", "set-itemproperty", "new-item", "set-item")),
        Rule("script:registry-modify", "Registry modification", "Script modifies registry values or properties.", 35, "Script.RegistryModify", 8, "Registry modification", "Script modifies registry values or properties.", 35, Tags("Persistence", "SystemModification"), Any("reg add", "reg.exe add")),
        Rule("script:registry-modify", "Registry modification", "Script modifies registry values or properties.", 35, "Script.RegistryModify", 8, "Registry modification", "Script modifies registry values or properties.", 35, Tags("Persistence", "SystemModification"), Any("new-itemproperty", "set-itemproperty"), Any("hklm:", "hkcu:", "hkcr:", "hku:", "hkcc:", "registry::", "hkey_local_machine", "hkey_current_user", "hkey_classes_root", "hkey_users", "hkey_current_config")),
        Rule("script:scheduled-task", "Scheduled task creation", "Script creates or registers scheduled tasks.", 65, "Script.Persistence", 25, "Persistence mechanism", "Script references autorun keys, scheduled tasks, or startup-folder persistence.", 65, Tags("Persistence"), Any("schtasks /create", "schtasks.exe /create", "register-scheduledtask")),
        Rule("script:startup-folder", "Startup folder persistence", "Script modifies the Windows startup folder.", 60, "Script.Persistence", 20, "Persistence mechanism", "Script modifies autorun keys, scheduled tasks, or startup-folder persistence.", 65, Tags("Persistence"), Any("\\start menu\\programs\\startup"), Any("copy-item", "move-item", "new-item", "set-content", "add-content", "out-file", "copy ", "xcopy ", "robocopy ")),
        Rule("script:vssadmin-shadows", "Shadow copy deletion", "Script deletes Windows shadow copies.", 85, "Script.ShadowCopyDeletion", 35, "Shadow copy deletion", "Script deletes Windows shadow copies.", 85, Tags("Destructive", "Impact"), Any("vssadmin delete shadows", "vssadmin.exe delete shadows")),
        Rule("script:cipher-wipe", "Cipher wipe", "Script invokes cipher wipe behavior.", 70, "Script.CipherWipe", 25, "Cipher wipe", "Script invokes cipher wipe behavior.", 70, Tags("Destructive", "Impact"), Any("cipher /w", "cipher.exe /w")),
        Rule("script:format-drive", "Drive format command", "Script invokes drive format behavior.", 90, "Script.FormatDrive", 40, "Drive format command", "Script invokes drive format behavior.", 90, Tags("Destructive", "Impact"), Any("format a:", "format b:", "format c:", "format d:", "format e:", "format f:", "format g:", "format h:", "format i:", "format j:", "format k:", "format l:", "format m:", "format n:", "format o:", "format p:", "format q:", "format r:", "format s:", "format t:", "format u:", "format v:", "format w:", "format x:", "format y:", "format z:")),
        Rule("script:format-drive", "Drive format command", "Script invokes drive format behavior.", 90, "Script.FormatDrive", 40, "Drive format command", "Script invokes drive or volume format behavior.", 90, Tags("Destructive", "Impact"), Any("format fs=")),
        Rule("script:recursive-force-delete", "Recursive forced delete", "Script removes files recursively with force flags.", 60, "Script.RecursiveForceDelete", 15, "Recursive forced delete", "Script removes files recursively with force flags.", 60, Tags("Destructive"), Any("remove-item"), requiredAll: Any("-recurse", "-force")),
        Rule("script:recursive-force-delete", "Recursive forced delete", "Script removes files recursively with force flags.", 60, "Script.RecursiveForceDelete", 15, "Recursive forced delete", "Script removes files recursively with force flags.", 60, Tags("Destructive"), Any("rd /s /q", "rmdir /s /q", "del /s /f", "del /s /q")),
        Rule("script:bcdedit", "Boot configuration edit", "Script edits Windows boot configuration.", 60, "Script.BootConfigEdit", 20, "Boot configuration edit", "Script edits Windows boot configuration.", 60, Tags("DefenseEvasion", "SystemModification"), Any("bcdedit"), Any("/set", "/deletevalue", "/delete", "/create", "/copy", "/import", "/default", "/displayorder", "/bootsequence", "/timeout", "/ems", "/emssettings", "/debug", "/dbgsettings", "/hypervisorsettings")),
        Rule("script:hidden-window", "Hidden window launch", "Script launches processes hidden from view.", 45, "Script.HiddenWindow", 10, "Hidden window launch", "Script launches processes hidden from view.", 45, Tags("DefenseEvasion"), Any("-windowstyle hidden", " -w hidden")),
        Rule("script:indirect-exec", "Indirect execution host", "Script invokes dual-use hosts such as rundll32, regsvr32, wscript, or cscript.", 60, "Script.IndirectExecution", 20, "Indirect execution host", "Script invokes dual-use execution hosts.", 60, Tags("Execution", "DefenseEvasion"), Any("rundll32 ", "rundll32.exe", "regsvr32 ", "regsvr32.exe", "wscript ", "wscript.exe", "cscript ", "cscript.exe")),
        Rule("script:attrib-hidden", "Hidden attribute set", "Script hides files with attrib.", 35, "Script.AttribHidden", 8, "Hidden attribute set", "Script hides files with attrib.", 35, Tags("DefenseEvasion"), Any("attrib ", "attrib.exe"), Any("+h")),
        Rule("script:credential-dump-hint", "Credential dumping hint", "Script references credential dumping or LSASS-related terms.", 80, "Sig.CredentialDumpHint", 30, "Credential dumping hint", "Script references credential dumping or LSASS-related terms.", 80, Tags("CredentialAccess"), SecurityHeuristics.SensitiveIndicators),
        Rule("script:plaintext-credential", "Plaintext credential conversion", "Script converts plaintext into credential material.", 45, "Script.PlaintextCredential", 10, "Plaintext credential conversion", "Script converts plaintext into credential material.", 45, Tags("CredentialAccess"), Any("convertto-securestring"), Any("-asplaintext"), collectSnippets: false),
        Rule("script:clipboard-read", "Clipboard read", "Script reads clipboard contents.", 35, "Script.ClipboardRead", 8, "Clipboard read", "Script reads clipboard contents.", 35, Tags("Collection"), Any("get-clipboard")),
        Rule("script:elevation-request", "Elevation request", "Script requests administrator execution.", 35, "Script.ElevationRequest", 8, "Elevation request", "Script requests administrator execution.", 35, Tags("PrivilegeEscalation"), Any("#requires -runasadministrator", "-verb runas")),
        Rule("script:execution-policy-bypass", "Execution policy bypass", "Script bypasses or relaxes PowerShell execution policy.", 50, "Script.ExecutionPolicyBypass", 10, "Execution policy bypass", "Script bypasses or relaxes PowerShell execution policy.", 50, Tags("DefenseEvasion"), Any("set-executionpolicy bypass", "set-executionpolicy unrestricted")),
        Rule("script:execution-policy-bypass", "Execution policy bypass", "Script bypasses or relaxes PowerShell execution policy.", 50, "Script.ExecutionPolicyBypass", 10, "Execution policy bypass", "Script bypasses or relaxes PowerShell execution policy.", 50, Tags("DefenseEvasion"), Any("set-executionpolicy -executionpolicy bypass", "set-executionpolicy -executionpolicy unrestricted")),
        Rule("script:execution-policy-bypass", "Execution policy bypass", "Script bypasses or relaxes PowerShell execution policy.", 50, "Script.ExecutionPolicyBypass", 10, "Execution policy bypass", "Script bypasses or relaxes PowerShell execution policy.", 50, Tags("DefenseEvasion"), Any("powershell", "pwsh"), Any("-executionpolicy bypass", "-executionpolicy unrestricted", "-ep bypass", "-ep unrestricted")),
        Rule("script:defender-tamper", "Security tool tampering", "Script disables or weakens Defender, firewall, or security exclusions.", 85, "Script.SecurityToolTamper", 35, "Security tool tampering", "Script disables or weakens Defender, firewall, or security exclusions.", 85, Tags("DefenseEvasion"), Any("set-mppreference", "add-mppreference"), Any("-disablerealtimemonitoring", "-disableioavprotection", "-disablebehaviormonitoring", "-disableblockatfirstseen", "-disableintrusionpreventionsystem", "-disablescriptscanning", "-exclusionpath", "-exclusionextension", "-exclusionprocess")),
        Rule("script:defender-tamper", "Security tool tampering", "Script disables or weakens Defender, firewall, or security exclusions.", 85, "Script.SecurityToolTamper", 35, "Security tool tampering", "Script disables or weakens Defender, firewall, or security exclusions.", 85, Tags("DefenseEvasion"), Any("netsh advfirewall", "netsh.exe advfirewall", "netsh firewall", "netsh.exe firewall"), Any(" off", "disable")),
        Rule("script:defender-tamper", "Security tool tampering", "Script disables or weakens Defender, firewall, or security exclusions.", 85, "Script.SecurityToolTamper", 35, "Security tool tampering", "Script disables or weakens Defender, firewall, or security exclusions.", 85, Tags("DefenseEvasion"), Any("set-netfirewallprofile"), Any("-enabled false", "-enabled:false", "-enabled $false", "-enabled:$false"))
    };

    public static IReadOnlyList<ScriptFindingRule> Rules => s_rules;

    public static bool TryGetRule(string? code, out ScriptFindingRule rule)
    {
        rule = s_rules.FirstOrDefault(item => string.Equals(item.Code, code, StringComparison.OrdinalIgnoreCase))!;
        return rule != null;
    }

    public static bool TryGetAssessmentRule(string? assessmentCode, out ScriptFindingRule rule)
    {
        rule = s_rules.FirstOrDefault(item => string.Equals(item.AssessmentCode, assessmentCode, StringComparison.OrdinalIgnoreCase))!;
        return rule != null;
    }

    private static ScriptFindingRule Rule(
        string code,
        string shortText,
        string longText,
        int severity,
        string assessmentCode,
        int assessmentWeight,
        string assessmentShort,
        string assessmentLong,
        int assessmentSeverity,
        IReadOnlyList<string> behaviorTags,
        IReadOnlyList<string> any,
        IReadOnlyList<string>? requiredAny = null,
        IReadOnlyList<string>? requiredAll = null,
        IReadOnlyList<string>? excludedAny = null,
        int minHitsInFile = 1,
        bool collectSnippets = true)
        => new(code, shortText, longText, "Script", severity, assessmentCode, assessmentWeight, assessmentShort, assessmentLong, assessmentSeverity, behaviorTags, any, requiredAny, requiredAll, excludedAny, minHitsInFile, collectSnippets);

    private static IReadOnlyList<string> Any(params string[] values) => values;

    private static IReadOnlyList<string> Tags(params string[] values) => values;
}
