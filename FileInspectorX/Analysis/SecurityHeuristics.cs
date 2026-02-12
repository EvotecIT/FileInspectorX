namespace FileInspectorX;

/// <summary>
/// Lightweight, dependency-free content heuristics used to emit neutral security signals and detect simple secret categories.
/// </summary>
internal static partial class SecurityHeuristics
{
    // ACTIVE (default): Base64-encoded indicators decoded at runtime to avoid static signatures
    private static readonly string[] SensitiveIndicators = DecodeB64(new[]
    {
        // "mimikatz", "sekurlsa::", "lsadump::dcsync", "Invoke-Mimikatz", "procdump ", "sekurlsa:"
        "bWltaWthdHo=",
        "c2VrdXJsc2E6Og==",
        "bHNhZHVtcDo6ZGNzeW5j",
        "SW52b2tlLU1pbWlrYXR6",
        "cHJvY2R1bXAg",
        "c2VrdXJsc2E6"
    });

    // Neutral output codes aligned with SensitiveIndicators ordering; do not include the actual words
    private static readonly string[] SensitiveCodes = new[]
    {
        "sig:X1001", // mimikatz
        "sig:X1002", // sekurlsa::
        "sig:X1003", // lsadump::dcsync
        "sig:X1004", // Invoke-Mimikatz
        "sig:X1005", // procdump
        "sig:X1006", // sekurlsa:
    };
    internal static IReadOnlyList<string> AssessScript(string path, string? declaredExt, int budgetBytes)
    {
        var findings = new List<string>(8);
        try {
            if (!Settings.SecurityScanScripts) return findings;
            string text = ReadTextHead(path, budgetBytes);
            if (string.IsNullOrEmpty(text)) return findings;
            var lower = text.ToLowerInvariant();

            // Generic encoded payload indicators
            if (lower.Contains("frombase64string(") || lower.Contains("encodedcommand") || lower.Contains("-enc ")) findings.Add("ps:encoded");

            // PS expression/eval style
            if (ContainsAny(lower, new [] { "invoke-expression", "iex ", "iex\n", "iex\t" })) findings.Add("ps:iex");

            // PS web download
            if (ContainsAny(lower, new [] { "invoke-webrequest", "invoke-restmethod", "downloadstring(", "new-object system.net.webclient" })) findings.Add("ps:web-dl");

            // PS reflection / add-type
            if (ContainsAny(lower, new [] { "add-type", "reflection.assembly", "[reflection.assembly]::load" })) findings.Add("ps:reflection");

            // Python encoded exec
            if (ContainsAny(lower, new [] { "exec(" }) && (lower.Contains("base64.b64decode(") || lower.Contains("b64decode("))) findings.Add("py:exec-b64");

            // Python process launch
            if (ContainsAny(lower, new [] { "subprocess.popen(", "os.system(" })) findings.Add("py:exec");

            // Ruby eval/exec
            if (ContainsAny(lower, new [] { "eval(", "kernel.exec(", "open-uri" })) findings.Add("rb:eval");

            // Lua exec/loadstring
            if (ContainsAny(lower, new [] { "loadstring(", "os.execute(" })) findings.Add("lua:exec");

            // Batch/Generic: certutil decode
            if (ContainsAny(lower, new [] { "certutil -decode", "certutil.exe -decode" })) findings.Add("bat:certutil");

            // Windows scripting/JS: ActiveX and dangerous COM usage
            if (ContainsAny(lower, new [] { "wscript.shell", "activexobject", "adodb.stream" })) findings.Add("js:activex");

            // mshta usage
            if (ContainsAny(lower, new [] { "mshta ", "mshta.exe" })) findings.Add("js:mshta");

            // fromCharCode bursts (heuristic)
            int fcc = 0; int pos = 0; while (true) { int at = lower.IndexOf("fromcharcode(", pos, StringComparison.Ordinal); if (at < 0) break; fcc++; pos = at + 12; if (fcc > 20) break; }
            if (fcc > 20) findings.Add("js:fromcharcode");

            // Encoded high-signal names (decoded from B64 at runtime); neutral codes only
            for (int i = 0; i < SensitiveIndicators.Length && i < SensitiveCodes.Length; i++) {
                var token = SensitiveIndicators[i];
                if (string.IsNullOrEmpty(token)) continue;
                if (lower.IndexOf(token, StringComparison.OrdinalIgnoreCase) >= 0) findings.Add(SensitiveCodes[i]);
            }

            // If the script declared extension itself is risky, add a generic hint
            if (declaredExt is "ps1" or "psm1" or "psd1" or "sh" or "bash" or "zsh" or "bat" or "cmd" or "js" or "rb" or "py" or "lua")
                findings.Add("script:dangerous-kind");

            // Network paths and share mappings (UNC, net use, PSDrive)
            var uncShares = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var share in ExtractUncShares(text)) uncShares.Add(share);
            if (uncShares.Count > 0) findings.Add($"net:unc={uncShares.Count}");

            int mapCount = 0;
            if (lower.Contains("net use ")) mapCount += CountToken(lower, "net use ");
            if (lower.Contains("new-psdrive ")) mapCount += CountToken(lower, "new-psdrive ");
            if (mapCount > 0) findings.Add($"net:map={mapCount}");

            var hosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var h in ExtractHttpHosts(text)) hosts.Add(h);
            foreach (var share in uncShares) { var h = ExtractHostFromUnc(share); if (!string.IsNullOrEmpty(h)) hosts.Add(h!); }
            if (hosts.Count > 0)
            {
                findings.Add($"net:hosts={hosts.Count}");
                // Split into internal/external using HtmlAllowedDomains as an allowlist (suffix match)
                int internalCount = 0, externalCount = 0;
                foreach (var h in hosts)
                {
                    if (IsAllowedHost(h)) internalCount++; else externalCount++;
                }
                if (internalCount > 0) findings.Add($"net:hosts-int={internalCount}");
                if (externalCount > 0) findings.Add($"net:hosts-ext={externalCount}");
            }

            if (Settings.ResolveNetworkHostsInHeuristics && hosts.Count > 0)
            {
                int max = Math.Max(1, Settings.NetworkHostResolveMax);
                int ok = 0, fail = 0, pingOk = 0, pingFail = 0, taken = 0;
                foreach (var h in hosts)
                {
                    if (taken++ >= max) break;
                    bool resolved = TryResolveHost(h, Settings.NetworkHostResolveTimeoutMs);
                    if (resolved) ok++; else fail++;
                    if (Settings.PingHostsInHeuristics && resolved)
                    {
                        if (TryPingHost(h, Settings.NetworkHostResolveTimeoutMs)) pingOk++; else pingFail++;
                    }
                }
                if (ok > 0) findings.Add($"net:dns-ok={ok}");
                if (fail > 0) findings.Add($"net:dns-fail={fail}");
                if (Settings.PingHostsInHeuristics)
                {
                    if (pingOk > 0) findings.Add($"net:ping-ok={pingOk}");
                    if (pingFail > 0) findings.Add($"net:ping-fail={pingFail}");
                }
            }

            // Lightweight secrets (privacy-safe): only categories, never values
            if (Settings.SecretsScanEnabled)
            {
                if (CountPrivateKeyIndicators(text) > 0)
                    findings.Add("secret:privkey");

                if (CountJwtLikeIndicators(text) > 0) findings.Add("secret:jwt");

                if (CountKeyPatternIndicators(text) > 0) findings.Add("secret:keypattern");

                if (CountTokenFamilyIndicators(text) > 0) findings.Add("secret:token");
            }
        } catch { }
        return findings;
    }

    internal enum PsClassLevel { None = 0, Weak = 1, Strong = 2 }

    internal static (PsClassLevel level, int verbHits, int structHits) ClassifyPowerShellFromText(string text)
    {
        if (string.IsNullOrEmpty(text)) return (PsClassLevel.None, 0, 0);
        var lower = text.ToLowerInvariant();
        int structHits = 0;
        if (lower.Contains("#!/") && (lower.Contains("pwsh") || lower.Contains("powershell"))) structHits++;
        if (lower.Contains("[cmdletbinding")) structHits++;
        if (lower.Contains("param(") || lower.Contains("param (")) structHits++;
        if (lower.Contains("set-strictmode")) structHits++;
        if (lower.Contains("$psversiontable")) structHits++;
        if (lower.Contains("import-module")) structHits++;
        if (lower.Contains("function ")) structHits++;

        // Count common verb-prefixed cmdlets; require multiple distinct occurrences
        int verbHits = 0;
        string[] verbs = new [] { "get-", "set-", "invoke-", "new-", "remove-", "start-", "stop-", "enable-", "disable-", "update-", "add-" };
        int distinct = 0;
        foreach (var v in verbs)
        {
            if (lower.IndexOf(v, StringComparison.Ordinal) >= 0) { distinct++; verbHits += CountToken(lower, v); }
        }
        // Heuristic thresholds:
        //  - Strong: structural cues >=2 OR (>=1 structural cue AND >=3 distinct verbs)
        //  - Weak:   >=3 distinct verbs OR presence of many PowerShell sigils ($env:, $PSModulePath) without structure
        if (structHits >= 2 || (structHits >= 1 && distinct >= 3)) return (PsClassLevel.Strong, verbHits, structHits);
        if (distinct >= 3 || lower.Contains("$env:") || lower.Contains("$psmodulepath")) return (PsClassLevel.Weak, verbHits, structHits);
        return (PsClassLevel.None, verbHits, structHits);
    }

    internal static (bool isLog, int info, int warn, int error) ClassifyLogFromText(string text)
    {
        if (string.IsNullOrEmpty(text)) return (false, 0, 0, 0);
        int info=0, warn=0, error=0; int tsLines=0, total=0; bool eventViewer=false;
        using (var sr = new System.IO.StringReader(text))
        {
            string? line; int lines = 0;
            while (lines < 800 && (line = sr.ReadLine()) != null)
            {
                lines++; total++;
                var l = line.Trim(); if (l.Length == 0) continue;
                // Timestamp-like prefix: 2025-10-26 12:34:56,123 or 2025-10-26T12:34:56Z
                if (l.Length >= 10 && char.IsDigit(l[0]) && char.IsDigit(l[1]) && char.IsDigit(l[2]) && char.IsDigit(l[3]) && l[4]=='-' && char.IsDigit(l[5])) tsLines++;
                var u = l.ToUpperInvariant();
                if (u.Contains("INFO")) info++;
                if (u.Contains("WARN") || u.Contains("WARNING")) warn++;
                if (u.Contains("ERROR") || u.Contains("ERR ")) error++;
                if (!eventViewer && (u.Contains("LOG NAME:") && (u.Contains("EVENT ID:") || u.Contains("TASK CATEGORY:") || u.Contains("LEVEL:")))) eventViewer = true;
            }
        }
        // Basic log heuristic: at least a few timestamped lines or level tokens across multiple lines
        bool isLog = eventViewer || (tsLines >= 3 && total >= 10) || (info+warn+error >= 5);
        return (isLog, info, warn, error);
    }

    internal static IReadOnlyList<string> GetCmdlets(string path, int budgetBytes)
    {
        try
        {
            string text = ReadTextHead(path, budgetBytes);
            if (string.IsNullOrEmpty(text)) return Array.Empty<string>();
            const int MaxCmdlets = 12;
            // Common cmdlets/verbs of interest
            string[] probes = new [] {
                "start-process", "invoke-command", "invoke-webrequest", "invoke-restmethod", "invoke-expression",
                "start-bitstransfer", "new-psdrive", "set-itemproperty", "get-itemproperty",
                "copy-item", "remove-item", "add-type", "import-module", "set-executionpolicy",
                "register-scheduledtask", "new-scheduledtask", "schtasks", "set-alias",
                "get-content", "set-content", "add-content"
            };
            var ordered = new List<string>(MaxCmdlets);
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            void AddCmdlet(string value)
            {
                if (ordered.Count >= MaxCmdlets) return;
                if (string.IsNullOrWhiteSpace(value)) return;
                if (seen.Add(value)) ordered.Add(value);
            }
            foreach (var p in probes)
            {
                if (text.IndexOf(p, StringComparison.OrdinalIgnoreCase) >= 0) AddCmdlet(p);
            }
            if (ordered.Count >= MaxCmdlets) return ordered;

            TryAddScriptHints(text, AddCmdlet, () => ordered.Count < MaxCmdlets);
            if (ordered.Count >= MaxCmdlets) return ordered;

            int i = 0;
            while (i < text.Length && ordered.Count < MaxCmdlets)
            {
                while (i < text.Length && !IsCmdletStart(text[i])) i++;
                int start = i;
                while (i < text.Length && IsCmdletChar(text[i])) i++;
                int len = i - start;
                if (len >= 4)
                {
                    var token = text.Substring(start, len);
                    int dash = token.IndexOf('-');
                    if (dash > 0 && dash < token.Length - 1)
                    {
                        var verb = token.AsSpan(0, dash);
                        if (IsCommonPsVerb(verb))
                        {
                            AddCmdlet(token.ToLowerInvariant());
                        }
                    }
                }
                if (i == start) i++;
            }
            return ordered;
        }
        catch { return Array.Empty<string>(); }
    }

    private static bool IsCmdletStart(char c) => char.IsLetter(c);
    private static bool IsCmdletChar(char c) => char.IsLetterOrDigit(c) || c == '-';
    private static bool IsCommonPsVerb(ReadOnlySpan<char> verb)
    {
        if (verb.Length < 2 || verb.Length > 16) return false;
        return verb.Equals("get", StringComparison.OrdinalIgnoreCase) ||
               verb.Equals("set", StringComparison.OrdinalIgnoreCase) ||
               verb.Equals("new", StringComparison.OrdinalIgnoreCase) ||
               verb.Equals("add", StringComparison.OrdinalIgnoreCase) ||
               verb.Equals("remove", StringComparison.OrdinalIgnoreCase) ||
               verb.Equals("clear", StringComparison.OrdinalIgnoreCase) ||
               verb.Equals("copy", StringComparison.OrdinalIgnoreCase) ||
               verb.Equals("move", StringComparison.OrdinalIgnoreCase) ||
               verb.Equals("rename", StringComparison.OrdinalIgnoreCase) ||
               verb.Equals("test", StringComparison.OrdinalIgnoreCase) ||
               verb.Equals("invoke", StringComparison.OrdinalIgnoreCase) ||
               verb.Equals("start", StringComparison.OrdinalIgnoreCase) ||
               verb.Equals("stop", StringComparison.OrdinalIgnoreCase) ||
               verb.Equals("enable", StringComparison.OrdinalIgnoreCase) ||
               verb.Equals("disable", StringComparison.OrdinalIgnoreCase) ||
               verb.Equals("import", StringComparison.OrdinalIgnoreCase) ||
               verb.Equals("export", StringComparison.OrdinalIgnoreCase) ||
               verb.Equals("select", StringComparison.OrdinalIgnoreCase) ||
               verb.Equals("convert", StringComparison.OrdinalIgnoreCase) ||
               verb.Equals("write", StringComparison.OrdinalIgnoreCase) ||
               verb.Equals("read", StringComparison.OrdinalIgnoreCase) ||
               verb.Equals("update", StringComparison.OrdinalIgnoreCase) ||
               verb.Equals("connect", StringComparison.OrdinalIgnoreCase) ||
               verb.Equals("disconnect", StringComparison.OrdinalIgnoreCase) ||
               verb.Equals("format", StringComparison.OrdinalIgnoreCase) ||
               verb.Equals("register", StringComparison.OrdinalIgnoreCase) ||
               verb.Equals("unregister", StringComparison.OrdinalIgnoreCase) ||
               verb.Equals("resolve", StringComparison.OrdinalIgnoreCase) ||
               verb.Equals("find", StringComparison.OrdinalIgnoreCase) ||
               verb.Equals("build", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsAllowedHost(string host)
    {
        return IsHostAllowedByDomains(host, Settings.HtmlAllowedDomains);
    }

    internal static bool IsHostAllowedByDomains(string host, IEnumerable<string>? allowedDomains)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(host)) return false;
            if (allowedDomains == null) return false;
            var h = host.ToLowerInvariant();
            foreach (var d in allowedDomains)
            {
                if (string.IsNullOrWhiteSpace(d)) continue;
                var dom = d.Trim().ToLowerInvariant();
                if (dom.StartsWith("*.", StringComparison.Ordinal)) dom = dom.Substring(2);
                dom = dom.TrimStart('.');
                if (dom.Length == 0) continue;
                if (h.Equals(dom, StringComparison.Ordinal)) return true;
                if (h.Length > dom.Length && h.EndsWith(dom, StringComparison.Ordinal) && h[h.Length - dom.Length - 1] == '.') return true;
            }
        } catch { }
        return false;
    }

    internal static bool TryResolveHostForTest(string host, int timeoutMs) => TryResolveHost(host, timeoutMs);

    internal static IReadOnlyList<string> AssessTextGeneric(string path, string? declaredExt, int budgetBytes)
    {
        var findings = new List<string>(8);
        try {
            string text = ReadTextHead(path, budgetBytes);
            if (string.IsNullOrEmpty(text)) return findings;
            // Lowercasing is bounded by ReadTextHead (max 512 KB) to limit allocations.
            var lower = text.ToLowerInvariant();
            var logCues = HasLogCues(text);

            // IIS W3C logs
            if (LooksLikeIisW3cLog(lower))
                findings.Add("log:iis-w3c");

            // Windows DNS server log (text)
            if (LogHeuristics.LooksLikeDnsLog(lower))
                findings.Add("log:dns");
            // Windows Firewall log (pfirewall.log)
            if (LogHeuristics.LooksLikeFirewallLog(lower))
                findings.Add("log:firewall");
            // DHCP audit log
            if (LogHeuristics.LooksLikeDhcpLog(lower))
                findings.Add("log:dhcp");
            // Exchange message tracking
            if (LogHeuristics.LooksLikeExchangeMessageTrackingLog(lower))
                findings.Add("exchange:msgtrack");
            // Windows Defender textual logs
            if (LogHeuristics.LooksLikeDefenderTextLog(lower, logCues))
                findings.Add("defender:txt");
            // SQL Server ERRORLOG
            if (LogHeuristics.LooksLikeSqlErrorLog(lower, logCues))
                findings.Add("sql:errorlog");
            // NPS / RADIUS logs
            if (LogHeuristics.LooksLikeNpsRadiusLog(lower))
                findings.Add("nps:radius");
            // SQL Server Agent logs
            if (LogHeuristics.LooksLikeSqlAgentLog(lower, logCues))
                findings.Add("sql:agent");
            // Netlogon log
            if (LogHeuristics.LooksLikeNetlogonLog(lower, logCues))
                findings.Add("log:netlogon");
            // Event Viewer text export
            if (LogHeuristics.LooksLikeEventViewerTextExport(lower))
                findings.Add("event:txt");

            // Windows Event XML
            if (lower.Contains("<event ") && lower.Contains("http://schemas.microsoft.com/win/2004/08/events/event"))
                findings.Add("event-xml");
            // Sysmon
            if (lower.Contains("microsoft-windows-sysmon"))
                findings.Add("sysmon");

            // LDIF
            if (lower.Contains("ldif-version:") && lower.Contains("\ndn:"))
                findings.Add("ldif");

            // AAD sign-in logs (JSON)
            if (LooksLikeJsonWithKeys(lower, new [] {"userprincipalname", "appid" }) && (lower.Contains("resulttype") || lower.Contains("status")))
                findings.Add("aad:signin");
            // AAD audit logs (JSON)
            if (LooksLikeJsonWithKeys(lower, new [] {"operationname", "category" }) || lower.Contains("activitydisplayname"))
                findings.Add("aad:audit");
            // MDE/Defender logs (JSON)
            if (LooksLikeJsonWithKeys(lower, new [] {"deviceid", "computername" }) && (lower.Contains("alertid") || lower.Contains("threatname")))
                findings.Add("mde:alert");

            // Citrix ICA or Receiver configuration cues (neutral)
            if (declaredExt == "ica" || lower.Contains("[wfclient]") || lower.Contains("[applicationservers]"))
                findings.Add("citrix:ica");
            if (declaredExt == "cr" || lower.Contains("receiver") || lower.Contains("workspace"))
            {
                // Only add when XML-ish and likely configuration
                if (lower.Contains("<") && (lower.Contains("store") || lower.Contains("configuration")))
                    findings.Add("citrix:receiver-config");
            }

            // Secrets categories (privacy-safe; same as script path)
            if (Settings.SecretsScanEnabled)
            {
                if (CountPrivateKeyIndicators(text) > 0)
                    findings.Add("secret:privkey");
                if (CountJwtLikeIndicators(text) > 0) findings.Add("secret:jwt");
                if (CountKeyPatternIndicators(text) > 0) findings.Add("secret:keypattern");
                if (CountTokenFamilyIndicators(text) > 0) findings.Add("secret:token");
            }
        } catch { }
        return findings;
    }

    private static bool LooksLikeIisW3cLog(string lower)
    {
        if (!lower.Contains("#fields:")) return false;
        if (!lower.Contains("#software: microsoft internet information services")) return false;
        return lower.Contains("#version:") || lower.Contains("#date:");
    }

    private static bool HasLogCues(string text)
    {
        const int MaxBytesToScan = 4096; // cap to first ~4 KB of text
        var span = text.AsSpan(0, Math.Min(text.Length, MaxBytesToScan));
        int lines = 0;
        int i = 0;
        while (i < span.Length && lines < 4)
        {
            int start = i;
            int nl = span.Slice(i).IndexOf('\n');
            int end = nl >= 0 ? i + nl : span.Length;
            var line = span.Slice(start, Math.Max(0, end - start));
            if (LooksLikeTimestamp(line) || StartsWithLevelToken(line)) return true;
            i = end + 1;
            lines++;
        }
        return false;
    }

    private static bool LooksLikeTimestamp(ReadOnlySpan<char> line)
    {
        if (line.Length < 10) return false;
        bool y = char.IsDigit(line[0]) && char.IsDigit(line[1]) && char.IsDigit(line[2]) && char.IsDigit(line[3]);
        bool sep1 = line[4] == '-' || line[4] == '/';
        bool m = char.IsDigit(line[5]) && char.IsDigit(line[6]);
        bool sep2 = line[7] == '-' || line[7] == '/';
        bool d = char.IsDigit(line[8]) && char.IsDigit(line[9]);
        return y && sep1 && m && sep2 && d;
    }

    private static bool StartsWithLevelToken(ReadOnlySpan<char> line)
    {
        return StartsWithToken(line, "INFO") || StartsWithToken(line, "WARN") || StartsWithToken(line, "ERROR") || StartsWithToken(line, "DEBUG") || StartsWithToken(line, "TRACE") || StartsWithToken(line, "FATAL") || StartsWithToken(line, "CRITICAL") || StartsWithToken(line, "ALERT") || StartsWithToken(line, "[INFO]") || StartsWithToken(line, "[WARN]") || StartsWithToken(line, "[ERROR]") || StartsWithToken(line, "[DEBUG]") || StartsWithToken(line, "[CRITICAL]") || StartsWithToken(line, "[ALERT]");
    }

    private static bool StartsWithToken(ReadOnlySpan<char> line, string token)
    {
        if (line.Length < token.Length) return false;
        for (int i = 0; i < token.Length; i++)
        {
            if (char.ToUpperInvariant(line[i]) != char.ToUpperInvariant(token[i])) return false;
        }
        return true;
    }

    internal static SecretsSummary CountSecrets(string path, int budgetBytes)
    {
        var s = new SecretsSummary();
        try {
            if (!Settings.SecretsScanEnabled) return s;
            string text = ReadTextHead(path, budgetBytes);
            if (string.IsNullOrEmpty(text)) return s;
            s.PrivateKeyCount = CountPrivateKeyIndicators(text);
            s.JwtLikeCount = CountJwtLikeIndicators(text);
            s.KeyPatternCount = CountKeyPatternIndicators(text);
            s.TokenFamilyCount = CountTokenFamilyIndicators(text);
        } catch { }
        return s;
    }

    private static bool ContainsAny(string hay, IEnumerable<string> needles) {
        foreach (var n in needles) if (hay.IndexOf(n, StringComparison.Ordinal) >= 0) return true;
        return false;
    }

    private static bool ContainsAnyIgnoreCase(string hay, IEnumerable<string> needles) {
        foreach (var n in needles) if (hay.IndexOf(n, StringComparison.OrdinalIgnoreCase) >= 0) return true;
        return false;
    }

    private static string ReadTextHead(string path, int budget)
    {
        try {
            using var fs = File.OpenRead(path);
            int cap = Math.Max(8 * 1024, Math.Min(budget, 512 * 1024));
            var buf = new byte[Math.Min(cap, (int)Math.Min(fs.Length, cap))];
            int n = fs.Read(buf, 0, buf.Length);
            if (n <= 0) return string.Empty;
            if (n >= 3 && buf[0] == 0xEF && buf[1] == 0xBB && buf[2] == 0xBF)
                return System.Text.Encoding.UTF8.GetString(buf, 3, n - 3);
            if (n >= 4 && buf[0] == 0xFF && buf[1] == 0xFE && buf[2] == 0x00 && buf[3] == 0x00)
                return new System.Text.UTF32Encoding(false, true, true).GetString(buf, 4, n - 4);
            if (n >= 4 && buf[0] == 0x00 && buf[1] == 0x00 && buf[2] == 0xFE && buf[3] == 0xFF)
                return new System.Text.UTF32Encoding(true, true, true).GetString(buf, 4, n - 4);
            if (n >= 2 && buf[0] == 0xFF && buf[1] == 0xFE)
                return System.Text.Encoding.Unicode.GetString(buf, 2, n - 2);
            if (n >= 2 && buf[0] == 0xFE && buf[1] == 0xFF)
                return System.Text.Encoding.BigEndianUnicode.GetString(buf, 2, n - 2);
            return System.Text.Encoding.UTF8.GetString(buf, 0, n);
        } catch { return string.Empty; }
    }

    private static IEnumerable<string> ExtractUncShares(string text)
    {
        try
        {
            var list = new List<string>();
            var span = text.AsSpan();
            int i = 0; while (i + 3 < span.Length)
            {
                if (span[i] == '\\' && span[i+1] == '\\')
                {
                    int start = i; i += 2; int s = i; while (i < span.Length && IsHostChar(span[i])) i++; if (i <= s || i >= span.Length || span[i] != '\\') { i++; continue; }
                    string server = span.Slice(s, i - s).ToString(); i++;
                    int shStart = i; while (i < span.Length && IsShareChar(span[i])) i++; if (i > shStart)
                    {
                        string share = span.Slice(shStart, i - shStart).ToString(); list.Add($"\\\\{server}\\{share}");
                    }
                }
                else i++;
            }
            return list;
        } catch { return Array.Empty<string>(); }
    }
    private static IEnumerable<string> ExtractHttpHosts(string text)
    {
        var hosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            int i = 0; var s = text;
            while (i < s.Length)
            {
                int at = s.IndexOf("http", i, StringComparison.OrdinalIgnoreCase); if (at < 0) break;
                int end = at; while (end < s.Length && !char.IsWhiteSpace(s[end]) && s[end] != '"' && s[end] != '\'' && s[end] != ')' && s[end] != '<' && s[end] != '>') end++;
                var cand = s.Substring(at, end - at);
                if (Uri.TryCreate(cand, UriKind.Absolute, out var u) && (u.Scheme == Uri.UriSchemeHttp || u.Scheme == Uri.UriSchemeHttps) && !string.IsNullOrEmpty(u.Host)) hosts.Add(u.Host);
                i = end + 1;
            }
        } catch { }
        return hosts;
    }
    private static string? ExtractHostFromUnc(string unc)
    {
        try
        {
            var p = unc.Replace('/', '\\');
            if (p.StartsWith("\\\\"))
            {
                var parts = p.Split(new[]{'\\'}, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length > 0) return parts[0];
            }
        } catch { }
        return null;
    }
    private static bool IsHostChar(char c) => char.IsLetterOrDigit(c) || c == '.' || c == '-' || c == '_';
    private static bool IsShareChar(char c) => IsHostChar(c) || c == '$';
    private static int CountToken(string hay, string token) { int c = 0, idx = 0; while ((idx = hay.IndexOf(token, idx, StringComparison.Ordinal)) >= 0) { c++; idx += token.Length; if (c > 1000) break; } return c; }
    private static bool TryResolveHost(string host, int timeoutMs)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(host)) return false;
            timeoutMs = Math.Max(1, timeoutMs);
#if NET8_0_OR_GREATER
            using var cts = new System.Threading.CancellationTokenSource(timeoutMs);
            var addresses = System.Net.Dns.GetHostAddressesAsync(host, cts.Token).GetAwaiter().GetResult();
            return addresses is { Length: > 0 };
#else
            var ar = System.Net.Dns.BeginGetHostEntry(host, null, null);
            var waitHandle = ar.AsyncWaitHandle;
            try
            {
                if (!waitHandle.WaitOne(timeoutMs)) return false;
            }
            finally
            {
                waitHandle.Close();
            }

            var entry = System.Net.Dns.EndGetHostEntry(ar);
            return entry?.AddressList is { Length: > 0 };
#endif
        }
        catch
        {
            return false;
        }
    }
    private static bool TryPingHost(string host, int timeoutMs)
    { try { using var ping = new System.Net.NetworkInformation.Ping(); var reply = ping.Send(host, timeoutMs); return reply?.Status == System.Net.NetworkInformation.IPStatus.Success; } catch { return false; } }

    private static string[] DecodeB64(string[] arr)
    {
        var outArr = new string[arr.Length];
        for (int i = 0; i < arr.Length; i++)
        {
            try {
                var bytes = Convert.FromBase64String(arr[i]);
                outArr[i] = System.Text.Encoding.ASCII.GetString(bytes).ToLowerInvariant();
            } catch { outArr[i] = string.Empty; }
        }
        return outArr;
    }

    private static readonly string[] PrivateKeyMarkers = new[]
    {
        "-----begin rsa private key-----",
        "-----begin private key-----",
        "-----begin dsa private key-----",
        "-----begin openssh private key-----",
        "-----begin encrypted private key-----",
        "-----begin ec private key-----"
    };

    private static int CountPrivateKeyIndicators(string text)
    {
        int hits = 0;
        try
        {
            for (int i = 0; i < PrivateKeyMarkers.Length; i++)
            {
                hits += CountTokenIgnoreCase(text, PrivateKeyMarkers[i], maxMatches: 32 - hits);
                if (hits >= 32) return 32;
            }
        }
        catch { }
        return hits;
    }

    private static int CountJwtLikeIndicators(string text)
    {
        const int MaxMatches = 16;
        try
        {
            int max = Math.Min(text.Length, 16 * 1024);
            int count = 0;
            int i = 0;
            while (i < max && count < MaxMatches)
            {
                while (i < max && !IsJwtTokenChar(text[i])) i++;
                if (i >= max) break;
                int start = i;
                while (i < max && IsJwtTokenChar(text[i])) i++;
                int end = i;
                int len = end - start;
                if (len < 24) continue;

                var token = text.Substring(start, len);
                if (LooksLikeJwtToken(token)) count++;
            }
            return count;
        }
        catch { return 0; }
    }

    private static bool LooksLikeJwtToken(string token)
    {
        if (string.IsNullOrWhiteSpace(token)) return false;
        int d1 = token.IndexOf('.');
        if (d1 <= 0) return false;
        int d2 = token.IndexOf('.', d1 + 1);
        if (d2 <= d1 + 1) return false;
        if (token.IndexOf('.', d2 + 1) >= 0) return false;

        var h = token.Substring(0, d1);
        var p = token.Substring(d1 + 1, d2 - d1 - 1);
        var s = token.Substring(d2 + 1);

        if (h.Length < 8 || p.Length < 8 || s.Length < 6) return false;
        if (!TryDecodeBase64Url(h, out var hb) || !TryDecodeBase64Url(p, out var pb)) return false;
        if (!LooksLikeJsonObject(hb, requireJwtHeaderKeys: true)) return false;
        if (!LooksLikeJsonObject(pb, requireJwtHeaderKeys: false)) return false;
        return true;
    }

    private static bool TryDecodeBase64Url(string segment, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        try
        {
            if (string.IsNullOrEmpty(segment) || segment.Length > 4096) return false;
            for (int i = 0; i < segment.Length; i++)
                if (!IsJwtTokenChar(segment[i])) return false;

            string normalized = segment.Replace('-', '+').Replace('_', '/');
            int mod = normalized.Length % 4;
            if (mod == 1) return false;
            if (mod != 0) normalized = normalized.PadRight(normalized.Length + (4 - mod), '=');
            bytes = Convert.FromBase64String(normalized);
            return bytes.Length > 1 && bytes.Length <= 4096;
        }
        catch { bytes = Array.Empty<byte>(); return false; }
    }

    private static bool LooksLikeJsonObject(byte[] utf8, bool requireJwtHeaderKeys)
    {
        try
        {
            if (utf8 == null || utf8.Length < 2 || utf8.Length > 4096) return false;
            var json = System.Text.Encoding.UTF8.GetString(utf8).Trim();
            if (json.Length < 2 || json[0] != '{' || json[json.Length - 1] != '}') return false;
            if (json.IndexOf(':') < 0 || json.IndexOf('"') < 0) return false;

            var lower = json.ToLowerInvariant();
            if (requireJwtHeaderKeys)
            {
                return lower.Contains("\"alg\"") || lower.Contains("\"typ\"") || lower.Contains("\"kid\"") || lower.Contains("\"enc\"");
            }

            if (lower.Contains("\"sub\"") || lower.Contains("\"iss\"") || lower.Contains("\"aud\"") || lower.Contains("\"exp\"") ||
                lower.Contains("\"iat\"") || lower.Contains("\"nbf\"") || lower.Contains("\"jti\"") || lower.Contains("\"scope\""))
                return true;

            return lower.Contains("\":");
        }
        catch { return false; }
    }

    private static int CountKeyPatternIndicators(string text)
    {
        int count = 0;
        try
        {
            var t = text;
            int max = Math.Min(t.Length, 4096);
            for (int i = 0; i < max - 6 && count < 32; i++)
            {
                if ((t[i] == 'k' || t[i] == 'K') && SpanEqualsIgnoreCase(t, i, "key=", max))
                {
                    if (HasLongTokenAfter(t, i + 4)) count++;
                }
                else if ((t[i] == 's' || t[i] == 'S') && SpanEqualsIgnoreCase(t, i, "secret=", max))
                {
                    if (HasLongTokenAfter(t, i + 7)) count++;
                }
                else if ((t[i] == 'p' || t[i] == 'P') && SpanEqualsIgnoreCase(t, i, "password=", max))
                {
                    if (HasLongTokenAfter(t, i + 9)) count++;
                }
                else if ((t[i] == 'p' || t[i] == 'P') && SpanEqualsIgnoreCase(t, i, "pwd=", max))
                {
                    if (HasLongTokenAfter(t, i + 4)) count++;
                }
                else if ((t[i] == 'c' || t[i] == 'C') && SpanEqualsIgnoreCase(t, i, "connectionstring=", max))
                {
                    int window = Math.Min(max, i + 256);
                    var slice = t.Substring(i, window - i);
                    if (slice.IndexOf("password=", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        slice.IndexOf("pwd=", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        count++;
                    }
                }
            }
        }
        catch { }
        return count;
    }

    private static bool SpanEqualsIgnoreCase(string text, int start, string token, int max)
    {
        if (start < 0 || start + token.Length > max || start + token.Length > text.Length) return false;
        return text.AsSpan(start, token.Length).ToString().Equals(token, StringComparison.OrdinalIgnoreCase);
    }

    private static bool HasLongTokenAfter(string t, int start)
    {
        int i = start;
        while (i < t.Length && (t[i] == ' ' || t[i] == '"' || t[i] == '\'')) i++;
        int len = 0;
        int max = Math.Min(t.Length, start + 256);
        for (; i < max; i++)
        {
            char c = t[i];
            if (char.IsLetterOrDigit(c) || c == '+' || c == '/' || c == '=' || c == '-' || c == '_') len++;
            else break;
        }
        return len >= 20;
    }

    private enum TokenFamilyKind
    {
        Unknown = 0,
        GitHub = 1,
        GitLab = 2,
        AwsAccessKeyId = 3,
        Slack = 4,
        StripeLive = 5
    }

    private static int CountTokenFamilyIndicators(string text)
    {
        const int MaxMatches = 24;
        try
        {
            int max = Math.Min(text.Length, 24 * 1024);
            if (max <= 0) return 0;
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            // Prefix-driven probing keeps scan cost low and avoids classifying generic words.
            ProbePrefix(text, max, "github_pat_", StringComparison.OrdinalIgnoreCase, seen, MaxMatches);
            ProbePrefix(text, max, "ghp_", StringComparison.OrdinalIgnoreCase, seen, MaxMatches);
            ProbePrefix(text, max, "gho_", StringComparison.OrdinalIgnoreCase, seen, MaxMatches);
            ProbePrefix(text, max, "ghu_", StringComparison.OrdinalIgnoreCase, seen, MaxMatches);
            ProbePrefix(text, max, "ghs_", StringComparison.OrdinalIgnoreCase, seen, MaxMatches);
            ProbePrefix(text, max, "ghr_", StringComparison.OrdinalIgnoreCase, seen, MaxMatches);
            ProbePrefix(text, max, "glpat-", StringComparison.OrdinalIgnoreCase, seen, MaxMatches);
            ProbePrefix(text, max, "AKIA", StringComparison.Ordinal, seen, MaxMatches);
            ProbePrefix(text, max, "ASIA", StringComparison.Ordinal, seen, MaxMatches);
            ProbePrefix(text, max, "xoxb-", StringComparison.OrdinalIgnoreCase, seen, MaxMatches);
            ProbePrefix(text, max, "xoxp-", StringComparison.OrdinalIgnoreCase, seen, MaxMatches);
            ProbePrefix(text, max, "xoxa-", StringComparison.OrdinalIgnoreCase, seen, MaxMatches);
            ProbePrefix(text, max, "xoxs-", StringComparison.OrdinalIgnoreCase, seen, MaxMatches);
            ProbePrefix(text, max, "xoxr-", StringComparison.OrdinalIgnoreCase, seen, MaxMatches);
            ProbePrefix(text, max, "sk_live_", StringComparison.OrdinalIgnoreCase, seen, MaxMatches);
            ProbePrefix(text, max, "rk_live_", StringComparison.OrdinalIgnoreCase, seen, MaxMatches);

            return seen.Count;
        }
        catch { return 0; }
    }

    private static void ProbePrefix(
        string text,
        int max,
        string prefix,
        StringComparison comparison,
        HashSet<string> seen,
        int maxMatches)
    {
        if (string.IsNullOrEmpty(text) || string.IsNullOrEmpty(prefix) || max <= 0) return;
        int i = 0;
        while (i < max && seen.Count < maxMatches)
        {
            int at = text.IndexOf(prefix, i, comparison);
            if (at < 0 || at >= max) break;

            // Require token boundary before prefix to avoid matching mid-word.
            if (at > 0 && IsTokenBodyChar(text[at - 1]))
            {
                i = at + 1;
                continue;
            }

            int end = at + prefix.Length;
            while (end < max && IsTokenBodyChar(text[end])) end++;

            int len = end - at;
            if (len >= 12)
            {
                var token = TrimTokenNoise(text.Substring(at, len));
                if (token.Length >= 12 && token.Length <= 200 && TryGetTokenFamily(token, out var family))
                {
                    if (!LooksLikePlaceholderToken(token) && (!RequiresContext(family) || HasSecretLikeContext(text, at, end, family)))
                        seen.Add(token);
                }
            }

            i = at + prefix.Length;
        }
    }

    private static string TrimTokenNoise(string token)
        => token.Trim(' ', '\t', '\r', '\n', '"', '\'', '`', '(', ')', '[', ']', '{', '}', '<', '>', ',', ';', '.');

    private static bool TryGetTokenFamily(string token, out TokenFamilyKind kind)
    {
        if (LooksLikeGitHubToken(token)) { kind = TokenFamilyKind.GitHub; return true; }
        if (LooksLikeGitLabToken(token)) { kind = TokenFamilyKind.GitLab; return true; }
        if (LooksLikeAwsAccessKeyId(token)) { kind = TokenFamilyKind.AwsAccessKeyId; return true; }
        if (LooksLikeSlackToken(token)) { kind = TokenFamilyKind.Slack; return true; }
        if (LooksLikeStripeLiveToken(token)) { kind = TokenFamilyKind.StripeLive; return true; }
        kind = TokenFamilyKind.Unknown;
        return false;
    }

    private static bool LooksLikeGitHubToken(string token)
    {
        if (token.StartsWith("github_pat_", StringComparison.OrdinalIgnoreCase))
        {
            int p = "github_pat_".Length;
            int bodyLen = token.Length - p;
            return bodyLen >= 50 && bodyLen <= 180 && IsAlphaNumOrUnderscore(token, p);
        }

        string[] classic = new[] { "ghp_", "gho_", "ghu_", "ghs_", "ghr_" };
        for (int i = 0; i < classic.Length; i++)
        {
            var prefix = classic[i];
            if (!token.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) continue;
            int p = prefix.Length;
            int bodyLen = token.Length - p;
            return bodyLen == 36 && IsAlphaNum(token, p);
        }
        return false;
    }

    private static bool LooksLikeGitLabToken(string token)
    {
        if (!token.StartsWith("glpat-", StringComparison.OrdinalIgnoreCase)) return false;
        int p = "glpat-".Length;
        int bodyLen = token.Length - p;
        return bodyLen >= 20 && bodyLen <= 160 && IsAlphaNumOrUnderscoreDash(token, p);
    }

    private static bool LooksLikeAwsAccessKeyId(string token)
    {
        if (token.Length != 20) return false;
        if (!(token.StartsWith("AKIA", StringComparison.Ordinal) || token.StartsWith("ASIA", StringComparison.Ordinal))) return false;
        return IsUpperAlphaNum(token, 0);
    }

    private static bool LooksLikeSlackToken(string token)
    {
        var parts = token.Split(new[] { '-' }, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 4 || parts.Length > 6) return false;
        if (!(parts[0].Equals("xoxb", StringComparison.OrdinalIgnoreCase) ||
              parts[0].Equals("xoxp", StringComparison.OrdinalIgnoreCase) ||
              parts[0].Equals("xoxa", StringComparison.OrdinalIgnoreCase) ||
              parts[0].Equals("xoxs", StringComparison.OrdinalIgnoreCase) ||
              parts[0].Equals("xoxr", StringComparison.OrdinalIgnoreCase))) return false;

        int numericSegments = 0;
        int longAlphaNumSegments = 0;
        for (int i = 1; i < parts.Length; i++)
        {
            var seg = parts[i];
            if (seg.Length == 0) return false;
            if (IsDigits(seg))
            {
                if (seg.Length >= 6 || (parts[0].Equals("xoxa", StringComparison.OrdinalIgnoreCase) && seg == "2"))
                    numericSegments++;
            }
            else if (seg.Length >= 12 && IsAlphaNum(seg, 0))
            {
                longAlphaNumSegments++;
            }
            else
            {
                return false;
            }
        }
        return numericSegments >= 1 && longAlphaNumSegments >= 1;
    }

    private static bool LooksLikeStripeLiveToken(string token)
    {
        if (token.StartsWith("sk_live_", StringComparison.OrdinalIgnoreCase))
        {
            int p = "sk_live_".Length;
            int bodyLen = token.Length - p;
            return bodyLen >= 16 && bodyLen <= 128 && IsAlphaNum(token, p);
        }
        if (token.StartsWith("rk_live_", StringComparison.OrdinalIgnoreCase))
        {
            int p = "rk_live_".Length;
            int bodyLen = token.Length - p;
            return bodyLen >= 16 && bodyLen <= 128 && IsAlphaNum(token, p);
        }
        return false;
    }

    private static bool RequiresContext(TokenFamilyKind family)
        => family == TokenFamilyKind.AwsAccessKeyId;

    private static bool LooksLikePlaceholderToken(string token)
    {
        if (string.IsNullOrWhiteSpace(token)) return true;
        var lower = token.ToLowerInvariant();
        return lower.IndexOf("example", StringComparison.Ordinal) >= 0 ||
               lower.IndexOf("sample", StringComparison.Ordinal) >= 0 ||
               lower.IndexOf("placeholder", StringComparison.Ordinal) >= 0 ||
               lower.IndexOf("dummy", StringComparison.Ordinal) >= 0 ||
               lower.IndexOf("changeme", StringComparison.Ordinal) >= 0 ||
               lower.IndexOf("notreal", StringComparison.Ordinal) >= 0 ||
               lower.IndexOf("not_real", StringComparison.Ordinal) >= 0 ||
               lower.IndexOf("your_", StringComparison.Ordinal) >= 0;
    }

    private static bool HasSecretLikeContext(string text, int start, int end, TokenFamilyKind family)
    {
        try
        {
            if (string.IsNullOrEmpty(text)) return false;
            int from = Math.Max(0, start - 64);
            int to = Math.Min(text.Length, end + 64);
            if (to <= from) return false;
            var window = text.Substring(from, to - from);

            if (ContainsAnyIgnoreCase(window, new[]
            {
                "token", "secret", "api_key", "apikey", "access_key", "accesskey",
                "authorization", "bearer", "credential", "key=", "token=", "secret=", "password="
            }))
            {
                return true;
            }

            if (family == TokenFamilyKind.AwsAccessKeyId)
            {
                return ContainsAnyIgnoreCase(window, new[] { "aws", "iam", "sts", "x-amz", "accesskeyid" });
            }
        }
        catch { }
        return false;
    }

    private static bool IsDigits(string s)
    {
        if (string.IsNullOrEmpty(s)) return false;
        for (int i = 0; i < s.Length; i++) if (s[i] < '0' || s[i] > '9') return false;
        return true;
    }

    private static bool IsUpperAlphaNum(string s, int start)
    {
        if (string.IsNullOrEmpty(s) || start < 0 || start >= s.Length) return false;
        for (int i = start; i < s.Length; i++)
        {
            char c = s[i];
            bool ok = (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
            if (!ok) return false;
        }
        return true;
    }

    private static bool IsAlphaNum(string s, int start)
    {
        if (string.IsNullOrEmpty(s) || start < 0 || start >= s.Length) return false;
        for (int i = start; i < s.Length; i++)
        {
            char c = s[i];
            bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
            if (!ok) return false;
        }
        return true;
    }

    private static bool IsAlphaNumOrUnderscore(string s, int start)
    {
        if (string.IsNullOrEmpty(s) || start < 0 || start >= s.Length) return false;
        for (int i = start; i < s.Length; i++)
        {
            char c = s[i];
            bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
            if (!ok) return false;
        }
        return true;
    }

    private static bool IsAlphaNumOrUnderscoreDash(string s, int start)
    {
        if (string.IsNullOrEmpty(s) || start < 0 || start >= s.Length) return false;
        for (int i = start; i < s.Length; i++)
        {
            char c = s[i];
            bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-';
            if (!ok) return false;
        }
        return true;
    }

    private static bool IsTokenHeadChar(char c) => (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');

    private static bool IsTokenBodyChar(char c) => IsTokenHeadChar(c) || c == '_' || c == '-';

    private static bool IsJwtTokenChar(char c)
        => (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.';

    private static int CountTokenIgnoreCase(string hay, string token, int maxMatches)
    {
        if (string.IsNullOrEmpty(hay) || string.IsNullOrEmpty(token) || maxMatches <= 0) return 0;
        int c = 0;
        int idx = 0;
        while ((idx = hay.IndexOf(token, idx, StringComparison.OrdinalIgnoreCase)) >= 0)
        {
            c++;
            idx += token.Length;
            if (c >= maxMatches) break;
        }
        return c;
    }

    private static bool LooksLikeJsonWithKeys(string lower, IEnumerable<string> keys)
    {
        // Cheap test: looks JSON-ish and contains all keys
        if (!(lower.Contains("{") && lower.Contains("}"))) return false;
        foreach (var k in keys) if (!lower.Contains(k)) return false; return true;
    }
}
