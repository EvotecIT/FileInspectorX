namespace FileInspectorX;

/// <summary>
/// Lightweight, dependency-free content heuristics used to emit neutral security signals and detect simple secret categories.
/// </summary>
internal static partial class SecurityHeuristics
{
    // ACTIVE (default): Base64-encoded indicators decoded at runtime to avoid static signatures
    private static readonly string[] SensitiveIndicators = DecodeB64(new[]
    {
        // Neutral indicator set decoded from Base64 at runtime; keep raw trigger text out of source.
        "bWltaWthdHo=",
        "c2VrdXJsc2E6Og==",
        "bHNhZHVtcDo6ZGNzeW5j",
        "SW52b2tlLU1pbWlrYXR6",
        "cHJvY2R1bXAg",
        "c2VrdXJsc2E6"
    });

    // Neutral output codes aligned with SensitiveIndicators ordering.
    private static readonly string[] SensitiveCodes = new[]
    {
        "sig:X1001", // credential-dumping family A
        "sig:X1002", // credential-dumping family B
        "sig:X1003", // directory-replication dump family
        "sig:X1004", // reflected credential-dumping family
        "sig:X1005", // dump-utility family
        "sig:X1006", // credential-dumping family C
    };
    internal static IReadOnlyList<string> AssessScript(string path, string? declaredExt, int budgetBytes)
    {
        try
        {
            string text = ReadTextHead(path, budgetBytes);
            return AssessScriptFromText(text, declaredExt);
        }
        catch { return Array.Empty<string>(); }
    }

    internal static IReadOnlyList<string> AssessScriptFromText(string? text, string? declaredExt, bool includeSecrets = true)
    {
        var findings = new List<string>(8);
        try {
            if (!Settings.SecurityScanScripts) return findings;
            if (string.IsNullOrEmpty(text)) return findings;
            var source = text ?? string.Empty;
            var lower = source.ToLowerInvariant();

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
            foreach (var share in ExtractUncShares(source)) uncShares.Add(share);
            if (uncShares.Count > 0) findings.Add($"net:unc={uncShares.Count}");

            int mapCount = 0;
            if (lower.Contains("net use ")) mapCount += CountToken(lower, "net use ");
            if (lower.Contains("new-psdrive ")) mapCount += CountToken(lower, "new-psdrive ");
            if (mapCount > 0) findings.Add($"net:map={mapCount}");

            var hosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var h in ExtractHttpHosts(source)) hosts.Add(h);
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
            if (includeSecrets && Settings.SecretsScanEnabled)
            {
                var secrets = CountSecretsFromText(source);
                foreach (var code in GetSecretFindingCodes(secrets))
                {
                    if (!findings.Contains(code, StringComparer.OrdinalIgnoreCase))
                        findings.Add(code);
                }
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
            return GetCmdletsFromText(text);
        }
        catch { return Array.Empty<string>(); }
    }

    internal static IReadOnlyList<string> GetCmdletsFromText(string? text)
    {
        try
        {
            if (string.IsNullOrEmpty(text)) return Array.Empty<string>();
            var source = text ?? string.Empty;
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
                if (source.IndexOf(p, StringComparison.OrdinalIgnoreCase) >= 0) AddCmdlet(p);
            }
            if (ordered.Count >= MaxCmdlets) return ordered;

            TryAddScriptHints(source, AddCmdlet, () => ordered.Count < MaxCmdlets);
            if (ordered.Count >= MaxCmdlets) return ordered;

            int i = 0;
            while (i < source.Length && ordered.Count < MaxCmdlets)
            {
                while (i < source.Length && !IsCmdletStart(source[i])) i++;
                int start = i;
                while (i < source.Length && IsCmdletChar(source[i])) i++;
                int len = i - start;
                if (len >= 4)
                {
                    var token = source.Substring(start, len);
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
        try
        {
            string text = ReadTextHead(path, budgetBytes);
            return AssessTextGenericFromText(text, declaredExt);
        }
        catch { return Array.Empty<string>(); }
    }

    internal static IReadOnlyList<string> AssessTextGenericFromText(string? text, string? declaredExt, bool includeSecrets = true)
    {
        var findings = new List<string>(8);
        try {
            if (string.IsNullOrEmpty(text)) return findings;
            var source = text ?? string.Empty;
            // Lowercasing is bounded by ReadTextHead (max 512 KB) to limit allocations.
            var lower = source.ToLowerInvariant();
            var logCues = HasLogCues(source);

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
            if (includeSecrets && Settings.SecretsScanEnabled)
            {
                var secrets = CountSecretsFromText(source);
                foreach (var code in GetSecretFindingCodes(secrets))
                {
                    if (!findings.Contains(code, StringComparer.OrdinalIgnoreCase))
                        findings.Add(code);
                }
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
        try
        {
            string text = ReadTextHead(path, budgetBytes);
            return CountSecretsFromText(text);
        }
        catch { return new SecretsSummary(); }
    }

    internal static SecretsSummary CountSecretsFromText(string? text)
    {
        var s = new SecretsSummary();
        try {
            if (!Settings.SecretsScanEnabled) return s;
            if (string.IsNullOrEmpty(text)) return s;
            var source = text ?? string.Empty;
            s.PrivateKeyCount = CountPrivateKeyIndicators(source);
            s.JwtLikeCount = CountJwtLikeIndicators(source);
            s.KeyPatternCount = CountKeyPatternIndicators(source);
            var tokenFamilies = CountTokenFamilyIndicatorsDetailed(source);
            s.TokenFamilyCount = tokenFamilies.TotalCount;
            s.GitHubTokenCount = tokenFamilies.GitHubCount;
            s.GitLabTokenCount = tokenFamilies.GitLabCount;
            s.AwsAccessKeyIdCount = tokenFamilies.AwsAccessKeyIdCount;
            s.SlackTokenCount = tokenFamilies.SlackCount;
            s.StripeLiveKeyCount = tokenFamilies.StripeLiveCount;
            s.GcpApiKeyCount = tokenFamilies.GcpApiKeyCount;
            s.NpmTokenCount = tokenFamilies.NpmTokenCount;
            s.AzureSasTokenCount = tokenFamilies.AzureSasCount;
            s.Findings = BuildSecretFindingDetails(source, s, tokenFamilies);
        } catch { }
        return s;
    }

    internal static IReadOnlyList<string> GetSecretFindingCodes(SecretsSummary? secrets)
    {
        if (secrets == null) return Array.Empty<string>();
        var codes = new List<string>(12);
        if (secrets.PrivateKeyCount > 0) codes.Add("secret:privkey");
        if (secrets.JwtLikeCount > 0) codes.Add("secret:jwt");
        if (secrets.KeyPatternCount > 0) codes.Add("secret:keypattern");
        if (secrets.TokenFamilyCount > 0) codes.Add("secret:token");
        if (secrets.GitHubTokenCount > 0) codes.Add("secret:token:github");
        if (secrets.GitLabTokenCount > 0) codes.Add("secret:token:gitlab");
        if (secrets.AwsAccessKeyIdCount > 0) codes.Add("secret:token:aws-akid");
        if (secrets.SlackTokenCount > 0) codes.Add("secret:token:slack");
        if (secrets.StripeLiveKeyCount > 0) codes.Add("secret:token:stripe");
        if (secrets.GcpApiKeyCount > 0) codes.Add("secret:token:gcp-apikey");
        if (secrets.NpmTokenCount > 0) codes.Add("secret:token:npm");
        if (secrets.AzureSasTokenCount > 0) codes.Add("secret:token:azure-sas");
        return codes;
    }

    private static IReadOnlyList<SecretFindingDetail> BuildSecretFindingDetails(string text, SecretsSummary summary, TokenFamilyCounters tokenFamilies)
    {
        var details = new List<SecretFindingDetail>(12);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void AddDetail(string code, string confidence, int index, string evidence)
        {
            if (details.Count >= 12) return;
            if (string.IsNullOrWhiteSpace(code) || string.IsNullOrWhiteSpace(evidence)) return;
            string key = code + "|" + evidence;
            if (!seen.Add(key)) return;
            details.Add(new SecretFindingDetail
            {
                Code = code,
                Confidence = confidence,
                Line = GetLineNumber(text, index),
                Evidence = evidence
            });
        }

        if (summary.PrivateKeyCount > 0 && TryFindAnyPrivateKeyMarker(text, out var marker, out var markerIndex))
            AddDetail("secret:privkey", "High", markerIndex, marker);

        if (summary.JwtLikeCount > 0)
        {
            foreach (var token in CollectJwtTokens(text, maxMatches: 3))
                AddDetail("secret:jwt", "Medium", token.Index, RedactToken(token.Token, keepHead: 8, keepTail: 6));
        }

        if (summary.KeyPatternCount > 0)
        {
            foreach (var m in CollectKeyPatternEvidence(text, maxMatches: 3))
                AddDetail("secret:keypattern", "Medium", m.Index, m.Evidence);
        }

        foreach (var match in tokenFamilies.Samples)
        {
            var code = SecretCodeFromTokenFamily(match.Family);
            if (string.IsNullOrEmpty(code)) continue;
            AddDetail(code, SecretConfidenceFromTokenFamily(match.Family), match.Index, RedactToken(match.Token, keepHead: 9, keepTail: 4));
            if (details.Count >= 12) break;
        }

        return details;
    }

    private sealed class JwtTokenMatch
    {
        public string Token { get; set; } = string.Empty;
        public int Index { get; set; }
    }

    private sealed class KeyPatternEvidence
    {
        public int Index { get; set; }
        public string Evidence { get; set; } = string.Empty;
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

    private static IEnumerable<JwtTokenMatch> CollectJwtTokens(string text, int maxMatches)
    {
        var matches = new List<JwtTokenMatch>(Math.Max(0, maxMatches));
        var seen = new HashSet<string>(StringComparer.Ordinal);
        try
        {
            int max = Math.Min(text.Length, 16 * 1024);
            int i = 0;
            while (i < max && matches.Count < maxMatches)
            {
                while (i < max && !IsJwtTokenChar(text[i])) i++;
                if (i >= max) break;

                int start = i;
                while (i < max && IsJwtTokenChar(text[i])) i++;
                int len = i - start;
                if (len < 24) continue;

                var token = text.Substring(start, len);
                if (!LooksLikeJwtToken(token) || !seen.Add(token)) continue;
                matches.Add(new JwtTokenMatch { Token = token, Index = start });
            }
        }
        catch { }
        return matches;
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

    private static IEnumerable<KeyPatternEvidence> CollectKeyPatternEvidence(string text, int maxMatches)
    {
        var matches = new List<KeyPatternEvidence>(Math.Max(0, maxMatches));
        try
        {
            var t = text;
            int max = Math.Min(t.Length, 4096);
            for (int i = 0; i < max - 6 && matches.Count < maxMatches; i++)
            {
                string? label = null;
                int valueStart = -1;
                bool isConnectionString = false;
                if ((t[i] == 'k' || t[i] == 'K') && SpanEqualsIgnoreCase(t, i, "key=", max))
                {
                    label = "key";
                    valueStart = i + 4;
                }
                else if ((t[i] == 's' || t[i] == 'S') && SpanEqualsIgnoreCase(t, i, "secret=", max))
                {
                    label = "secret";
                    valueStart = i + 7;
                }
                else if ((t[i] == 'p' || t[i] == 'P') && SpanEqualsIgnoreCase(t, i, "password=", max))
                {
                    label = "password";
                    valueStart = i + 9;
                }
                else if ((t[i] == 'p' || t[i] == 'P') && SpanEqualsIgnoreCase(t, i, "pwd=", max))
                {
                    label = "pwd";
                    valueStart = i + 4;
                }
                else if ((t[i] == 'c' || t[i] == 'C') && SpanEqualsIgnoreCase(t, i, "connectionstring=", max))
                {
                    label = "connectionstring";
                    valueStart = i + "connectionstring=".Length;
                    isConnectionString = true;
                }

                if (label == null) continue;
                if (isConnectionString)
                {
                    int window = Math.Min(max, i + 256);
                    var slice = t.Substring(i, window - i);
                    if (slice.IndexOf("password=", StringComparison.OrdinalIgnoreCase) < 0 &&
                        slice.IndexOf("pwd=", StringComparison.OrdinalIgnoreCase) < 0)
                    {
                        continue;
                    }

                    matches.Add(new KeyPatternEvidence
                    {
                        Index = i,
                        Evidence = "connectionstring=<redacted>"
                    });
                    continue;
                }

                if (!TryGetLongTokenAfter(t, valueStart, out var tokenStart, out var candidate))
                    continue;

                matches.Add(new KeyPatternEvidence
                {
                    Index = i,
                    Evidence = label + "=" + RedactToken(candidate, keepHead: 4, keepTail: 4)
                });
            }
        }
        catch { }
        return matches;
    }

    private static bool SpanEqualsIgnoreCase(string text, int start, string token, int max)
    {
        if (start < 0 || start + token.Length > max || start + token.Length > text.Length) return false;
        for (int i = 0; i < token.Length; i++)
        {
            if (char.ToUpperInvariant(text[start + i]) != char.ToUpperInvariant(token[i])) return false;
        }
        return true;
    }

    private static bool HasLongTokenAfter(string t, int start)
    {
        return TryGetLongTokenAfter(t, start, out _, out _);
    }

    private static bool TryGetLongTokenAfter(string t, int start, out int tokenStart, out string candidate)
    {
        tokenStart = -1;
        candidate = string.Empty;
        int i = start;
        while (i < t.Length && (t[i] == ' ' || t[i] == '"' || t[i] == '\'')) i++;
        tokenStart = i;
        int max = Math.Min(t.Length, start + 256);
        for (; i < max; i++)
        {
            char c = t[i];
            if (char.IsLetterOrDigit(c) || c == '+' || c == '/' || c == '=' || c == '-' || c == '_') { }
            else break;
        }
        int len = i - tokenStart;
        if (len < 20) return false;
        candidate = t.Substring(tokenStart, len);
        if (LooksLikePlaceholderToken(candidate)) return false;
        if (IsLowDiversityToken(candidate)) return false;
        return true;
    }

    private enum TokenFamilyKind
    {
        Unknown = 0,
        GitHub = 1,
        GitLab = 2,
        AwsAccessKeyId = 3,
        Slack = 4,
        StripeLive = 5,
        GcpApiKey = 6,
        NpmToken = 7,
        AzureSas = 8
    }

    private static int CountTokenFamilyIndicators(string text)
        => CountTokenFamilyIndicatorsDetailed(text).TotalCount;

    private sealed class TokenFamilyMatch
    {
        public string Token { get; set; } = string.Empty;
        public TokenFamilyKind Family { get; set; } = TokenFamilyKind.Unknown;
        public int Index { get; set; }
    }

    private sealed class TokenFamilyCounters
    {
        private readonly HashSet<string> _seenTokens = new(StringComparer.OrdinalIgnoreCase);
        private readonly List<TokenFamilyMatch> _samples = new(8);

        public int TotalCount => _seenTokens.Count;
        public int GitHubCount { get; private set; }
        public int GitLabCount { get; private set; }
        public int AwsAccessKeyIdCount { get; private set; }
        public int SlackCount { get; private set; }
        public int StripeLiveCount { get; private set; }
        public int GcpApiKeyCount { get; private set; }
        public int NpmTokenCount { get; private set; }
        public int AzureSasCount { get; private set; }
        public IReadOnlyList<TokenFamilyMatch> Samples => _samples;

        public bool TryAddToken(string token, TokenFamilyKind family, int index)
        {
            if (string.IsNullOrWhiteSpace(token) || family == TokenFamilyKind.Unknown) return false;
            if (!_seenTokens.Add(token)) return false;
            switch (family)
            {
                case TokenFamilyKind.GitHub: GitHubCount++; break;
                case TokenFamilyKind.GitLab: GitLabCount++; break;
                case TokenFamilyKind.AwsAccessKeyId: AwsAccessKeyIdCount++; break;
                case TokenFamilyKind.Slack: SlackCount++; break;
                case TokenFamilyKind.StripeLive: StripeLiveCount++; break;
                case TokenFamilyKind.GcpApiKey: GcpApiKeyCount++; break;
                case TokenFamilyKind.NpmToken: NpmTokenCount++; break;
                case TokenFamilyKind.AzureSas: AzureSasCount++; break;
            }
            if (_samples.Count < 10)
            {
                _samples.Add(new TokenFamilyMatch
                {
                    Token = token,
                    Family = family,
                    Index = Math.Max(0, index)
                });
            }
            return true;
        }
    }

    private static TokenFamilyCounters CountTokenFamilyIndicatorsDetailed(string text)
    {
        const int MaxMatches = 24;
        var counters = new TokenFamilyCounters();
        try
        {
            int max = Math.Min(text.Length, 24 * 1024);
            if (max <= 0) return counters;

            // Prefix-driven probing keeps scan cost low and avoids classifying generic words.
            ProbePrefix(text, max, "github_pat_", StringComparison.OrdinalIgnoreCase, counters, MaxMatches);
            ProbePrefix(text, max, "ghp_", StringComparison.OrdinalIgnoreCase, counters, MaxMatches);
            ProbePrefix(text, max, "gho_", StringComparison.OrdinalIgnoreCase, counters, MaxMatches);
            ProbePrefix(text, max, "ghu_", StringComparison.OrdinalIgnoreCase, counters, MaxMatches);
            ProbePrefix(text, max, "ghs_", StringComparison.OrdinalIgnoreCase, counters, MaxMatches);
            ProbePrefix(text, max, "ghr_", StringComparison.OrdinalIgnoreCase, counters, MaxMatches);
            ProbePrefix(text, max, "glpat-", StringComparison.OrdinalIgnoreCase, counters, MaxMatches);
            ProbePrefix(text, max, "AKIA", StringComparison.Ordinal, counters, MaxMatches);
            ProbePrefix(text, max, "ASIA", StringComparison.Ordinal, counters, MaxMatches);
            ProbePrefix(text, max, "xoxb-", StringComparison.OrdinalIgnoreCase, counters, MaxMatches);
            ProbePrefix(text, max, "xoxp-", StringComparison.OrdinalIgnoreCase, counters, MaxMatches);
            ProbePrefix(text, max, "xoxa-", StringComparison.OrdinalIgnoreCase, counters, MaxMatches);
            ProbePrefix(text, max, "xoxs-", StringComparison.OrdinalIgnoreCase, counters, MaxMatches);
            ProbePrefix(text, max, "xoxr-", StringComparison.OrdinalIgnoreCase, counters, MaxMatches);
            ProbePrefix(text, max, "sk_live_", StringComparison.OrdinalIgnoreCase, counters, MaxMatches);
            ProbePrefix(text, max, "rk_live_", StringComparison.OrdinalIgnoreCase, counters, MaxMatches);
            ProbePrefix(text, max, "AIza", StringComparison.Ordinal, counters, MaxMatches);
            ProbePrefix(text, max, "npm_", StringComparison.OrdinalIgnoreCase, counters, MaxMatches);
            ProbeAzureSas(text, max, counters, MaxMatches);
        }
        catch { }
        return counters;
    }

    private static void ProbePrefix(
        string text,
        int max,
        string prefix,
        StringComparison comparison,
        TokenFamilyCounters counters,
        int maxMatches)
    {
        if (string.IsNullOrEmpty(text) || string.IsNullOrEmpty(prefix) || max <= 0) return;
        int i = 0;
        while (i < max && counters.TotalCount < maxMatches)
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
                        counters.TryAddToken(token, family, at);
                }
            }

            i = at + prefix.Length;
        }
    }

    private static void ProbeAzureSas(string text, int max, TokenFamilyCounters counters, int maxMatches)
    {
        if (string.IsNullOrEmpty(text) || max <= 0) return;
        int i = 0;
        while (i < max && counters.TotalCount < maxMatches)
        {
            int at = text.IndexOf("sig=", i, StringComparison.OrdinalIgnoreCase);
            if (at < 0 || at >= max) break;

            int start = at;
            while (start > 0 && !IsSecretDelimiter(text[start - 1])) start--;
            int end = at;
            while (end < max && !IsSecretDelimiter(text[end])) end++;
            if (end > start)
            {
                var token = TrimTokenNoise(text.Substring(start, end - start).TrimStart('?', '&'));
                if (token.Length >= 24 && token.Length <= 512 && LooksLikeAzureSasToken(token))
                {
                    if (!LooksLikePlaceholderToken(token) && HasSecretLikeContext(text, start, end, TokenFamilyKind.AzureSas))
                        counters.TryAddToken(token, TokenFamilyKind.AzureSas, start);
                }
            }

            i = at + 4;
        }
    }

    private static bool IsSecretDelimiter(char c)
        => char.IsWhiteSpace(c) || c == '"' || c == '\'' || c == '<' || c == '>' || c == '(' || c == ')' || c == '[' || c == ']';

    private static string TrimTokenNoise(string token)
        => token.Trim(' ', '\t', '\r', '\n', '"', '\'', '`', '(', ')', '[', ']', '{', '}', '<', '>', ',', ';', '.');

    private static string RedactToken(string token, int keepHead, int keepTail)
    {
        if (string.IsNullOrWhiteSpace(token)) return string.Empty;
        if (token.Length <= Math.Max(6, keepHead + keepTail)) return "<redacted>";
        keepHead = Math.Max(0, keepHead);
        keepTail = Math.Max(0, keepTail);
        int middle = token.Length - keepHead - keepTail;
        if (middle <= 0) return "<redacted>";
        return token.Substring(0, keepHead) + new string('*', middle) + token.Substring(token.Length - keepTail, keepTail);
    }

    private static bool TryFindAnyPrivateKeyMarker(string text, out string marker, out int index)
    {
        marker = string.Empty;
        index = -1;
        try
        {
            for (int i = 0; i < PrivateKeyMarkers.Length; i++)
            {
                int at = text.IndexOf(PrivateKeyMarkers[i], StringComparison.OrdinalIgnoreCase);
                if (at < 0) continue;
                marker = PrivateKeyMarkers[i];
                index = at;
                return true;
            }
        }
        catch { }
        return false;
    }

    private static string SecretCodeFromTokenFamily(TokenFamilyKind family)
    {
        return family switch
        {
            TokenFamilyKind.GitHub => "secret:token:github",
            TokenFamilyKind.GitLab => "secret:token:gitlab",
            TokenFamilyKind.AwsAccessKeyId => "secret:token:aws-akid",
            TokenFamilyKind.Slack => "secret:token:slack",
            TokenFamilyKind.StripeLive => "secret:token:stripe",
            TokenFamilyKind.GcpApiKey => "secret:token:gcp-apikey",
            TokenFamilyKind.NpmToken => "secret:token:npm",
            TokenFamilyKind.AzureSas => "secret:token:azure-sas",
            _ => string.Empty
        };
    }

    private static string SecretConfidenceFromTokenFamily(TokenFamilyKind family)
    {
        return family switch
        {
            TokenFamilyKind.AwsAccessKeyId => "High",
            TokenFamilyKind.AzureSas => "High",
            TokenFamilyKind.GitHub => "High",
            TokenFamilyKind.GitLab => "High",
            _ => "Medium"
        };
    }

    private static int? GetLineNumber(string text, int index)
    {
        if (string.IsNullOrEmpty(text) || index < 0) return null;
        if (index > text.Length) index = text.Length;
        int line = 1;
        for (int i = 0; i < index; i++)
        {
            if (text[i] == '\n') line++;
        }
        return line;
    }

    private static bool TryGetTokenFamily(string token, out TokenFamilyKind kind)
    {
        if (LooksLikeGitHubToken(token)) { kind = TokenFamilyKind.GitHub; return true; }
        if (LooksLikeGitLabToken(token)) { kind = TokenFamilyKind.GitLab; return true; }
        if (LooksLikeAwsAccessKeyId(token)) { kind = TokenFamilyKind.AwsAccessKeyId; return true; }
        if (LooksLikeSlackToken(token)) { kind = TokenFamilyKind.Slack; return true; }
        if (LooksLikeStripeLiveToken(token)) { kind = TokenFamilyKind.StripeLive; return true; }
        if (LooksLikeGcpApiKey(token)) { kind = TokenFamilyKind.GcpApiKey; return true; }
        if (LooksLikeNpmToken(token)) { kind = TokenFamilyKind.NpmToken; return true; }
        if (LooksLikeAzureSasToken(token)) { kind = TokenFamilyKind.AzureSas; return true; }
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

    private static bool LooksLikeGcpApiKey(string token)
    {
        if (!token.StartsWith("AIza", StringComparison.Ordinal)) return false;
        if (token.Length != 39) return false;
        return IsAlphaNumOrUnderscoreDash(token, 4);
    }

    private static bool LooksLikeNpmToken(string token)
    {
        if (!token.StartsWith("npm_", StringComparison.OrdinalIgnoreCase)) return false;
        int p = "npm_".Length;
        int bodyLen = token.Length - p;
        return bodyLen >= 24 && bodyLen <= 128 && IsAlphaNumOrUnderscore(token, p);
    }

    private static bool LooksLikeAzureSasToken(string token)
    {
        if (string.IsNullOrWhiteSpace(token)) return false;
        var lower = token.ToLowerInvariant();
        if (lower.IndexOf("sv=", StringComparison.Ordinal) < 0) return false;
        if (lower.IndexOf("sig=", StringComparison.Ordinal) < 0) return false;
        if (lower.IndexOf("se=", StringComparison.Ordinal) < 0 && lower.IndexOf("sp=", StringComparison.Ordinal) < 0) return false;
        int sigPos = lower.IndexOf("sig=", StringComparison.Ordinal);
        if (sigPos < 0 || sigPos + 4 >= token.Length) return false;
        int sigStart = sigPos + 4;
        int sigEnd = token.IndexOf('&', sigStart);
        if (sigEnd < 0) sigEnd = token.Length;
        int sigLen = sigEnd - sigStart;
        if (sigLen < 20 || sigLen > 256) return false;
        for (int i = sigStart; i < sigEnd; i++)
        {
            char c = token[i];
            bool ok = char.IsLetterOrDigit(c) || c == '%' || c == '+' || c == '/' || c == '=' || c == '-' || c == '_' || c == '.';
            if (!ok) return false;
        }
        return true;
    }

    private static bool RequiresContext(TokenFamilyKind family)
        => family == TokenFamilyKind.AwsAccessKeyId ||
           family == TokenFamilyKind.GcpApiKey ||
           family == TokenFamilyKind.NpmToken ||
           family == TokenFamilyKind.AzureSas;

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
               lower.IndexOf("replace_me", StringComparison.Ordinal) >= 0 ||
               lower.IndexOf("replace-with", StringComparison.Ordinal) >= 0 ||
               lower.IndexOf("replacewith", StringComparison.Ordinal) >= 0 ||
               lower.IndexOf("replace", StringComparison.Ordinal) >= 0 ||
               lower.IndexOf("token_here", StringComparison.Ordinal) >= 0 ||
               lower.IndexOf("secret_here", StringComparison.Ordinal) >= 0 ||
               lower.IndexOf("key_here", StringComparison.Ordinal) >= 0 ||
               lower.IndexOf("your_api_key", StringComparison.Ordinal) >= 0 ||
               lower.IndexOf("yourapikey", StringComparison.Ordinal) >= 0 ||
               lower.IndexOf("your_token", StringComparison.Ordinal) >= 0 ||
               lower.IndexOf("yourtoken", StringComparison.Ordinal) >= 0 ||
               lower.IndexOf("your_secret", StringComparison.Ordinal) >= 0 ||
               lower.IndexOf("yoursecret", StringComparison.Ordinal) >= 0 ||
               lower.IndexOf("your_", StringComparison.Ordinal) >= 0;
    }

    private static bool IsLowDiversityToken(string token)
    {
        if (string.IsNullOrEmpty(token)) return true;
        var seen = new HashSet<char>();
        for (int i = 0; i < token.Length; i++)
        {
            seen.Add(char.ToLowerInvariant(token[i]));
            if (seen.Count >= 4) return false;
        }
        return true;
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
