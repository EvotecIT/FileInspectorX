namespace FileInspectorX;

/// <summary>
/// Lightweight, dependency-free content heuristics used to emit neutral security signals and detect simple secret categories.
/// </summary>
internal static class SecurityHeuristics
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
            if (hosts.Count > 0) findings.Add($"net:hosts={hosts.Count}");

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
                if (ContainsAny(lower, new [] {"-----begin rsa private key-----", "-----begin private key-----", "-----begin dsa private key-----", "-----begin openssh private key-----"}))
                    findings.Add("secret:privkey");

                if (LooksLikeJwt(text) || LooksLikeJwtFallback(text) || lower.Contains("header.payload.signature")) findings.Add("secret:jwt");

                if (LooksLikeKeyPattern(text)) findings.Add("secret:keypattern");
            }
        } catch { }
        return findings;
    }

    internal static IReadOnlyList<string> AssessTextGeneric(string path, string? declaredExt, int budgetBytes)
    {
        var findings = new List<string>(8);
        try {
            string text = ReadTextHead(path, budgetBytes);
            if (string.IsNullOrEmpty(text)) return findings;
            var lower = text.ToLowerInvariant();

            // IIS W3C logs
            if (lower.Contains("#fields:") && (lower.Contains("#software: microsoft internet information services") || lower.Contains("#version:")))
                findings.Add("log:iis-w3c");

            // Windows DNS server log (text)
            if (lower.Contains("dns server log") || lower.Contains("dns server log file"))
                findings.Add("log:dns");
            // Windows Firewall log (pfirewall.log)
            if ((lower.Contains("microsoft windows firewall") || lower.Contains("windows firewall")) && lower.Contains("fields:"))
                findings.Add("log:firewall");
            // DHCP audit log
            if (lower.Contains("#software: microsoft dhcp server") && lower.Contains("#fields:"))
                findings.Add("log:dhcp");
            // Exchange message tracking
            if (lower.Contains("message tracking log file") || lower.Contains("#software: microsoft exchange"))
                findings.Add("exchange:msgtrack");
            // Windows Defender textual logs
            if (lower.Contains("windows defender") || lower.Contains("microsoft defender") || lower.Contains("mpcmdrun"))
                findings.Add("defender:txt");
            // SQL Server ERRORLOG
            if ((lower.Contains("sql server") || lower.Contains("errorlog")) && lower.Contains("spid"))
                findings.Add("sql:errorlog");
            // NPS / RADIUS logs
            if ((lower.Contains("#software: microsoft internet authentication service") || lower.Contains("#software: microsoft network policy server")) && lower.Contains("#fields:"))
                findings.Add("nps:radius");
            // SQL Server Agent logs
            if (lower.Contains("sqlserveragent") || lower.Contains("sql server agent"))
                findings.Add("sql:agent");
            // Netlogon log
            if (lower.Contains("netlogon") || lower.Contains("netrlogon") || lower.Contains("secure channel"))
                findings.Add("log:netlogon");
            // Event Viewer text export
            if ((lower.Contains("log name:") && lower.Contains("event id:")) || (lower.Contains("source:") && lower.Contains("task category:") && lower.Contains("level:")))
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
                if (lower.Contains("-----begin rsa private key-----") || lower.Contains("-----begin private key-----") || lower.Contains("-----begin dsa private key-----") || lower.Contains("-----begin openssh private key-----"))
                    findings.Add("secret:privkey");
                if (LooksLikeJwt(text) || LooksLikeJwtFallback(text) || lower.Contains("header.payload.signature")) findings.Add("secret:jwt");
                if (LooksLikeKeyPattern(text)) findings.Add("secret:keypattern");
            }
        } catch { }
        return findings;
    }

    internal static SecretsSummary CountSecrets(string path, int budgetBytes)
    {
        var s = new SecretsSummary();
        try {
            if (!Settings.SecretsScanEnabled) return s;
            string text = ReadTextHead(path, budgetBytes);
            if (string.IsNullOrEmpty(text)) return s;
            var lower = text.ToLowerInvariant();
            if (ContainsAny(lower, new [] {"-----begin rsa private key-----", "-----begin private key-----", "-----begin dsa private key-----", "-----begin openssh private key-----"})) s.PrivateKeyCount++;
            if (LooksLikeJwt(text) || LooksLikeJwtFallback(text)) s.JwtLikeCount++;
            if (LooksLikeKeyPattern(text)) s.KeyPatternCount++;
        } catch { }
        return s;
    }

    private static bool ContainsAny(string hay, IEnumerable<string> needles) {
        foreach (var n in needles) if (hay.IndexOf(n, StringComparison.Ordinal) >= 0) return true;
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
    { try { using var cts = new System.Threading.CancellationTokenSource(timeoutMs); var t = System.Threading.Tasks.Task.Run(() => System.Net.Dns.GetHostEntry(host), cts.Token); return t.Wait(timeoutMs) && t.Result != null; } catch { return false; } }
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

    private static bool LooksLikeJwt(string text)
    {
        try
        {
            int max = Math.Min(text.Length, 4096);
            int i = 0;
            while (i < max)
            {
                // Skip non base64url chars until a plausible segment starts
                while (i < max && !IsB64Url(text[i])) { if (char.IsWhiteSpace(text[i])) { /* reset state */ } i++; }
                int seg1 = 0; while (i < max && IsB64Url(text[i])) { seg1++; i++; }
                if (seg1 < 3 || i >= max || text[i] != '.') continue;
                i++; // consume dot
                int seg2 = 0; while (i < max && IsB64Url(text[i])) { seg2++; i++; }
                if (seg2 < 3 || i >= max || text[i] != '.') continue;
                i++; // consume second dot
                int seg3 = 0; while (i < max && IsB64Url(text[i])) { seg3++; i++; }
                if (seg3 >= 3) return true; // good enough for heuristic
            }
        }
        catch { }
        return false;

        static bool IsB64Url(char c)
            => (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
    }

    // Very permissive fallback: look for three dot-separated base64url-looking segments anywhere in the first 4KB.
    private static bool LooksLikeJwtFallback(string text)
    {
        try {
            int max = Math.Min(text.Length, 4096);
            int dots = 0; int seg = 0;
            for (int i = 0; i < max; i++)
            {
                char c = text[i];
                if (c == '.') { if (seg >= 3) { dots++; seg = 0; if (dots >= 2) return true; } else { dots = 0; seg = 0; } continue; }
                if (char.IsWhiteSpace(c)) { dots = 0; seg = 0; continue; }
                if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') seg++;
                else { dots = 0; seg = 0; }
            }
        } catch { }
        return false;
    }

    private static bool LooksLikeKeyPattern(string text)
    {
        try {
            var t = text; int max = Math.Min(t.Length, 4096);
            for (int i = 0; i < max - 6; i++)
            {
                if ((t[i] == 'k' || t[i] == 'K') && t.AsSpan(i, Math.Min(4, max - i)).ToString().Equals("key=", StringComparison.OrdinalIgnoreCase))
                {
                    if (HasLongTokenAfter(t, i + 4)) return true;
                }
                if ((t[i] == 's' || t[i] == 'S') && i + 7 < max && t.AsSpan(i, Math.Min(7, max - i)).ToString().Equals("secret=", StringComparison.OrdinalIgnoreCase))
                {
                    if (HasLongTokenAfter(t, i + 7)) return true;
                }
                if ((t[i] == 'p' || t[i] == 'P') && i + 9 < max && t.AsSpan(i, Math.Min(9, max - i)).ToString().Equals("password=", StringComparison.OrdinalIgnoreCase))
                {
                    if (HasLongTokenAfter(t, i + 9)) return true;
                }
                if ((t[i] == 'p' || t[i] == 'P') && i + 4 < max && t.AsSpan(i, Math.Min(4, max - i)).ToString().Equals("pwd=", StringComparison.OrdinalIgnoreCase))
                {
                    if (HasLongTokenAfter(t, i + 4)) return true;
                }
                if ((t[i] == 'c' || t[i] == 'C') && i + 16 < max && t.AsSpan(i, Math.Min(16, max - i)).ToString().Equals("connectionstring=", StringComparison.OrdinalIgnoreCase))
                {
                    // Look for password/pwd inside a small window after a connection string
                    int window = Math.Min(max, i + 256);
                    var slice = t.Substring(i, window - i);
                    if (slice.IndexOf("password=", StringComparison.OrdinalIgnoreCase) >= 0 || slice.IndexOf("pwd=", StringComparison.OrdinalIgnoreCase) >= 0)
                        return true;
                }
            }
        } catch { }
        return false;
    }

    private static bool HasLongTokenAfter(string t, int start)
    {
        int i = start; while (i < t.Length && (t[i] == ' ' || t[i] == '"' || t[i] == '\'')) i++;
        int len = 0; int max = Math.Min(t.Length, start + 256);
        for (; i < max; i++)
        {
            char c = t[i];
            if (char.IsLetterOrDigit(c) || c == '+' || c == '/' || c == '=' || c == '-' || c == '_') len++;
            else break;
        }
        return len >= 20;
    }

    private static bool LooksLikeJsonWithKeys(string lower, IEnumerable<string> keys)
    {
        // Cheap test: looks JSON-ish and contains all keys
        if (!(lower.Contains("{") && lower.Contains("}"))) return false;
        foreach (var k in keys) if (!lower.Contains(k)) return false; return true;
    }
}
