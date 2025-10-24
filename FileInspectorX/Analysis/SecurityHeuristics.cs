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
