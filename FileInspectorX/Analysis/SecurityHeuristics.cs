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

                if (LooksLikeJwt(text)) findings.Add("secret:jwt");

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
            if (LooksLikeJwt(text)) s.JwtLikeCount++;
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
        try {
            int dots = 0; int tokenLen = 0; int maxCheck = Math.Min(text.Length, 4096);
            for (int i = 0; i < maxCheck; i++)
            {
                char c = text[i];
                if (c == '.') { dots++; if (dots >= 2 && tokenLen > 20) return true; tokenLen = 0; continue; }
                if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') tokenLen++;
                else if (char.IsWhiteSpace(c)) { if (dots >= 2 && tokenLen > 10) return true; dots = 0; tokenLen = 0; }
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
}
