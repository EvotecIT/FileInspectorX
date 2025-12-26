using System;
using System.Collections.Generic;

namespace FileInspectorX;

public static partial class FileInspector
{
    private static readonly HashSet<string> TopTokenStopWords = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "function", "param", "return", "true", "false", "null", "begin", "process", "end",
        "foreach", "for", "while", "switch", "case", "break", "continue", "try", "catch", "finally",
        "using", "import", "module", "class", "public", "private", "protected", "static",
        "var", "let", "const", "default", "script", "global", "local",
        "info", "warn", "warning", "error", "debug", "trace", "fatal", "critical",
        "http", "https"
    };

    private static void TryPopulateTextMetrics(FileAnalysis res, ContentTypeDetectionResult? det, string path)
    {
        try
        {
            if (res.EstimatedLineCount == null && InspectHelpers.IsText(det))
                res.EstimatedLineCount = EstimateLines(path, Settings.DetectionReadBudgetBytes);

            if (!Settings.TopTokensEnabled) return;
            int max = Math.Max(0, Settings.TopTokensMax);
            if (max == 0) return;

            bool isLog = string.Equals(res.TextSubtype, "log", StringComparison.OrdinalIgnoreCase);
            bool isScript = !string.IsNullOrWhiteSpace(res.ScriptLanguage) ||
                            string.Equals(res.TextSubtype, "powershell", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(res.TextSubtype, "javascript", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(res.TextSubtype, "vbscript", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(res.TextSubtype, "shell", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(res.TextSubtype, "batch", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(res.TextSubtype, "python", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(res.TextSubtype, "ruby", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(res.TextSubtype, "perl", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(res.TextSubtype, "lua", StringComparison.OrdinalIgnoreCase);
            if (!isLog && !isScript) return;

            int minLen = Math.Max(2, Settings.TopTokensMinLength);
            int minCount = Math.Max(1, Settings.TopTokensMinCount);
            int cap = Math.Min(Settings.DetectionReadBudgetBytes, 256 * 1024);
            var text = ReadHeadText(path, cap);
            if (string.IsNullOrEmpty(text)) return;

            var tokens = ExtractTopTokens(text, max, minLen, minCount);
            if (tokens.Count > 0) res.TopTokens = tokens;
        }
        catch { }
    }

    private static IReadOnlyList<string> ExtractTopTokens(string text, int max, int minLen, int minCount)
    {
        if (string.IsNullOrEmpty(text) || max <= 0) return Array.Empty<string>();
        var counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var span = text.AsSpan();
        int i = 0;
        while (i < span.Length)
        {
            while (i < span.Length && !IsTokenChar(span[i])) i++;
            int start = i;
            while (i < span.Length && IsTokenChar(span[i])) i++;
            int len = i - start;
            if (len < minLen) continue;
            var token = span.Slice(start, len).ToString();
            token = TrimToken(token);
            if (token.Length < minLen) continue;
            token = token.ToLowerInvariant();
            if (TopTokenStopWords.Contains(token) || IsNumeric(token)) continue;
            counts.TryGetValue(token, out int c);
            counts[token] = c + 1;
        }
        if (counts.Count == 0) return Array.Empty<string>();

        var list = new List<KeyValuePair<string, int>>(counts);
        list.Sort((a, b) =>
        {
            int c = b.Value.CompareTo(a.Value);
            return c != 0 ? c : string.Compare(a.Key, b.Key, StringComparison.OrdinalIgnoreCase);
        });

        var result = new List<string>(Math.Min(max, list.Count));
        foreach (var kv in list)
        {
            if (kv.Value < minCount) break;
            result.Add($"{kv.Key}:{kv.Value}");
            if (result.Count >= max) break;
        }
        return result;
    }

    private static bool IsTokenChar(char c)
        => char.IsLetterOrDigit(c) || c == '_' || c == '-' || c == '.';

    private static bool IsNumeric(string token)
    {
        for (int i = 0; i < token.Length; i++)
            if (!char.IsDigit(token[i])) return false;
        return token.Length > 0;
    }

    private static string TrimToken(string token)
    {
        if (string.IsNullOrEmpty(token)) return string.Empty;
        int start = 0;
        int end = token.Length - 1;
        while (start <= end && IsTrimChar(token[start])) start++;
        while (end >= start && IsTrimChar(token[end])) end--;
        if (start == 0 && end == token.Length - 1) return token;
        if (end < start) return string.Empty;
        return token.Substring(start, end - start + 1);
    }

    private static bool IsTrimChar(char c) => c == '-' || c == '_' || c == '.' || c == ':';
}
