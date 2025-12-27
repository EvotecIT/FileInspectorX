using System;
using System.Collections.Generic;

namespace FileInspectorX;

public static partial class FileInspector
{
    private const int TopTokensHardMaxUniqueTokens = 100_000;
    private static readonly HashSet<string> TopTokenStopWords = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "function", "param", "return", "true", "false", "null", "begin", "process", "end",
        "foreach", "for", "while", "switch", "case", "break", "continue", "try", "catch", "finally",
        "using", "import", "module", "class", "public", "private", "protected", "static",
        "var", "let", "const", "default", "script", "global", "local",
        "info", "warn", "warning", "error", "debug", "trace", "fatal", "critical",
        "http", "https"
    };

    private static void TryPopulateTextMetrics(
        FileAnalysis res,
        ContentTypeDetectionResult? det,
        string path,
        Func<int, string>? readHeadText = null)
    {
        try
        {
            if (det == null) return;
            if (res.EstimatedLineCount == null && InspectHelpers.IsText(det))
                res.EstimatedLineCount = EstimateLines(path, Settings.DetectionReadBudgetBytes);

            if (!Settings.TopTokensEnabled) return;
            int max = Math.Max(0, Settings.TopTokensMax);
            if (max == 0) return;
            int maxUnique = Math.Max(0, Settings.TopTokensMaxUniqueTokens);
            if (maxUnique == 0) maxUnique = TopTokensHardMaxUniqueTokens;

            bool isLog = string.Equals(res.TextSubtype, "log", StringComparison.OrdinalIgnoreCase);
            bool isScript = IsScriptTextSubtype(res.TextSubtype) || IsScriptTextSubtype(res.ScriptLanguage);
            if (!isLog && !isScript) return;

            int minLen = Math.Max(2, Settings.TopTokensMinLength);
            int minCount = Math.Max(1, Settings.TopTokensMinCount);
            int maxBytes = Settings.TopTokensMaxBytes;
            if (maxBytes <= 0) maxBytes = Settings.DetectionReadBudgetBytes;
            int cap = Math.Min(Settings.DetectionReadBudgetBytes, maxBytes);
            var text = readHeadText != null ? readHeadText(cap) : ReadHeadText(path, cap);
            if (string.IsNullOrEmpty(text)) return;

            var tokens = ExtractTopTokens(text, max, minLen, minCount, maxUnique);
            if (tokens.Count > 0) res.TopTokens = tokens;
        }
        catch (Exception ex)
        {
            if (Settings.Logger.IsWarning)
                Settings.Logger.WriteWarning("textmetrics:failed ({0})", ex.GetType().Name);
            else if (Settings.Logger.IsDebug)
                Settings.Logger.WriteDebug("textmetrics:failed ({0})", ex.GetType().Name);
        }
    }

    private static IReadOnlyList<string> ExtractTopTokens(string text, int max, int minLen, int minCount, int maxUnique)
    {
        if (string.IsNullOrEmpty(text) || max <= 0) return Array.Empty<string>();
        var counts = maxUnique > 0
            ? new Dictionary<string, int>(maxUnique, StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var span = text.AsSpan();
        int i = 0;
        while (i < span.Length)
        {
            while (i < span.Length && !IsTokenChar(span[i])) i++;
            int start = i;
            while (i < span.Length && IsTokenChar(span[i])) i++;
            int len = i - start;
            if (len < minLen) continue;
            if (!TryTrimToken(span.Slice(start, len), out var trimmed)) continue;
            if (trimmed.Length < minLen) continue;
            if (IsNumeric(trimmed)) continue;
            var token = trimmed.ToString();
            if (TopTokenStopWords.Contains(token)) continue;
            if (ShouldRedactToken(token)) continue;
            if (maxUnique > 0 && counts.Count >= maxUnique && !counts.ContainsKey(token)) continue;
            counts.TryGetValue(token, out int c);
            counts[token] = c + 1;
        }
        if (counts.Count == 0) return Array.Empty<string>();

        var list = new List<KeyValuePair<string, int>>(counts);
        list.Sort((a, b) =>
        {
            int c = b.Value.CompareTo(a.Value);
            return c != 0 ? c : StringComparer.OrdinalIgnoreCase.Compare(a.Key, b.Key);
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

    private static bool ShouldRedactToken(string token)
    {
        var patterns = Settings.TopTokensRedactPatterns;
        if (patterns == null || patterns.Length == 0) return false;
        for (int i = 0; i < patterns.Length; i++)
        {
            var p = patterns[i];
            if (string.IsNullOrWhiteSpace(p)) continue;
            if (token.IndexOf(p, StringComparison.OrdinalIgnoreCase) >= 0) return true;
        }
        return false;
    }

    private static bool IsTokenChar(char c)
        => char.IsLetterOrDigit(c) || c == '_' || c == '-' || c == '.';

    private static bool IsNumeric(ReadOnlySpan<char> token)
    {
        for (int i = 0; i < token.Length; i++)
            if (!char.IsDigit(token[i])) return false;
        return token.Length > 0;
    }

    private static bool TryTrimToken(ReadOnlySpan<char> token, out ReadOnlySpan<char> trimmed)
    {
        if (token.IsEmpty) { trimmed = default; return false; }
        int start = 0;
        int end = token.Length - 1;
        while (start <= end && IsTrimChar(token[start])) start++;
        while (end >= start && IsTrimChar(token[end])) end--;
        if (end < start) { trimmed = default; return false; }
        trimmed = token.Slice(start, end - start + 1);
        return true;
    }

    private static bool IsTrimChar(char c) => c == '-' || c == '_' || c == '.';
}
