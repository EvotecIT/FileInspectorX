using System;
using System.IO;

namespace FileInspectorX;

internal static partial class SecurityHeuristics
{
    private static void TryAddScriptHints(string text, Action<string> add, Func<bool> canAdd)
    {
        if (string.IsNullOrEmpty(text)) return;
        if (canAdd == null || add == null) return;
        if (!canAdd()) return;

        try
        {
            using var sr = new StringReader(text);
            string? line;
            int lines = 0;
            int maxLines = Settings.ScriptHintMaxLines;
            if (maxLines <= 0) return;
            while (lines < maxLines && (line = sr.ReadLine()) != null)
            {
                lines++;
                if (!canAdd()) break;
                if (line.Length > Settings.ScriptHintMaxLineLength) continue;
                var trimmed = line.TrimStart();
                if (trimmed.Length == 0 || trimmed[0] == '#') continue;

                if (StartsWithToken(trimmed.AsSpan(), "import-module"))
                {
                    var module = TryExtractModuleName(trimmed, "import-module");
                    if (!string.IsNullOrEmpty(module)) add("module:" + module);
                    continue;
                }
                if (StartsWithToken(trimmed.AsSpan(), "using module"))
                {
                    var module = TryExtractModuleName(trimmed, "using module");
                    if (!string.IsNullOrEmpty(module)) add("module:" + module);
                    continue;
                }
                if (StartsWithToken(trimmed.AsSpan(), "function"))
                {
                    var name = TryExtractIdentifier(trimmed, "function");
                    if (!string.IsNullOrEmpty(name)) add("func:" + name);
                    continue;
                }
                if (StartsWithToken(trimmed.AsSpan(), "filter"))
                {
                    var name = TryExtractIdentifier(trimmed, "filter");
                    if (!string.IsNullOrEmpty(name)) add("func:" + name);
                    continue;
                }
                if (StartsWithToken(trimmed.AsSpan(), "class"))
                {
                    var name = TryExtractIdentifier(trimmed, "class");
                    if (!string.IsNullOrEmpty(name)) add("class:" + name);
                }
            }
        }
        catch { }
    }

    private static string? TryExtractModuleName(string line, string keyword)
    {
        try
        {
            var span = line.AsSpan();
            int start = keyword.Length;
            if (start < span.Length && !char.IsWhiteSpace(span[start]))
                start = IndexOfToken(span, keyword);
            if (start < 0) return null;
            start += keyword.Length;

            var lower = line.ToLowerInvariant();
            int nameIdx = lower.IndexOf("-name", StringComparison.Ordinal);
            if (nameIdx < 0) nameIdx = lower.IndexOf("-modulename", StringComparison.Ordinal);
            if (nameIdx >= 0)
            {
                var name = ReadTokenAfter(span, nameIdx + (lower.AsSpan(nameIdx).StartsWith("-modulename") ? 11 : 5));
                return NormalizeModuleName(name);
            }

            var token = ReadTokenAfter(span, start);
            return NormalizeModuleName(token);
        }
        catch { return null; }
    }

    private static string? TryExtractIdentifier(string line, string keyword)
    {
        try
        {
            var span = line.AsSpan();
            int start = IndexOfToken(span, keyword);
            if (start < 0) return null;
            start += keyword.Length;
            while (start < span.Length && char.IsWhiteSpace(span[start])) start++;
            if (start >= span.Length) return null;
            int i = start;
            while (i < span.Length)
            {
                char c = span[i];
                if (char.IsLetterOrDigit(c) || c == '-' || c == '_') i++;
                else break;
            }
            if (i <= start) return null;
            return span.Slice(start, i - start).ToString();
        }
        catch { return null; }
    }

    private static int IndexOfToken(ReadOnlySpan<char> line, string token)
    {
        if (string.IsNullOrEmpty(token)) return -1;
        for (int i = 0; i + token.Length <= line.Length; i++)
        {
            if (!StartsWithToken(line.Slice(i), token)) continue;
            // Enforce word boundaries to avoid matching inside longer identifiers.
            bool startOk = i == 0 || char.IsWhiteSpace(line[i - 1]);
            bool endOk = i + token.Length >= line.Length || char.IsWhiteSpace(line[i + token.Length]);
            if (startOk && endOk) return i;
        }
        return -1;
    }

    private static string? ReadTokenAfter(ReadOnlySpan<char> line, int start)
    {
        int i = start;
        while (i < line.Length && char.IsWhiteSpace(line[i])) i++;
        if (i >= line.Length) return null;
        char quote = line[i];
        if (quote == '"' || quote == '\'')
        {
            i++;
            int s = i;
            while (i < line.Length && line[i] != quote) i++;
            if (i <= s) return null;
            return line.Slice(s, i - s).ToString();
        }
        else
        {
            int s = i;
            while (i < line.Length && !char.IsWhiteSpace(line[i]) && line[i] != ';' && line[i] != '#') i++;
            if (i <= s) return null;
            return line.Slice(s, i - s).ToString();
        }
    }

    private static string? NormalizeModuleName(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var name = (raw ?? string.Empty).Trim().Trim('"', '\'');
        if (string.IsNullOrWhiteSpace(name)) return null;
        if (name.StartsWith("$", StringComparison.Ordinal)) return null;
        int semi = name.IndexOf(';');
        if (semi >= 0) name = name.Substring(0, semi);
        name = name.Trim();
        if (string.IsNullOrWhiteSpace(name)) return null;
        if (name.IndexOf('\\') >= 0 || name.IndexOf('/') >= 0)
            name = Path.GetFileName(name);
        if (name.EndsWith(".psd1", StringComparison.OrdinalIgnoreCase) ||
            name.EndsWith(".psm1", StringComparison.OrdinalIgnoreCase) ||
            name.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase))
            name = Path.GetFileNameWithoutExtension(name);
        return string.IsNullOrWhiteSpace(name) ? null : name;
    }
}
