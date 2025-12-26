namespace FileInspectorX;

internal static partial class Signatures
{
    private static string Utf8(ReadOnlySpan<byte> s)
    {
        if (s.Length == 0) return string.Empty;
#if NET8_0_OR_GREATER
        return System.Text.Encoding.UTF8.GetString(s);
#else
        var a = s.ToArray();
        return System.Text.Encoding.UTF8.GetString(a);
#endif
    }

    private static int GetHeaderBytes()
    {
        int hb = Settings.HeaderReadBytes;
        if (hb <= 0) hb = HEADER_BYTES_FALLBACK;
        return Math.Max(256, Math.Min(hb, 1 << 20));
    }

    private static int Count(ReadOnlySpan<byte> l, byte ch) { int c = 0; for (int i = 0; i < l.Length; i++) if (l[i] == ch) c++; return c; }
    private static bool IsDigit(byte b) => b >= (byte)'0' && b <= (byte)'9';
    private static ReadOnlySpan<byte> TrimBytes(ReadOnlySpan<byte> s)
    {
        int a = 0; int b = s.Length - 1;
        while (a <= b && (s[a] == (byte)' ' || s[a] == (byte)'\t' || s[a] == (byte)'\r')) a++;
        while (b >= a && (s[b] == (byte)' ' || s[b] == (byte)'\t' || s[b] == (byte)'\r')) b--;
        return a <= b ? s.Slice(a, b - a + 1) : ReadOnlySpan<byte>.Empty;
    }

    private static bool LooksLikeTimestamp(ReadOnlySpan<byte> l)
    {
        int i = 0;
        while (i < l.Length && char.IsWhiteSpace((char)l[i])) i++;
        if (i < l.Length && l[i] == (byte)'[')
        {
            i++;
            while (i < l.Length && char.IsWhiteSpace((char)l[i])) i++;
        }
        if (l.Length - i < 10) return false;
        bool y = IsDigit(l[i + 0]) && IsDigit(l[i + 1]) && IsDigit(l[i + 2]) && IsDigit(l[i + 3]);
        bool sep1 = l[i + 4] == (byte)'-' || l[i + 4] == (byte)'/';
        bool m = IsDigit(l[i + 5]) && IsDigit(l[i + 6]);
        bool sep2 = l[i + 7] == (byte)'-' || l[i + 7] == (byte)'/';
        bool d = IsDigit(l[i + 8]) && IsDigit(l[i + 9]);
        return y && sep1 && m && sep2 && d;
    }

    private static bool StartsWithToken(ReadOnlySpan<byte> l, string token)
    {
        var tb = System.Text.Encoding.ASCII.GetBytes(token);
        if (l.Length < tb.Length) return false;
        for (int i = 0; i < tb.Length; i++) if (char.ToUpperInvariant((char)l[i]) != char.ToUpperInvariant((char)tb[i])) return false;
        return true;
    }

    private static bool StartsWithLevelToken(ReadOnlySpan<byte> l)
    {
        if (StartsWithToken(l, "INFO") || StartsWithToken(l, "WARN") || StartsWithToken(l, "ERROR") || StartsWithToken(l, "DEBUG") || StartsWithToken(l, "TRACE") || StartsWithToken(l, "FATAL") || StartsWithToken(l, "CRITICAL") || StartsWithToken(l, "ALERT") || StartsWithToken(l, "[INFO]") || StartsWithToken(l, "[WARN]") || StartsWithToken(l, "[ERROR]") || StartsWithToken(l, "[DEBUG]") || StartsWithToken(l, "[CRITICAL]") || StartsWithToken(l, "[ALERT]"))
            return true;
        // Allow bracketed levels like "[Info -", "[ERROR  -", "[Warn ]"
        if (l.Length > 2 && l[0] == (byte)'[')
        {
            int i = 1;
            while (i < l.Length && char.IsWhiteSpace((char)l[i])) i++;
            int start = i;
            while (i < l.Length && char.IsLetter((char)l[i])) i++;
            int len = i - start;
            if (len >= 3 && IsLevelToken(l.Slice(start, len)))
            {
                if (i >= l.Length) return true;
                byte next = l[i];
                if (next == (byte)']' || next == (byte)'-' || next == (byte)' ' || next == (byte)'\t') return true;
            }
        }
        return false;
    }

    private static bool IsLevelToken(ReadOnlySpan<byte> token)
    {
        return (token.Length == 4 && StartsWithToken(token, "INFO")) ||
               (token.Length == 4 && StartsWithToken(token, "WARN")) ||
               (token.Length == 5 && StartsWithToken(token, "ERROR")) ||
               (token.Length == 5 && StartsWithToken(token, "DEBUG")) ||
               (token.Length == 5 && StartsWithToken(token, "TRACE")) ||
               (token.Length == 5 && StartsWithToken(token, "FATAL")) ||
               (token.Length == 5 && StartsWithToken(token, "ALERT")) ||
               (token.Length == 8 && StartsWithToken(token, "CRITICAL"));
    }

    private static int IndexOfToken(ReadOnlySpan<byte> hay, string token)
    {
        var tb = System.Text.Encoding.ASCII.GetBytes(token);
        for (int i = 0; i + tb.Length <= hay.Length; i++)
        {
            bool m = true;
            for (int j = 0; j < tb.Length; j++)
            {
                if (char.ToLowerInvariant((char)hay[i + j]) != char.ToLowerInvariant((char)tb[j])) { m = false; break; }
            }
            if (m) return i;
        }
        return -1;
    }

    private static bool LooksLikeAdmxXml(string lower)
    {
        int cues = 0;
        if (lower.Contains("schemas.microsoft.com/grouppolicy/2006/07/policydefinitions")) cues++;
        if (lower.Contains("<policynamespaces")) cues++;
        if (lower.Contains("<policies")) cues++;
        if (lower.Contains("<categories")) cues++;
        if (lower.Contains("<resources")) cues++;
        if (lower.Contains("schemaversion")) cues++;
        if (lower.Contains("revision=\"")) cues++;
        return cues >= 2;
    }

    private static bool LooksLikeAdmlXml(string lower)
    {
        int cues = 0;
        if (lower.Contains("schemas.microsoft.com/grouppolicy/2006/07/policydefinitions")) cues++;
        if (lower.Contains("<resources")) cues++;
        if (lower.Contains("<stringtable")) cues++;
        if (lower.Contains("<presentationtable")) cues++;
        if (lower.Contains("schemaversion")) cues++;
        if (lower.Contains("revision=\"")) cues++;
        return cues >= 2;
    }

    private static string? TryGetXmlRootName(string s)
    {
        if (string.IsNullOrEmpty(s)) return null;
        int i = 0;
        while (i < s.Length)
        {
            int lt = s.IndexOf('<', i);
            if (lt < 0 || lt + 1 >= s.Length) return null;
            char next = s[lt + 1];
            if (next == '?' || next == '!')
            {
                int gt = s.IndexOf('>', lt + 2);
                if (gt < 0) return null;
                i = gt + 1;
                continue;
            }
            int start = lt + 1;
            while (start < s.Length && char.IsWhiteSpace(s[start])) start++;
            int end = start;
            while (end < s.Length && (char.IsLetterOrDigit(s[end]) || s[end] == ':' || s[end] == '_' || s[end] == '-')) end++;
            if (end > start) return s.Substring(start, end - start);
            i = lt + 1;
        }
        return null;
    }

    private static bool LooksIniSectionLine(ReadOnlySpan<byte> line)
    {
        const string DisallowedIniSectionChars = "()=@{}";
        // INI/INF sections are typically "[Section Name]" as the full (non-comment) line.
        // Avoid false positives from PowerShell type accelerators/attributes like "[int]$x" or "[ValidateSet(...)]".
        if (line.Length < 3) return false;
        int start = 0;
        while (start < line.Length && (line[start] == (byte)' ' || line[start] == (byte)'\t')) start++;
        if (start >= line.Length || line[start] != (byte)'[') return false;

        int closeRel = line.Slice(start + 1).IndexOf((byte)']');
        if (closeRel < 0) return false;
        int close = start + 1 + closeRel;
        if (close <= start + 1) return false;

        // Require the section token to be "simple": allow letters/digits/space/._- but not ()=@{} etc.
        for (int i = start + 1; i < close; i++)
        {
            byte c = line[i];
            if (DisallowedIniSectionChars.IndexOf((char)c) >= 0) return false;
            if (!(char.IsLetterOrDigit((char)c) || c == (byte)' ' || c == (byte)'_' || c == (byte)'-' || c == (byte)'.')) return false;
        }

        // After the closing bracket, allow only whitespace or a comment delimiter.
        int after = close + 1;
        while (after < line.Length && (line[after] == (byte)' ' || line[after] == (byte)'\t')) after++;
        if (after >= line.Length) return true;
        return line[after] == (byte)';' || line[after] == (byte)'#';
    }

    private static bool HasQuotedKeyColon(ReadOnlySpan<byte> s)
    {
        for (int i = 0; i + 3 < s.Length; i++)
        {
            if (s[i] == (byte)'"')
            {
                int j = i + 1; while (j < s.Length && s[j] != (byte)'"' && s[j] != (byte)'\n' && s[j] != (byte)'\r') j++;
                if (j < s.Length && s[j] == (byte)'"')
                {
                    int k = j + 1; while (k < s.Length && char.IsWhiteSpace((char)s[k])) k++;
                    if (k < s.Length && s[k] == (byte)':') return true;
                }
            }
        }
        return false;
    }

    private static void CountYamlStructure(ReadOnlySpan<byte> head, int maxLines, out int yamlKeys, out int yamlLists)
    {
        yamlKeys = 0;
        yamlLists = 0;
        int scanned = 0;
        int lineStart = 0;
        for (int i = 0; i < head.Length && scanned < maxLines; i++)
        {
            if (head[i] == (byte)'\n' || i == head.Length - 1)
            {
                int end = head[i] == (byte)'\n' ? i : i + 1;
                var raw = head.Slice(lineStart, Math.Max(0, end - lineStart));
                lineStart = i + 1;
                scanned++;
                var line = TrimBytes(raw);
                if (line.Length == 0) continue;
                if (line.Length >= 3 && line[0] == (byte)'-' && line[1] == (byte)'-' && line[2] == (byte)'-') continue;
                if (line.Length >= 3 && line[0] == (byte)'.' && line[1] == (byte)'.' && line[2] == (byte)'.') continue;
                if (StartsWithToken(line, "Proc-Type:") || StartsWithToken(line, "DEK-Info:")) continue;
                if (LooksYamlKeyValue(line)) yamlKeys++;
                else if (LooksYamlListItem(line)) yamlLists++;
            }
        }
    }

    private static bool LooksYamlListItem(ReadOnlySpan<byte> l)
    {
        if (l.Length < 2) return false;
        int i = 0;
        while (i < l.Length && (l[i] == (byte)' ' || l[i] == (byte)'\t')) i++;
        if (i >= l.Length || l[i] != (byte)'-') return false;
        if (i + 1 >= l.Length) return false;
        return l[i + 1] == (byte)' ' || l[i + 1] == (byte)'\t';
    }

    private static bool LooksYamlKeyValue(ReadOnlySpan<byte> l)
    {
        if (l.Length == 0) return false;
        // Ignore common log tokens
        if (StartsWithToken(l, "[INFO]") || StartsWithToken(l, "[WARN]") || StartsWithToken(l, "[ERROR]") || StartsWithToken(l, "[DEBUG]")) return false;
        if (StartsWithToken(l, "INFO:") || StartsWithToken(l, "WARN:") || StartsWithToken(l, "ERROR:") || StartsWithToken(l, "DEBUG:")) return false;
        int cpos = l.IndexOf((byte)':'); if (cpos <= 0 || cpos > Math.Min(80, l.Length - 1)) return false;
        // If there is any quote before ':', do not treat as YAML key (likely part of a quoted string)
        for (int i = 0; i < cpos; i++) { if (l[i] == (byte)'"' || l[i] == (byte)'\'') return false; }
        // Ignore URI-like key:/value
        if (cpos + 1 < l.Length && l[cpos + 1] == (byte)'/') return false;
        int p = 0; while (p < l.Length && (l[p] == (byte)' ' || l[p] == (byte)'\t' || l[p] == (byte)'-')) p++;
        if (p >= l.Length || p >= cpos) return false;
        // Require key segment without whitespace to reduce false positives like "Data being exported:"
        for (int i = p; i < cpos; i++) { if (l[i] == (byte)' ' || l[i] == (byte)'\t') return false; }
        // Start token must look like an identifier (letter or underscore)
        if (!(char.IsLetter((char)l[p]) || l[p] == (byte)'_')) return false;
        return true;
    }

    private static bool LooksLikeCompleteJson(string s)
    {
        if (string.IsNullOrWhiteSpace(s)) return false;
        var t = s.Trim();
        if (t.Length < 2) return false;
        char first = t[0];
        char last = t[t.Length - 1];
        return (first == '{' || first == '[') && (last == '}' || last == ']');
    }

    private static bool TryValidateJsonStructure(string s)
    {
        if (string.IsNullOrWhiteSpace(s)) return false;
        var span = s.AsSpan().Trim();
        if (span.Length < 2) return false;
        char first = span[0];
        char last = span[span.Length - 1];
        if (!((first == '{' || first == '[') && (last == '}' || last == ']'))) return false;
        int depthObj = 0;
        int depthArr = 0;
        bool inString = false;
        bool escape = false;
        for (int i = 0; i < span.Length; i++)
        {
            char c = span[i];
            if (inString)
            {
                if (escape) { escape = false; continue; }
                if (c == '\\') { escape = true; continue; }
                if (c == '"') inString = false;
                continue;
            }
            if (c == '"') { inString = true; continue; }
            if (c == '{') depthObj++;
            else if (c == '}') { depthObj--; if (depthObj < 0) return false; }
            else if (c == '[') depthArr++;
            else if (c == ']') { depthArr--; if (depthArr < 0) return false; }
        }
        return !inString && depthObj == 0 && depthArr == 0;
    }

    private static bool LooksLikeCompleteXml(string lower, string? rootLower)
    {
        if (string.IsNullOrWhiteSpace(lower)) return false;
        if (!lower.Contains("</")) return false;
        if (!lower.TrimEnd().EndsWith(">")) return false;
        if (!string.IsNullOrEmpty(rootLower))
            return lower.Contains("</" + rootLower);
        return true;
    }

    private static bool TryXmlWellFormed(string xml, out string? rootName)
    {
        rootName = null;
        if (string.IsNullOrWhiteSpace(xml)) return false;
        try
        {
            var settings = new System.Xml.XmlReaderSettings
            {
                DtdProcessing = System.Xml.DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = Math.Min(10_000_000L, Math.Max(1024L, (long)xml.Length * 4L)),
                MaxCharactersFromEntities = 1024
            };
            int timeoutMs = Math.Max(0, Settings.XmlWellFormednessTimeoutMs);
            var sw = timeoutMs > 0 ? System.Diagnostics.Stopwatch.StartNew() : null;
            using var reader = System.Xml.XmlReader.Create(new System.IO.StringReader(xml), settings);
            while (reader.Read())
            {
                if (sw != null && sw.ElapsedMilliseconds > timeoutMs) return false;
                if (reader.NodeType == System.Xml.XmlNodeType.Element)
                {
                    rootName = reader.Name;
                    break;
                }
            }
            return !string.IsNullOrEmpty(rootName);
        }
        catch
        {
            return false;
        }
    }
}
