namespace FileInspectorX;

internal static partial class Signatures
{
    private static string Utf8(ReadOnlySpan<byte> s)
    {
        if (s.Length == 0) return string.Empty;
#if NET8_0_OR_GREATER
        return System.Text.Encoding.UTF8.GetString(s);
#else
        var rented = ArrayPool<byte>.Shared.Rent(s.Length);
        try
        {
            s.CopyTo(rented);
            return System.Text.Encoding.UTF8.GetString(rented, 0, s.Length);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented, clearArray: true);
        }
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

    private static bool LooksLikePlainText(ReadOnlySpan<byte> data, out bool extended, out double printableRatio)
    {
        extended = false;
        printableRatio = 0;
        if (data.Length == 0) return false;

        const int SmallSampleThreshold = 32;
        const int SmallSampleMinTextLike = 4;
        const double SmallSamplePrintableFloor = 0.8;

        int sampleLimit = Settings.PlainTextSampleBytes;
        if (sampleLimit <= 0) sampleLimit = 2048;
        int sample = Math.Min(sampleLimit, data.Length);
        if (sample <= 0) return false;

        int printable = 0;
        int control = 0;
        int high = 0;
        for (int i = 0; i < sample; i++)
        {
            byte b = data[i];
            if (b == 9 || b == 10 || b == 13) { printable++; continue; }
            if (b < 32 || b == 127) { control++; continue; }
            if (b < 127) { printable++; continue; }
            high++;
        }
        extended = high > 0;
        int textLike = printable + high;
        printableRatio = textLike / (double)sample;
        double controlRatio = control / (double)sample;

        double minPrintable = Settings.PlainTextPrintableMinRatio;
        if (minPrintable <= 0 || minPrintable > 1) minPrintable = 0.85;
        double maxControl = Settings.PlainTextControlMaxRatio;
        if (maxControl < 0 || maxControl > 1) maxControl = 0.02;
        if (sample < SmallSampleThreshold)
        {
            if (textLike < SmallSampleMinTextLike) return false;
            if (controlRatio > maxControl) return false;
            if (printableRatio < Math.Min(SmallSamplePrintableFloor, minPrintable)) return false;
            return true;
        }

        if (controlRatio > maxControl) return false;
        return printableRatio >= minPrintable;
    }

    private static bool LooksLikeTimestamp(ReadOnlySpan<byte> l)
    {
        if (l.Length < 10) return false;
        int i = 0;
        while (i < l.Length && char.IsWhiteSpace((char)l[i])) i++;
        if (i >= l.Length) return false;
        if (i < l.Length && l[i] == (byte)'[')
        {
            i++;
            while (i < l.Length && char.IsWhiteSpace((char)l[i])) i++;
            if (i >= l.Length) return false;
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

    private static bool StartsWithTimestampedLevelToken(ReadOnlySpan<byte> l)
    {
        if (!LooksLikeTimestamp(l)) return false;

        int i = 0;
        while (i < l.Length && char.IsWhiteSpace((char)l[i])) i++;
        if (i < l.Length && l[i] == (byte)'[')
        {
            i++;
            while (i < l.Length && char.IsWhiteSpace((char)l[i])) i++;
        }

        // Skip the leading timestamp token, including time / fractional seconds / timezone
        while (i < l.Length && !char.IsWhiteSpace((char)l[i]) && l[i] != (byte)']') i++;
        while (i < l.Length && (char.IsWhiteSpace((char)l[i]) || l[i] == (byte)']')) i++;
        if (i >= l.Length) return false;

        return StartsWithLevelToken(l.Slice(i));
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

    private static int CountAdmxCues(string lower, out bool strong)
    {
        bool hasNamespace = lower.Contains("schemas.microsoft.com/grouppolicy/2006/07/policydefinitions");
        bool hasPolicyNamespaces = lower.Contains("<policynamespaces");
        bool hasPolicies = lower.Contains("<policies");
        bool hasPolicy = lower.Contains("<policy ");
        bool hasCategories = lower.Contains("<categories");
        bool hasSupportedOn = lower.Contains("<supportedon");
        bool hasResources = lower.Contains("<resources");
        bool hasMsPoliciesNs = lower.Contains("namespace=\"microsoft.policies.");
        bool hasSchema = lower.Contains("schemaversion");
        bool hasRevision = lower.Contains("revision=\"");

        int cues = 0;
        if (hasNamespace) cues++;
        if (hasPolicyNamespaces) cues++;
        if (hasPolicies) cues++;
        if (hasPolicy) cues++;
        if (hasCategories) cues++;
        if (hasSupportedOn) cues++;
        if (hasResources) cues++;
        if (hasMsPoliciesNs) cues++;
        if (hasSchema) cues++;
        if (hasRevision) cues++;

        strong = (hasPolicyNamespaces && (hasPolicies || hasPolicy) && hasCategories) ||
                 (hasNamespace && (hasPolicies || hasPolicy)) ||
                 (hasPolicyNamespaces && hasSupportedOn);
        return cues;
    }

    private static bool LooksLikeAdmxXml(string lower)
    {
        int cues = CountAdmxCues(lower, out _);
        return cues >= 2;
    }

    private static int CountAdmlCues(string lower, out bool strong)
    {
        bool hasNamespace = lower.Contains("schemas.microsoft.com/grouppolicy/2006/07/policydefinitions");
        bool hasResources = lower.Contains("<resources");
        bool hasStringTable = lower.Contains("<stringtable");
        bool hasStringId = lower.Contains("<string id=");
        bool hasPresentationTable = lower.Contains("<presentationtable");
        bool hasSchema = lower.Contains("schemaversion");
        bool hasRevision = lower.Contains("revision=\"");

        int cues = 0;
        if (hasNamespace) cues++;
        if (hasResources) cues++;
        if (hasStringTable) cues++;
        if (hasStringId) cues++;
        if (hasPresentationTable) cues++;
        if (hasSchema) cues++;
        if (hasRevision) cues++;

        strong = (hasStringTable && hasStringId) ||
                 (hasResources && hasStringTable && hasPresentationTable);
        return cues;
    }

    private static bool LooksLikeAdmlXml(string lower)
    {
        int cues = CountAdmlCues(lower, out _);
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
        // Do not treat "C:\path\to\file: ..." style lines as YAML keys.
        if (cpos == 1 && char.IsLetter((char)l[0]) && cpos + 1 < l.Length && (l[cpos + 1] == (byte)'\\' || l[cpos + 1] == (byte)'/')) return false;
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

    private static int CountHeaderStyleColonLines(ReadOnlySpan<byte> head, int maxLines)
    {
        int count = 0;
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
                if (LooksLikeHeaderStyleColonLine(TrimBytes(raw))) count++;
            }
        }
        return count;
    }

    private static bool LooksLikeHeaderStyleColonLine(ReadOnlySpan<byte> l)
    {
        if (l.Length < 4) return false;
        if (!char.IsUpper((char)l[0])) return false;
        if (LooksLikeTimestamp(l) || LooksLikeSyslogLine(l)) return false;
        if (StartsWithToken(l, "[INFO]") || StartsWithToken(l, "[WARN]") || StartsWithToken(l, "[ERROR]") || StartsWithToken(l, "[DEBUG]"))
            return false;

        int cpos = l.IndexOf((byte)':');
        if (cpos <= 0 || cpos > Math.Min(40, l.Length - 1)) return false;
        if (cpos + 1 < l.Length && !(l[cpos + 1] == (byte)' ' || l[cpos + 1] == (byte)'\t')) return false;

        bool hasAlpha = false;
        for (int i = 0; i < cpos; i++)
        {
            byte c = l[i];
            if (char.IsLetter((char)c))
            {
                hasAlpha = true;
                continue;
            }

            if (char.IsDigit((char)c) || c == (byte)' ' || c == (byte)'-')
                continue;

            return false;
        }

        return hasAlpha;
    }

    private static bool LooksLikeSyslogLine(ReadOnlySpan<byte> l)
    {
        if (l.Length < 16) return false;

        int i = 0;
        while (i < l.Length && char.IsWhiteSpace((char)l[i])) i++;
        if (i + 15 >= l.Length) return false;

        if (!LooksLikeSyslogMonth(l.Slice(i, 3))) return false;
        i += 3;

        if (i >= l.Length || l[i] != (byte)' ') return false;
        while (i < l.Length && l[i] == (byte)' ') i++;

        int dayDigits = 0;
        while (i < l.Length && dayDigits < 2 && IsDigit(l[i]))
        {
            i++;
            dayDigits++;
        }
        if (dayDigits < 1 || i >= l.Length || l[i] != (byte)' ') return false;
        while (i < l.Length && l[i] == (byte)' ') i++;

        if (i + 7 >= l.Length) return false;
        if (!(IsDigit(l[i]) && IsDigit(l[i + 1]) && l[i + 2] == (byte)':' &&
              IsDigit(l[i + 3]) && IsDigit(l[i + 4]) && l[i + 5] == (byte)':' &&
              IsDigit(l[i + 6]) && IsDigit(l[i + 7])))
            return false;
        i += 8;

        if (i >= l.Length || l[i] != (byte)' ') return false;
        while (i < l.Length && l[i] == (byte)' ') i++;

        int hostStart = i;
        while (i < l.Length && !char.IsWhiteSpace((char)l[i]))
        {
            byte c = l[i];
            if (!(char.IsLetterOrDigit((char)c) || c == (byte)'.' || c == (byte)'-' || c == (byte)'_'))
                return false;
            i++;
        }
        if (i == hostStart || i >= l.Length) return false;
        while (i < l.Length && l[i] == (byte)' ') i++;
        if (i >= l.Length) return false;

        int colon = l.Slice(i).IndexOf((byte)':');
        return colon > 0 && colon < 48;
    }

    private static bool LooksLikeSyslogMonth(ReadOnlySpan<byte> token)
    {
        return token.Length == 3 &&
               (StartsWithToken(token, "Jan") ||
                StartsWithToken(token, "Feb") ||
                StartsWithToken(token, "Mar") ||
                StartsWithToken(token, "Apr") ||
                StartsWithToken(token, "May") ||
                StartsWithToken(token, "Jun") ||
                StartsWithToken(token, "Jul") ||
                StartsWithToken(token, "Aug") ||
                StartsWithToken(token, "Sep") ||
                StartsWithToken(token, "Oct") ||
                StartsWithToken(token, "Nov") ||
                StartsWithToken(token, "Dec"));
    }

    private static bool LooksLikeEmailText(ReadOnlySpan<byte> head)
    {
        int headerCount = 0;
        int identityHeaders = 0;
        bool hasMimeVersion = false;
        bool hasContentType = false;
        bool sawSeparator = false;

        int lineStart = 0;
        int scanned = 0;
        for (int i = 0; i < head.Length && scanned < 24; i++)
        {
            if (head[i] != (byte)'\n' && i != head.Length - 1) continue;

            int end = head[i] == (byte)'\n' ? i : i + 1;
            var line = TrimBytes(head.Slice(lineStart, Math.Max(0, end - lineStart)));
            lineStart = i + 1;
            scanned++;

            if (line.Length == 0)
            {
                if (headerCount >= 2)
                {
                    sawSeparator = true;
                    break;
                }
                continue;
            }

            var headerKind = GetEmailHeaderKind(line);
            if (headerKind == 0)
            {
                if (headerCount >= 2) break;
                return false;
            }

            headerCount++;
            if (headerKind == 1) identityHeaders++;
            if (headerKind == 2) hasMimeVersion = true;
            if (headerKind == 3) hasContentType = true;
        }

        if (headerCount < 2) return false;
        if (!sawSeparator) return false;
        if (identityHeaders >= 1) return true;
        return hasMimeVersion && hasContentType && headerCount >= 3;
    }

    private static int GetEmailHeaderKind(ReadOnlySpan<byte> line)
    {
        if (line.Length < 3) return 0;
        if (StartsWithToken(line, "From:")) return 1;
        if (StartsWithToken(line, "To:")) return 1;
        if (StartsWithToken(line, "Cc:")) return 1;
        if (StartsWithToken(line, "Bcc:")) return 1;
        if (StartsWithToken(line, "Subject:")) return 1;
        if (StartsWithToken(line, "Date:")) return 1;
        if (StartsWithToken(line, "Reply-To:")) return 1;
        if (StartsWithToken(line, "Sender:")) return 1;
        if (StartsWithToken(line, "Message-ID:")) return 1;
        if (StartsWithToken(line, "MIME-Version:")) return 2;
        if (StartsWithToken(line, "Content-Type:")) return 3;
        if (StartsWithToken(line, "Content-Transfer-Encoding:")) return 4;
        if (StartsWithToken(line, "Content-Disposition:")) return 4;
        if (StartsWithToken(line, "Return-Path:")) return 4;
        if (StartsWithToken(line, "Received:")) return 4;
        return 0;
    }

    private static bool LooksLikeSingleLineDelimitedRecord(ReadOnlySpan<byte> line, byte separator)
    {
        if (line.Length == 0) return false;

        int tokens = 0;
        int dataLikeTokens = 0;
        int pathLikeTokens = 0;
        int assignmentTokens = 0;
        int flagLikeTokens = 0;
        int start = 0;

        for (int i = 0; i <= line.Length; i++)
        {
            if (i != line.Length && line[i] != separator) continue;

            var token = TrimBytes(line.Slice(start, i - start));
            start = i + 1;
            if (token.Length == 0) continue;

            tokens++;
            if (LooksLikeDelimitedPathToken(token)) pathLikeTokens++;
            if (LooksLikeDelimitedAssignmentToken(token)) assignmentTokens++;
            if (LooksLikeDelimitedFlagToken(token)) flagLikeTokens++;
            if (LooksLikeDelimitedDataToken(token)) dataLikeTokens++;
        }

        if (tokens < 3) return false;
        if (pathLikeTokens >= 2) return false;
        if (assignmentTokens >= 2) return false;
        if (flagLikeTokens >= 2) return false;
        if (separator == (byte)';' && assignmentTokens >= 1 && pathLikeTokens >= 1) return false;

        return dataLikeTokens >= 2;
    }

    private static bool LooksLikeDelimitedPathToken(ReadOnlySpan<byte> token)
    {
        if (token.Length < 2) return false;

        if (token.Length >= 3 &&
            char.IsLetter((char)token[0]) &&
            token[1] == (byte)':' &&
            (token[2] == (byte)'\\' || token[2] == (byte)'/'))
            return true;

        if (token.Length >= 2 &&
            token[0] == (byte)'\\' &&
            token[1] == (byte)'\\')
            return true;

        int slashCount = 0;
        for (int i = 0; i < token.Length; i++)
        {
            if (token[i] == (byte)'\\' || token[i] == (byte)'/')
                slashCount++;
        }

        if (slashCount >= 2) return true;
        if (IndexOfToken(token, "http://") >= 0 || IndexOfToken(token, "https://") >= 0) return true;
        return false;
    }

    private static bool LooksLikeDelimitedAssignmentToken(ReadOnlySpan<byte> token)
    {
        int eq = token.IndexOf((byte)'=');
        if (eq <= 0 || eq >= token.Length - 1) return false;

        for (int i = 0; i < eq; i++)
        {
            byte c = token[i];
            if (!(char.IsLetterOrDigit((char)c) || c == (byte)'_' || c == (byte)'-' || c == (byte)'.'))
                return false;
        }

        return true;
    }

    private static bool LooksLikeDelimitedFlagToken(ReadOnlySpan<byte> token)
    {
        if (token.Length < 2) return false;
        if ((token[0] == (byte)'-' || token[0] == (byte)'/') && char.IsLetter((char)token[1]))
            return true;
        return false;
    }

    private static bool LooksLikeDelimitedDataToken(ReadOnlySpan<byte> token)
    {
        if (token.Length == 0) return false;
        if (LooksLikeDelimitedPathToken(token)) return false;
        if (LooksLikeDelimitedAssignmentToken(token)) return false;
        if (LooksLikeDelimitedFlagToken(token)) return false;

        bool hasAlphaNum = false;
        for (int i = 0; i < token.Length; i++)
        {
            byte c = token[i];
            if (char.IsLetterOrDigit((char)c))
            {
                hasAlphaNum = true;
                continue;
            }

            if (c == (byte)' ' || c == (byte)'_' || c == (byte)'-' || c == (byte)'.' || c == (byte)'"' || c == (byte)'\'' || c == (byte)'(' || c == (byte)')')
                continue;

            return false;
        }

        return hasAlphaNum;
    }

    private static int CountPowerShellDataFileKeys(string s)
    {
        if (string.IsNullOrWhiteSpace(s)) return 0;

        string[] keys =
        {
            "RootModule",
            "ModuleVersion",
            "GUID",
            "Author",
            "CompanyName",
            "Copyright",
            "Description",
            "PowerShellVersion",
            "CompatiblePSEditions",
            "FunctionsToExport",
            "CmdletsToExport",
            "AliasesToExport",
            "VariablesToExport",
            "NestedModules",
            "RequiredModules",
            "RequiredAssemblies",
            "ScriptsToProcess",
            "FormatsToProcess",
            "TypesToProcess",
            "FileList",
            "PrivateData"
        };

        int found = 0;
        foreach (var key in keys)
        {
            if (s.IndexOf(key + " =", StringComparison.OrdinalIgnoreCase) >= 0)
                found++;
        }

        return found;
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
            long timeoutTicks = TimeoutHelpers.GetTimeoutTicks(timeoutMs);
            var sw = timeoutTicks > 0 ? System.Diagnostics.Stopwatch.StartNew() : null;
            using var reader = System.Xml.XmlReader.Create(new System.IO.StringReader(xml), settings);
            while (reader.Read())
            {
                if (TimeoutHelpers.IsExpired(sw, timeoutTicks)) return false;
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
