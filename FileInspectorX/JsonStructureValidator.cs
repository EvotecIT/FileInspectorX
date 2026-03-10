namespace FileInspectorX;

/// <summary>
/// Lightweight structural validation for JSON text.
/// </summary>
internal static class JsonStructureValidator
{
    internal static bool TryValidate(string s, int byteCount, out bool skipped)
    {
        skipped = false;
        if (string.IsNullOrWhiteSpace(s)) return false;
        if (!Settings.JsonStructuralValidationEnabled)
        {
            skipped = true;
            if (Settings.DetectionLogCandidates)
                Settings.Logger.WriteDebug("json:validate skipped (disabled)");
            return false;
        }
        int max = Settings.JsonStructuralValidationMaxBytes;
        if (max > 0)
        {
            int size = byteCount > 0 ? byteCount : s.Length;
            if (size > max)
            {
                skipped = true;
                if (Settings.DetectionLogCandidates)
                    Settings.Logger.WriteDebug($"json:validate skipped (size {size} > {max})");
                return false;
            }
        }
        int timeoutMs = Settings.JsonStructuralValidationTimeoutMs;
        long timeoutTicks = TimeoutHelpers.GetTimeoutTicks(timeoutMs);
        System.Diagnostics.Stopwatch? sw = timeoutTicks > 0 ? System.Diagnostics.Stopwatch.StartNew() : null;
        bool ok = TryValidateCore(s, sw, timeoutTicks, out bool timedOut);
        if (timedOut)
        {
            skipped = true;
            if (Settings.DetectionLogCandidates)
                Settings.Logger.WriteDebug("json:validate skipped (timeout)");
            return false;
        }
        if (!ok && Settings.DetectionLogCandidates)
            Settings.Logger.WriteDebug("json:validate failed");
        return ok;
    }

    internal static bool TryValidateCoreForTest(string s, System.Diagnostics.Stopwatch? sw, long timeoutTicks, out bool timedOut)
        => TryValidateCore(s, sw, timeoutTicks, out timedOut);

    private static bool TryValidateCore(string s, System.Diagnostics.Stopwatch? sw, long timeoutTicks, out bool timedOut)
    {
        timedOut = false;
        string text = s.Trim();
        if (text.Length < 2) return false;
        if (text[0] != '{' && text[0] != '[') return false;

        int i = 0;
        SkipWhitespace(ref i, text, sw, timeoutTicks, ref timedOut);
        if (timedOut) return false;
        if (!ParseValue(ref i, text, sw, timeoutTicks, ref timedOut)) return false;
        SkipWhitespace(ref i, text, sw, timeoutTicks, ref timedOut);
        return !timedOut && i == text.Length;
    }

    private static void SkipWhitespace(ref int i, string text, System.Diagnostics.Stopwatch? sw, long timeoutTicks, ref bool timedOut)
    {
        while (i < text.Length)
        {
            if ((i & 0x3FF) == 0 && TimeoutHelpers.IsExpired(sw, timeoutTicks))
            {
                timedOut = true;
                return;
            }

            char c = text[i];
            if (c != ' ' && c != '\t' && c != '\r' && c != '\n') break;
            i++;
        }
    }

    private static bool ParseValue(ref int i, string text, System.Diagnostics.Stopwatch? sw, long timeoutTicks, ref bool timedOut)
    {
        SkipWhitespace(ref i, text, sw, timeoutTicks, ref timedOut);
        if (timedOut || i >= text.Length) return false;

        switch (text[i])
        {
            case '{':
                return ParseObject(ref i, text, sw, timeoutTicks, ref timedOut);
            case '[':
                return ParseArray(ref i, text, sw, timeoutTicks, ref timedOut);
            case '"':
                return ParseString(ref i, text, sw, timeoutTicks, ref timedOut);
            case 't':
                return ConsumeLiteral(ref i, text, "true");
            case 'f':
                return ConsumeLiteral(ref i, text, "false");
            case 'n':
                return ConsumeLiteral(ref i, text, "null");
            default:
                return ParseNumber(ref i, text);
        }
    }

    private static bool ParseObject(ref int i, string text, System.Diagnostics.Stopwatch? sw, long timeoutTicks, ref bool timedOut)
    {
        i++;
        SkipWhitespace(ref i, text, sw, timeoutTicks, ref timedOut);
        if (timedOut || i > text.Length) return false;
        if (i < text.Length && text[i] == '}')
        {
            i++;
            return true;
        }

        while (i < text.Length)
        {
            if (!ParseString(ref i, text, sw, timeoutTicks, ref timedOut)) return false;
            SkipWhitespace(ref i, text, sw, timeoutTicks, ref timedOut);
            if (timedOut || i >= text.Length || text[i] != ':') return false;
            i++;
            if (!ParseValue(ref i, text, sw, timeoutTicks, ref timedOut)) return false;
            SkipWhitespace(ref i, text, sw, timeoutTicks, ref timedOut);
            if (timedOut || i >= text.Length) return false;
            if (text[i] == '}')
            {
                i++;
                return true;
            }
            if (text[i] != ',') return false;
            i++;
            SkipWhitespace(ref i, text, sw, timeoutTicks, ref timedOut);
            if (timedOut) return false;
        }

        return false;
    }

    private static bool ParseArray(ref int i, string text, System.Diagnostics.Stopwatch? sw, long timeoutTicks, ref bool timedOut)
    {
        i++;
        SkipWhitespace(ref i, text, sw, timeoutTicks, ref timedOut);
        if (timedOut || i > text.Length) return false;
        if (i < text.Length && text[i] == ']')
        {
            i++;
            return true;
        }

        while (i < text.Length)
        {
            if (!ParseValue(ref i, text, sw, timeoutTicks, ref timedOut)) return false;
            SkipWhitespace(ref i, text, sw, timeoutTicks, ref timedOut);
            if (timedOut || i >= text.Length) return false;
            if (text[i] == ']')
            {
                i++;
                return true;
            }
            if (text[i] != ',') return false;
            i++;
            SkipWhitespace(ref i, text, sw, timeoutTicks, ref timedOut);
            if (timedOut) return false;
        }

        return false;
    }

    private static bool ParseString(ref int i, string text, System.Diagnostics.Stopwatch? sw, long timeoutTicks, ref bool timedOut)
    {
        if (i >= text.Length || text[i] != '"') return false;
        i++;
        while (i < text.Length)
        {
            if ((i & 0x3FF) == 0 && TimeoutHelpers.IsExpired(sw, timeoutTicks))
            {
                timedOut = true;
                return false;
            }

            char c = text[i++];
            if (c == '"') return true;
            if (c == '\\')
            {
                if (i >= text.Length) return false;
                char esc = text[i++];
                if (esc == 'u')
                {
                    for (int j = 0; j < 4; j++)
                    {
                        if (i >= text.Length || !IsHex(text[i++])) return false;
                    }
                }
                else if (esc != '"' && esc != '\\' && esc != '/' && esc != 'b' && esc != 'f' && esc != 'n' && esc != 'r' && esc != 't')
                {
                    return false;
                }
                continue;
            }

            if (c < 0x20) return false;
        }

        return false;
    }

    private static bool ParseNumber(ref int i, string text)
    {
        int start = i;
        if (text[i] == '-') i++;
        if (i >= text.Length) return false;

        if (text[i] == '0')
        {
            i++;
            if (i < text.Length && char.IsDigit(text[i])) return false;
        }
        else
        {
            if (!char.IsDigit(text[i])) return false;
            while (i < text.Length && char.IsDigit(text[i])) i++;
        }

        if (i < text.Length && text[i] == '.')
        {
            i++;
            if (i >= text.Length || !char.IsDigit(text[i])) return false;
            while (i < text.Length && char.IsDigit(text[i])) i++;
        }

        if (i < text.Length && (text[i] == 'e' || text[i] == 'E'))
        {
            i++;
            if (i < text.Length && (text[i] == '+' || text[i] == '-')) i++;
            if (i >= text.Length || !char.IsDigit(text[i])) return false;
            while (i < text.Length && char.IsDigit(text[i])) i++;
        }

        return i > start;
    }

    private static bool ConsumeLiteral(ref int i, string text, string literal)
    {
        if (i + literal.Length > text.Length) return false;
        for (int j = 0; j < literal.Length; j++)
        {
            if (text[i + j] != literal[j]) return false;
        }

        i += literal.Length;
        return true;
    }

    private static bool IsHex(char c)
    {
        return (c >= '0' && c <= '9') ||
               (c >= 'a' && c <= 'f') ||
               (c >= 'A' && c <= 'F');
    }
}
