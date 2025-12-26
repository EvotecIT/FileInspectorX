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
        bool ok = TryValidateCore(s);
        if (!ok && Settings.DetectionLogCandidates)
            Settings.Logger.WriteDebug("json:validate failed");
        return ok;
    }

    private static bool TryValidateCore(string s)
    {
        var span = s.AsSpan().Trim();
        if (span.Length < 2) return false;
        char first = span[0];
        char last = span[span.Length - 1];
        if (!((first == '{' || first == '[') && (last == '}' || last == ']')))
            return false;
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
}
