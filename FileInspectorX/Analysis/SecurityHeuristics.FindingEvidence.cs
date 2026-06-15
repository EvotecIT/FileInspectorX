namespace FileInspectorX;

internal static partial class SecurityHeuristics
{
    private const int MaxFindingEvidence = 48;
    private const int MaxFindingSnippetChars = 180;

    internal static IReadOnlyList<FindingEvidence> AssessScriptEvidenceFromText(string? text, string? declaredExt)
    {
        var evidence = new List<FindingEvidence>(16);
        try
        {
            if (!Settings.SecurityScanScripts || string.IsNullOrEmpty(text))
            {
                return evidence;
            }

            var lines = SplitLogicalLines(text!);

            foreach (var rule in ScriptFindingRuleCatalog.Rules)
            {
                AddRuleEvidence(evidence, lines, rule);
            }

            if (declaredExt is "ps1" or "psm1" or "psd1" or "sh" or "bash" or "zsh" or "bat" or "cmd" or "js" or "rb" or "py" or "lua")
            {
                AddEvidence(evidence, "script:dangerous-kind", null, null, null, null, null, null);
            }
        }
        catch
        {
        }

        return evidence;
    }

    private static IReadOnlyList<string> SplitLines(string text)
        => text.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');

    private static IReadOnlyList<ScriptEvidenceLine> SplitLogicalLines(string text)
    {
        var physicalLines = SplitLines(text);
        var logicalLines = new List<ScriptEvidenceLine>(physicalLines.Count);
        var builder = new System.Text.StringBuilder();
        var startLine = 1;
        var continuing = false;

        for (var index = 0; index < physicalLines.Count; index++)
        {
            var line = physicalLines[index] ?? string.Empty;
            var trimmedEnd = line.TrimEnd();
            var hasContinuation = EndsWithOddBacktickCount(trimmedEnd);
            var segment = hasContinuation ? trimmedEnd.Substring(0, trimmedEnd.Length - 1) : line;

            if (!continuing)
            {
                startLine = index + 1;
                builder.Clear();
            }

            if (builder.Length > 0)
            {
                builder.Append(' ');
            }

            builder.Append(segment.Trim());

            if (hasContinuation)
            {
                continuing = true;
                continue;
            }

            logicalLines.Add(new ScriptEvidenceLine(builder.ToString(), startLine));
            continuing = false;
        }

        if (continuing)
        {
            logicalLines.Add(new ScriptEvidenceLine(builder.ToString(), startLine));
        }

        return logicalLines;
    }

    private static bool EndsWithOddBacktickCount(string value)
    {
        var count = 0;
        for (var index = value.Length - 1; index >= 0 && value[index] == '`'; index--)
        {
            count++;
        }

        return count % 2 == 1;
    }

    private static void AddRuleEvidence(
        List<FindingEvidence> evidence,
        IReadOnlyList<ScriptEvidenceLine> lines,
        ScriptFindingRule rule)
    {
        if (evidence.Count >= MaxFindingEvidence || evidence.Any(item => string.Equals(item.Code, rule.Code, StringComparison.OrdinalIgnoreCase)))
        {
            return;
        }

        int totalHits = 0;
        var sampleLines = new List<int>(3);
        var sampleSnippets = new List<string>(3);

        for (var index = 0; index < lines.Count; index++)
        {
            var entry = lines[index];
            var line = entry.Text ?? string.Empty;
            if (rule.ExcludedAny != null && ContainsAnyIgnoreCase(line, rule.ExcludedAny))
            {
                continue;
            }

            if (rule.RequiredAny != null && !ContainsAnyIgnoreCase(line, rule.RequiredAny))
            {
                continue;
            }

            if (rule.RequiredAll != null && !ContainsAllIgnoreCase(line, rule.RequiredAll))
            {
                continue;
            }

            if (IsDefenderPreferenceRule(rule) && !HasDefenderWeakeningPreference(line))
            {
                continue;
            }

            var hitsInLine = CountAnyOccurrencesIgnoreCase(line, rule.Any);
            if (hitsInLine <= 0)
            {
                continue;
            }

            totalHits += hitsInLine;
            if (sampleLines.Count < 3)
            {
                var snippet = rule.CollectSnippets ? SanitizeSnippet(line) : null;
                if (rule.CollectSnippets && snippet != null)
                {
                    sampleLines.Add(entry.LineNumber);
                    sampleSnippets.Add(snippet);
                }
                else if (!rule.CollectSnippets)
                {
                    sampleLines.Add(entry.LineNumber);
                }
            }
        }

        if (totalHits >= rule.MinHitsInFile)
        {
            AddEvidence(
                evidence,
                rule.Code,
                sampleLines.Count > 0 ? sampleLines[0] : null,
                sampleSnippets.Count > 0 ? sampleSnippets[0] : null,
                totalHits,
                sampleLines,
                sampleSnippets,
                rule.BehaviorTags);
        }
    }

    private static void AddEvidence(
        List<FindingEvidence> evidence,
        string code,
        int? line,
        string? snippet,
        int? hitCount,
        IReadOnlyList<int>? lines,
        IReadOnlyList<string>? snippets,
        IReadOnlyList<string>? behaviorTags)
    {
        if (evidence.Count >= MaxFindingEvidence || string.IsNullOrWhiteSpace(code))
        {
            return;
        }

        if (evidence.Any(item => string.Equals(item.Code, code, StringComparison.OrdinalIgnoreCase)))
        {
            return;
        }

        evidence.Add(new FindingEvidence
        {
            Code = code,
            Line = line,
            Snippet = string.IsNullOrWhiteSpace(snippet) ? null : snippet,
            SourceTag = line.HasValue ? "script:line" : "script:metadata",
            HitCount = hitCount,
            Lines = lines != null && lines.Count > 0 ? lines : null,
            Snippets = snippets != null && snippets.Count > 0 ? snippets : null,
            BehaviorTags = behaviorTags != null && behaviorTags.Count > 0 ? behaviorTags : null
        });
    }

    private static int CountAnyOccurrencesIgnoreCase(string value, IEnumerable<string> needles)
    {
        var count = 0;
        foreach (var needle in needles)
        {
            if (string.IsNullOrEmpty(needle))
            {
                continue;
            }

            var index = value.IndexOf(needle, StringComparison.OrdinalIgnoreCase);
            while (index >= 0)
            {
                count++;
                index = value.IndexOf(needle, index + needle.Length, StringComparison.OrdinalIgnoreCase);
            }
        }

        return count;
    }

    private static bool ContainsAllIgnoreCase(string value, IEnumerable<string> needles)
    {
        foreach (var needle in needles)
        {
            if (!string.IsNullOrEmpty(needle) &&
                value.IndexOf(needle, StringComparison.OrdinalIgnoreCase) < 0)
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsDefenderPreferenceRule(ScriptFindingRule rule)
        => string.Equals(rule.Code, "script:defender-tamper", StringComparison.OrdinalIgnoreCase) &&
           ContainsAnyIgnoreCase(string.Join("\n", rule.Any), new[] { "set-mppreference", "add-mppreference" });

    private static bool HasDefenderWeakeningPreference(string line)
    {
        if (ContainsAnyIgnoreCase(line, new[] { "-exclusionpath", "-exclusionextension", "-exclusionprocess" }))
        {
            return true;
        }

        foreach (var parameter in new[]
        {
            "-disablerealtimemonitoring",
            "-disableioavprotection",
            "-disablebehaviormonitoring",
            "-disableblockatfirstseen",
            "-disableintrusionpreventionsystem",
            "-disablescriptscanning"
        })
        {
            if (HasTrueOrImplicitPowerShellBoolean(line, parameter))
            {
                return true;
            }
        }

        return false;
    }

    private static bool HasTrueOrImplicitPowerShellBoolean(string value, string parameter)
    {
        var index = value.IndexOf(parameter, StringComparison.OrdinalIgnoreCase);
        while (index >= 0)
        {
            var cursor = index + parameter.Length;
            while (cursor < value.Length && char.IsWhiteSpace(value[cursor]))
            {
                cursor++;
            }

            if (cursor < value.Length && value[cursor] == ':')
            {
                cursor++;
                while (cursor < value.Length && char.IsWhiteSpace(value[cursor]))
                {
                    cursor++;
                }
            }

            if (!SpanEqualsIgnoreCase(value, cursor, "$false") &&
                !SpanEqualsIgnoreCase(value, cursor, "false"))
            {
                return true;
            }

            index = value.IndexOf(parameter, index + parameter.Length, StringComparison.OrdinalIgnoreCase);
        }

        return false;
    }

    private static bool SpanEqualsIgnoreCase(string value, int start, string token)
    {
        if (start < 0 || start + token.Length > value.Length)
        {
            return false;
        }

        return string.Compare(value, start, token, 0, token.Length, StringComparison.OrdinalIgnoreCase) == 0;
    }

    private static string? SanitizeSnippet(string? line)
    {
        if (string.IsNullOrWhiteSpace(line))
        {
            return null;
        }

        var snippet = line!.Trim();
        if (snippet.Length > MaxFindingSnippetChars)
        {
            snippet = snippet.Substring(0, MaxFindingSnippetChars - 3) + "...";
        }

        snippet = RedactUrlUserInfo(snippet);

        foreach (var token in new[] { "password", "passwd", "pwd", "secret", "token", "apikey", "api_key", "x-api-key", "authorization", "access_token", "access-token", "auth_token", "credential", "clientsecret", "privatekey", "private_key", "private-key" })
        {
            snippet = RedactAssignmentValue(snippet, token);
        }

        snippet = RedactBearerCredential(snippet);
        foreach (var parameter in new[] { "sig", "signature", "se", "sp", "spr", "sr", "sv", "x-amz-signature", "x-goog-signature" })
        {
            snippet = RedactQueryParameterValue(snippet, parameter);
        }

        return snippet;
    }

    private static string RedactUrlUserInfo(string value)
    {
        var searchStart = 0;
        while (searchStart < value.Length)
        {
            var schemeEnd = value.IndexOf("://", searchStart, StringComparison.Ordinal);
            if (schemeEnd < 0)
            {
                break;
            }

            var authorityStart = schemeEnd + 3;
            var authorityEnd = authorityStart;
            while (authorityEnd < value.Length &&
                   !char.IsWhiteSpace(value[authorityEnd]) &&
                   value[authorityEnd] != '/' &&
                   value[authorityEnd] != '?' &&
                   value[authorityEnd] != '#' &&
                   value[authorityEnd] != '\'' &&
                   value[authorityEnd] != '"' &&
                   value[authorityEnd] != ')' &&
                   value[authorityEnd] != ']' &&
                   value[authorityEnd] != '}')
            {
                authorityEnd++;
            }

            var at = authorityEnd > authorityStart
                ? value.LastIndexOf('@', authorityEnd - 1, authorityEnd - authorityStart)
                : -1;
            if (at > authorityStart)
            {
                value = value.Substring(0, authorityStart) + "<redacted>" + value.Substring(at);
                searchStart = authorityStart + "<redacted>".Length + 1;
            }
            else
            {
                searchStart = Math.Max(authorityEnd + 1, authorityStart + 1);
            }
        }

        return value;
    }

    private static string RedactQueryParameterValue(string value, string parameter)
    {
        var index = value.IndexOf(parameter + "=", StringComparison.OrdinalIgnoreCase);
        while (index >= 0)
        {
            if (index > 0 && value[index - 1] != '?' && value[index - 1] != '&')
            {
                index = value.IndexOf(parameter + "=", index + parameter.Length + 1, StringComparison.OrdinalIgnoreCase);
                continue;
            }

            var start = index + parameter.Length + 1;
            var end = start;
            while (end < value.Length &&
                   value[end] != '&' &&
                   !char.IsWhiteSpace(value[end]) &&
                   value[end] != '\'' &&
                   value[end] != '"' &&
                   value[end] != ')' &&
                   value[end] != ']' &&
                   value[end] != '}')
            {
                end++;
            }

            if (end > start)
            {
                value = value.Substring(0, start) + "<redacted>" + value.Substring(end);
                index = value.IndexOf(parameter + "=", start + "<redacted>".Length, StringComparison.OrdinalIgnoreCase);
            }
            else
            {
                index = value.IndexOf(parameter + "=", index + parameter.Length + 1, StringComparison.OrdinalIgnoreCase);
            }
        }

        return value;
    }

    private static string RedactBearerCredential(string value)
    {
        var index = value.IndexOf("bearer", StringComparison.OrdinalIgnoreCase);
        while (index >= 0)
        {
            var start = index + "bearer".Length;
            while (start < value.Length && char.IsWhiteSpace(value[start]))
            {
                start++;
            }

            var end = start;
            while (end < value.Length &&
                   !char.IsWhiteSpace(value[end]) &&
                   value[end] != ';' &&
                   value[end] != ',' &&
                   value[end] != ')' &&
                   value[end] != ']' &&
                   value[end] != '}')
            {
                end++;
            }

            if (end > start)
            {
                value = value.Substring(0, start) + "<redacted>" + value.Substring(end);
                index = value.IndexOf("bearer", start + "<redacted>".Length, StringComparison.OrdinalIgnoreCase);
            }
            else
            {
                index = value.IndexOf("bearer", index + "bearer".Length, StringComparison.OrdinalIgnoreCase);
            }
        }

        return value;
    }

    private static string RedactAssignmentValue(string value, string key)
    {
        var index = value.IndexOf(key, StringComparison.OrdinalIgnoreCase);
        while (index >= 0)
        {
            var separator = FindAssignmentSeparator(value, index + key.Length);
            if (separator < 0)
            {
                index = value.IndexOf(key, index + key.Length, StringComparison.OrdinalIgnoreCase);
                continue;
            }

            var end = separator + 1;
            while (end < value.Length && char.IsWhiteSpace(value[end]))
            {
                end++;
            }

            var quote = end < value.Length && (value[end] == '\'' || value[end] == '"') ? value[end++] : '\0';
            var valueEnd = end;
            while (valueEnd < value.Length)
            {
                if (quote != '\0')
                {
                    if (value[valueEnd] == quote)
                    {
                        break;
                    }
                }
                else if (char.IsWhiteSpace(value[valueEnd]) || value[valueEnd] == ';' || value[valueEnd] == ',' || value[valueEnd] == ')')
                {
                    break;
                }

                valueEnd++;
            }

            if (valueEnd > end)
            {
                value = value.Substring(0, end) + "<redacted>" + value.Substring(valueEnd);
                index = value.IndexOf(key, end + "<redacted>".Length, StringComparison.OrdinalIgnoreCase);
            }
            else
            {
                index = value.IndexOf(key, index + key.Length, StringComparison.OrdinalIgnoreCase);
            }
        }

        return value;
    }

    private static int FindAssignmentSeparator(string value, int start)
    {
        for (var i = start; i < value.Length && i < start + 24; i++)
        {
            if (value[i] == '=' || value[i] == ':')
            {
                return i;
            }

            if (!char.IsWhiteSpace(value[i]) &&
                value[i] != '-' &&
                value[i] != '_' &&
                value[i] != '\'' &&
                value[i] != '"')
            {
                return -1;
            }
        }

        return -1;
    }

    private readonly struct ScriptEvidenceLine
    {
        internal ScriptEvidenceLine(string text, int lineNumber)
        {
            Text = text;
            LineNumber = lineNumber;
        }

        internal string Text { get; }

        internal int LineNumber { get; }
    }
}
