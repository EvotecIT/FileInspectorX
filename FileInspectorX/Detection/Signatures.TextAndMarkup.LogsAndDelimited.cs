namespace FileInspectorX;

internal static partial class Signatures
{
    private static bool TryDetectLogAndDelimitedText(in TextContext ctx, out ContentTypeDetectionResult? result)
    {
        result = null;
        var head = ctx.Head;
        var headStr = ctx.HeadStr;
        var headLower = ctx.HeadLower;
        bool scriptCues = ctx.ScriptCues;
        bool declaredLog = ctx.DeclaredLog;
        bool declaredMd = ctx.DeclaredMd;
        bool declaredInf = ctx.DeclaredInf;
        bool jsCues = ctx.JsCues;
        bool shShebang = ctx.ShShebang;
        bool batCues = ctx.BatCues;

        // Quick Windows DNS log check very early (before generic log heuristics)
        if (LogHeuristics.LooksLikeDnsLog(headLower))
        {
            result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = "Medium", Reason = "text:log-dns", ReasonDetails = "log:dns" };
            return true;
        }

        // Delimiter heuristics shared by CSV/TSV + log detection
        var span = head;
        int nl = head.IndexOf((byte)'\n'); if (nl < 0) nl = head.Length;
        var line1 = span.Slice(0, nl);
        var rest = span.Slice(Math.Min(nl + 1, span.Length));
        int nl2 = rest.IndexOf((byte)'\n'); if (nl2 < 0) nl2 = rest.Length;
        var line2 = rest.Slice(0, nl2);

        // LOG heuristic (timestamps/levels) promoted ahead of CSV/Markdown to avoid mislabels
        bool logCues = LooksLikeTimestamp(line1) || LooksLikeTimestamp(line2) || StartsWithLevelToken(line1) || StartsWithLevelToken(line2);
        if (!scriptCues)
        {
            if (LooksLikeTimestamp(line1) && LooksLikeTimestamp(line2))
            {
                result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = "Low", Reason = "text:log", ReasonDetails = "log:timestamps-2" };
                return true;
            }

            int levelCount = 0;
            if (StartsWithLevelToken(line1)) levelCount++;
            if (StartsWithLevelToken(line2)) levelCount++;
            // include up to two more lines
            var rest2 = rest.Slice(Math.Min(nl2 + 1, rest.Length));
            int nl3 = rest2.IndexOf((byte)'\n'); if (nl3 < 0) nl3 = rest2.Length; var line3 = rest2.Slice(0, nl3);
            var rest3 = rest2.Slice(Math.Min(nl3 + 1, rest2.Length));
            int nl4 = rest3.IndexOf((byte)'\n'); if (nl4 < 0) nl4 = rest3.Length; var line4 = rest3.Slice(0, nl4);
            if (StartsWithLevelToken(line3)) levelCount++;
            if (StartsWithLevelToken(line4)) levelCount++;
            int tsCount = 0; if (LooksLikeTimestamp(line1)) tsCount++; if (LooksLikeTimestamp(line2)) tsCount++; if (LooksLikeTimestamp(line3)) tsCount++; if (LooksLikeTimestamp(line4)) tsCount++;
            if (tsCount >= 2)
            {
                result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = "Low", Reason = "text:log", ReasonDetails = "log:timestamps-multi" };
                return true;
            }
            if (levelCount >= 2 || ((LooksLikeTimestamp(line1) || LooksLikeTimestamp(line2)) && levelCount >= 1))
            {
                // Boost confidence when we have both timestamps and levels across lines
                var conf = levelCount >= 2 && (LooksLikeTimestamp(line1) || LooksLikeTimestamp(line2)) ? "Medium" : "Low";
                result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = conf, Reason = "text:log-levels", ReasonDetails = levelCount >= 2 ? $"log:levels-{levelCount}" : "log:timestamp+level" };
                return true;
            }
            if (levelCount > 0) logCues = true;
            if (declaredLog && logCues)
            {
                result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = "Low", Reason = "text:log", ReasonDetails = "log:declared" };
                return true;
            }
        }

        // CSV/TSV/Delimited heuristics (look at first two lines) — also handle Excel 'sep=' directive and single-line CSV/TSV
        // Excel separator directive (first non-whitespace line like `sep=,` or `sep=;` or `sep=\t`)
        {
            string s = headStr.TrimStart('\ufeff', ' ', '\t', '\r', '\n');
            if (s.StartsWith("sep=", System.StringComparison.OrdinalIgnoreCase))
            {
                if (!logCues && !scriptCues)
                {
                    bool isTab = s.StartsWith("sep=\\t", System.StringComparison.OrdinalIgnoreCase) || (s.Length > 4 && s[4] == '\t');
                    if (isTab) { result = new ContentTypeDetectionResult { Extension = "tsv", MimeType = "text/tab-separated-values", Confidence = "Low", Reason = "text:tsv", ReasonDetails = "tsv:sep-directive" }; return true; }
                    else { result = new ContentTypeDetectionResult { Extension = "csv", MimeType = "text/csv", Confidence = "Low", Reason = "text:csv", ReasonDetails = "csv:sep-directive" }; return true; }
                }
            }
        }

        int commas1 = Count(line1, (byte)','); int commas2 = Count(line2, (byte)',');
        int semis1 = Count(line1, (byte)';'); int semis2 = Count(line2, (byte)';');
        int pipes1 = Count(line1, (byte)'|'); int pipes2 = Count(line2, (byte)'|');
        int tabs1 = Count(line1, (byte)'\t'); int tabs2 = Count(line2, (byte)'\t');
        if (!logCues && !scriptCues)
        {
            if ((commas1 >= 1 && commas2 >= 1 && Math.Abs(commas1 - commas2) <= 2) || (semis1 >= 1 && semis2 >= 1 && Math.Abs(semis1 - semis2) <= 2) || (pipes1 >= 1 && pipes2 >= 1 && Math.Abs(pipes1 - pipes2) <= 2)) { result = new ContentTypeDetectionResult { Extension = "csv", MimeType = "text/csv", Confidence = "Low", Reason = "text:csv", ReasonDetails = "csv:delimiter-repeat-2lines" }; return true; }
            if (tabs1 >= 1 && tabs2 >= 1 && Math.Abs(tabs1 - tabs2) <= 2) { result = new ContentTypeDetectionResult { Extension = "tsv", MimeType = "text/tab-separated-values", Confidence = "Low", Reason = "text:tsv", ReasonDetails = "tsv:tabs-2lines" }; return true; }
            if (line2.Length == 0 || (line2.Length == 0 && rest.Length == 0))
            {
                static int TokenCount(ReadOnlySpan<byte> l, byte sep)
                {
                    if (l.Length == 0) return 0;
                    int tokens = 1; for (int i = 0; i < l.Length; i++) if (l[i] == sep) tokens++; return tokens;
                }
                if (commas1 >= 2 && TokenCount(line1, (byte)',') >= 3) { result = new ContentTypeDetectionResult { Extension = "csv", MimeType = "text/csv", Confidence = "Low", Reason = "text:csv", ReasonDetails = "csv:single-line" }; return true; }
                if (semis1 >= 2 && TokenCount(line1, (byte)';') >= 3) { result = new ContentTypeDetectionResult { Extension = "csv", MimeType = "text/csv", Confidence = "Low", Reason = "text:csv", ReasonDetails = "csv:single-line" }; return true; }
                if (tabs1 >= 2 && TokenCount(line1, (byte)'\t') >= 3) { result = new ContentTypeDetectionResult { Extension = "tsv", MimeType = "text/tab-separated-values", Confidence = "Low", Reason = "text:tsv", ReasonDetails = "tsv:single-line" }; return true; }
            }
        }

        // INI/INF heuristic (guarded against PowerShell/type-accelerator patterns)
        {
            bool hasPsCues = HasPowerShellCues(head, headStr, headLower) || HasVerbNounCmdlet(headStr);
            if (!hasPsCues && !jsCues && !shShebang && !batCues)
            {
                bool hasSection = false;
                bool hasEquals = false;

                // Look for [Section] and key=value within the first few meaningful lines.
                // This avoids false positives when an INI file starts with comments/blank lines.
                int meaningfulLines = 0;
                int lineStart = 0;
                for (int i = 0; i < head.Length && meaningfulLines < 8; i++)
                {
                    if (head[i] == (byte)'\n' || i == head.Length - 1)
                    {
                        int end = head[i] == (byte)'\n' ? i : i + 1;
                        var raw = head.Slice(lineStart, Math.Max(0, end - lineStart));
                        lineStart = i + 1;
                        var line = TrimBytes(raw);
                        if (line.Length == 0) continue;

                        // Skip comment-only lines
                        if (line[0] == (byte)';' || line[0] == (byte)'#') continue;

                        if (!hasSection && LooksIniSectionLine(line)) hasSection = true;
                        if (!hasEquals)
                        {
                            int eq = line.IndexOf((byte)'=');
                            if (eq > 0) hasEquals = true;
                        }

                        meaningfulLines++;
                        if (hasSection && hasEquals) break;
                    }
                }

                if (hasSection && hasEquals)
                {
                    var ext = declaredInf ? "inf" : "ini";
                    result = new ContentTypeDetectionResult { Extension = ext, MimeType = "text/plain", Confidence = "Low", Reason = "text:ini", ReasonDetails = ext == "inf" ? "inf:section+equals" : "ini:section+equals" };
                    return true;
                }
            }
        }

        // Markdown quick cues (guarded to avoid scripts/logs; allow when declared .md)
        {
            var s = headStr; var sl = headLower;
            bool looksMd = sl.StartsWith("# ") || sl.Contains("\n# ") || sl.Contains("```") || sl.Contains("](");
            int mdCues = 0;
            if (sl.StartsWith("# ") || sl.Contains("\n# ")) mdCues++;
            if (sl.Contains("```")) mdCues++;
            if (sl.Contains("](")) mdCues++;
            if (sl.Contains("\n- ") || sl.StartsWith("- ") || sl.Contains("\n* ") || sl.StartsWith("* ")) mdCues++; // bullet list hint
            // Treat presence of a heading plus any additional non-empty line as another weak cue (without needing link/fence)
            if (mdCues == 1)
            {
                var lines = headStr.Split('\n');
                if (lines.Length >= 2 && lines[1].Trim().Length > 0) mdCues++;
            }
            if (looksMd)
            {
                // Do not classify as Markdown if strong PowerShell cues or log cues are present
                var okByCues = declaredMd ? mdCues >= 1 : mdCues >= 2;
                bool hasFence = sl.Contains("```");
                bool hasHeading = sl.StartsWith("# ") || sl.Contains("\n# ");
                bool mdStructural = hasFence || hasHeading;
                if (okByCues && !logCues && (!scriptCues || declaredMd || mdStructural))
                {
                    result = new ContentTypeDetectionResult { Extension = "md", MimeType = "text/markdown", Confidence = "Low", Reason = "text:md" };
                    return true;
                }
            }
        }

        // Windows well-known text logs: Firewall, Netlogon, Event Viewer text export
        if (!scriptCues)
        {
            if (LogHeuristics.LooksLikeFirewallLog(headLower)) { result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = "Medium", Reason = "text:log-firewall", ReasonDetails = "log:firewall" }; return true; }
            if (LogHeuristics.LooksLikeNetlogonLog(headLower, logCues)) { result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = "Medium", Reason = "text:log-netlogon", ReasonDetails = "log:netlogon" }; return true; }
            if (LogHeuristics.LooksLikeEventViewerTextExport(headLower)) { result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = "Medium", Reason = "text:event-txt", ReasonDetails = "log:event-txt" }; return true; }

            // Microsoft DHCP Server audit logs (similar to IIS/Firewall headers)
            if (LogHeuristics.LooksLikeDhcpLog(headLower)) { result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = "Medium", Reason = "text:log-dhcp", ReasonDetails = "log:dhcp" }; return true; }

            // Microsoft Exchange Message Tracking logs
            if (LogHeuristics.LooksLikeExchangeMessageTrackingLog(headLower)) { result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = "Medium", Reason = "text:log-exchange", ReasonDetails = "log:exchange" }; return true; }

            // Windows Defender textual logs (MpCmdRun outputs or Event Viewer text exports mentioning Defender)
            if (LogHeuristics.LooksLikeDefenderTextLog(headLower, logCues)) { result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = "Low", Reason = "text:log-defender", ReasonDetails = "log:defender" }; return true; }

            // SQL Server ERRORLOG text
            if (LogHeuristics.LooksLikeSqlErrorLog(headLower, logCues)) { result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = "Medium", Reason = "text:log-sql-errorlog", ReasonDetails = "log:sql-errorlog" }; return true; }

            // NPS / RADIUS (IAS/NPS) text logs
            if (LogHeuristics.LooksLikeNpsRadiusLog(headLower)) { result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = "Medium", Reason = "text:log-nps", ReasonDetails = "log:nps" }; return true; }

            // SQL Server Agent logs (SQLAgent.out / text snippets)
            if (LogHeuristics.LooksLikeSqlAgentLog(headLower, logCues)) { result = new ContentTypeDetectionResult { Extension = "log", MimeType = "text/plain", Confidence = "Low", Reason = "text:log-sqlagent", ReasonDetails = "log:sqlagent" }; return true; }
        }

        return false;
    }
}
