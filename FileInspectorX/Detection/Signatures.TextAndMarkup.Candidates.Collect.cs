namespace FileInspectorX;

internal static partial class Signatures
{
    static List<ContentTypeDetectionCandidate> CollectCandidates(ReadOnlySpan<byte> head, string headStr, string headLower, string decl)
    {
        var byExt = new Dictionary<string, ContentTypeDetectionCandidate>(StringComparer.OrdinalIgnoreCase);
        void AddCandidate(string ext, string mime, string confidence, string reason, string? details = null, int scoreAdjust = 0, bool? dangerousOverride = null)
        {
            if (string.IsNullOrWhiteSpace(ext)) return;
            int adjust = scoreAdjust + GetScoreAdjustment(ext, reason, details);
            if (!string.IsNullOrWhiteSpace(decl) && string.Equals(ext, decl, StringComparison.OrdinalIgnoreCase))
                adjust += 3;
            int score = ClampScore(ScoreFromConfidence(confidence) + adjust, confidence);
            bool dangerous = dangerousOverride ?? DangerousExtensions.IsDangerous(ext);
            var c = new ContentTypeDetectionCandidate { Extension = ext, MimeType = mime, Confidence = confidence, Reason = reason, ReasonDetails = details, Score = score, IsDangerous = dangerous };
            if (byExt.TryGetValue(ext, out var existing))
            {
                if (string.Equals(ext, "log", StringComparison.OrdinalIgnoreCase))
                {
                    var merged = MergeDetails(existing.ReasonDetails, c.ReasonDetails ?? NormalizeLogDetail(c.Reason));
                    if (c.Score > existing.Score)
                    {
                        c.ReasonDetails = merged;
                        byExt[ext] = c;
                    }
                    else
                    {
                        existing.ReasonDetails = merged;
                        byExt[ext] = existing;
                    }
                }
                else if (c.Score > existing.Score)
                {
                    byExt[ext] = c;
                }
            }
            else
            {
                if (string.Equals(ext, "log", StringComparison.OrdinalIgnoreCase) && string.IsNullOrEmpty(c.ReasonDetails))
                    c.ReasonDetails = NormalizeLogDetail(c.Reason);
                byExt.Add(ext, c);
            }
        }

        static bool ContainsToken(string text, string token)
        {
            if (string.IsNullOrEmpty(text) || string.IsNullOrEmpty(token)) return false;
            int idx = 0;
            while ((idx = text.IndexOf(token, idx, StringComparison.OrdinalIgnoreCase)) >= 0)
            {
                bool leftOk = idx == 0 || !char.IsLetterOrDigit(text[idx - 1]);
                int end = idx + token.Length;
                bool rightOk = end >= text.Length || !char.IsLetterOrDigit(text[end]);
                if (leftOk && rightOk) return true;
                idx = end;
            }
            return false;
        }
        static string? NormalizeLogDetail(string? reason)
        {
            if (string.IsNullOrWhiteSpace(reason)) return null;
            var value = reason!;
            if (value.StartsWith("text:log-", StringComparison.OrdinalIgnoreCase))
                return "log:" + value.Substring("text:log-".Length);
            if (value.StartsWith("text:event", StringComparison.OrdinalIgnoreCase))
                return "log:event-txt";
            return null;
        }
        static string? MergeDetails(string? first, string? second)
        {
            if (string.IsNullOrWhiteSpace(first)) return second;
            if (string.IsNullOrWhiteSpace(second)) return first;
            var a = first!;
            var b = second!;
            if (a.IndexOf(b, StringComparison.OrdinalIgnoreCase) >= 0) return a;
            if (b.IndexOf(a, StringComparison.OrdinalIgnoreCase) >= 0) return b;
            return a + "|" + b;
        }

        bool declaredMd = decl == "md" || decl == "markdown";
        bool declaredLog = decl == "log";
        bool declaredIni = decl == "ini";
        bool declaredInf = decl == "inf";
        bool declaredToml = decl == "toml";
        bool declaredAdmx = decl == "admx";
        bool declaredAdml = decl == "adml";
        bool declaredCmd = decl == "cmd";

        bool psCues = HasPowerShellCues(head, headStr, headLower) || HasVerbNounCmdlet(headStr);
        bool vbsCues = LooksLikeVbsScript(headLower);
        bool jsCues = LooksLikeJavaScript(headStr, headLower);
        bool shShebang = headLower.Contains("#!/bin/sh") || headLower.Contains("#!/usr/bin/env sh") || headLower.Contains("#!/usr/bin/env bash") || headLower.Contains("#!/bin/bash") || headLower.Contains("#!/usr/bin/env zsh") || headLower.Contains("#!/bin/zsh");
        bool batCues = headLower.Contains("@echo off") || headLower.Contains("setlocal") || headLower.Contains("endlocal") ||
                       headLower.Contains("\ngoto ") || headLower.Contains("\r\ngoto ") || headLower.Contains(" goto ") ||
                       headLower.StartsWith("rem ") || headLower.Contains("\nrem ") || headLower.Contains("\r\nrem ") || headLower.Contains(":end");
        bool scriptCues = psCues || vbsCues || jsCues || shShebang || batCues;

        int mdCuesLocal = 0;
        bool mdStructuralLocal = false;
        if (headLower.Contains("```")) { mdCuesLocal += 2; mdStructuralLocal = true; }
        if (headLower.StartsWith("# ") || headLower.Contains("\n# ")) mdCuesLocal++;
        if (headLower.Contains("](")) mdCuesLocal++;
        if (headLower.Contains("\n- ") || headLower.Contains("\n* ") || headLower.Contains("\n1. ")) mdCuesLocal++;
        bool mdLikely = mdStructuralLocal || mdCuesLocal >= 2 || (declaredMd && mdCuesLocal >= 1);
        int scriptPenaltyFromMarkdown = mdLikely ? (declaredMd ? -8 : -6) : 0;

        var span = head;
        if (span.Length == 0) return new List<ContentTypeDetectionCandidate>();

        int nl = span.IndexOf((byte)'\n'); if (nl < 0) nl = span.Length;
        var line1 = span.Slice(0, nl);
        var rest = span.Slice(Math.Min(nl + 1, span.Length));
        int nl2 = rest.IndexOf((byte)'\n'); if (nl2 < 0) nl2 = rest.Length;
        var line2 = rest.Slice(0, nl2);
        var rest2 = rest.Slice(Math.Min(nl2 + 1, rest.Length));
        int nl3 = rest2.IndexOf((byte)'\n'); if (nl3 < 0) nl3 = rest2.Length;
        var line3 = rest2.Slice(0, nl3);
        var rest3 = rest2.Slice(Math.Min(nl3 + 1, rest2.Length));
        int nl4 = rest3.IndexOf((byte)'\n'); if (nl4 < 0) nl4 = rest3.Length;
        var line4 = rest3.Slice(0, nl4);

        bool jsonComplete = LooksLikeCompleteJson(headStr);
        bool jsonValid = jsonComplete && TryValidateJsonStructure(headStr);
        bool htmlHasScript = headLower.Contains("<script") || headLower.Contains("javascript:") || headLower.Contains("onerror=") || headLower.Contains("onload=");

        bool logCuesLocal = LooksLikeTimestamp(line1) || LooksLikeTimestamp(line2) || StartsWithLevelToken(line1) || StartsWithLevelToken(line2);
        int logPenaltyFromScript = scriptCues ? -8 : 0;
        int scriptPenaltyFromLog = logCuesLocal ? -8 : 0;
        int scriptPenalty = scriptPenaltyFromLog + scriptPenaltyFromMarkdown;
        int logPenalty = logPenaltyFromScript + (mdLikely ? -4 : 0);
        int jsonPenalty = (scriptCues ? -4 : 0) + (logCuesLocal ? -4 : 0);
        if (!scriptCues)
        {
            if (LogHeuristics.LooksLikeDnsLog(headLower)) AddCandidate("log", "text/plain", "Medium", "text:log-dns", "log:dns", scoreAdjust: logPenalty);
            if (LogHeuristics.LooksLikeFirewallLog(headLower)) AddCandidate("log", "text/plain", "Medium", "text:log-firewall", "log:firewall", scoreAdjust: logPenalty);
            if (LogHeuristics.LooksLikeNetlogonLog(headLower, logCuesLocal)) AddCandidate("log", "text/plain", "Medium", "text:log-netlogon", "log:netlogon", scoreAdjust: logPenalty);
            if (LogHeuristics.LooksLikeEventViewerTextExport(headLower)) AddCandidate("log", "text/plain", "Medium", "text:event-txt", "log:event-txt", scoreAdjust: logPenalty);
            if (LogHeuristics.LooksLikeDhcpLog(headLower)) AddCandidate("log", "text/plain", "Medium", "text:log-dhcp", "log:dhcp", scoreAdjust: logPenalty);
            if (LogHeuristics.LooksLikeExchangeMessageTrackingLog(headLower)) AddCandidate("log", "text/plain", "Medium", "text:log-exchange", "log:exchange", scoreAdjust: logPenalty);
            if (LogHeuristics.LooksLikeDefenderTextLog(headLower, logCuesLocal)) AddCandidate("log", "text/plain", "Low", "text:log-defender", "log:defender", scoreAdjust: logPenalty);
            if (LogHeuristics.LooksLikeSqlErrorLog(headLower, logCuesLocal)) AddCandidate("log", "text/plain", "Medium", "text:log-sql-errorlog", "log:sql-errorlog", scoreAdjust: logPenalty);
            if (LogHeuristics.LooksLikeNpsRadiusLog(headLower)) AddCandidate("log", "text/plain", "Medium", "text:log-nps", "log:nps", scoreAdjust: logPenalty);
            if (LogHeuristics.LooksLikeSqlAgentLog(headLower, logCuesLocal)) AddCandidate("log", "text/plain", "Low", "text:log-sqlagent", "log:sqlagent", scoreAdjust: logPenalty);

            int levelCount = 0;
            if (StartsWithLevelToken(line1)) levelCount++;
            if (StartsWithLevelToken(line2)) levelCount++;
            if (StartsWithLevelToken(line3)) levelCount++;
            if (StartsWithLevelToken(line4)) levelCount++;
            int tsCount = 0;
            if (LooksLikeTimestamp(line1)) tsCount++;
            if (LooksLikeTimestamp(line2)) tsCount++;
            if (LooksLikeTimestamp(line3)) tsCount++;
            if (LooksLikeTimestamp(line4)) tsCount++;
            if (tsCount >= 2)
                AddCandidate("log", "text/plain", "Low", "text:log", "log:timestamps-multi", scoreAdjust: logPenalty);
            if (levelCount >= 2 || ((LooksLikeTimestamp(line1) || LooksLikeTimestamp(line2)) && levelCount >= 1))
            {
                var conf = levelCount >= 2 && (LooksLikeTimestamp(line1) || LooksLikeTimestamp(line2)) ? "Medium" : "Low";
                AddCandidate("log", "text/plain", conf, "text:log-levels", levelCount >= 2 ? $"log:levels-{levelCount}" : "log:timestamp+level", scoreAdjust: logPenalty);
            }
            if (declaredLog && logCuesLocal)
                AddCandidate("log", "text/plain", "Low", "text:log", "log:declared", scoreAdjust: logPenalty);
        }

        {
            static bool LooksJsonLine(ReadOnlySpan<byte> l)
            {
                if (l.Length < 2) return false;
                int i = 0; while (i < l.Length && (l[i] == (byte)' ' || l[i] == (byte)'\t')) i++;
                if (i >= l.Length || l[i] != (byte)'{') return false;
                int q = l.IndexOf((byte)'"'); if (q < 0) return false;
                int colon = l.IndexOf((byte)':'); if (colon < 0) return false;
                int end = l.LastIndexOf((byte)'}'); if (end < 0) return false;
                int depth = 0; bool inQ = false; bool colonOut = false;
                for (int k = 0; k < l.Length; k++)
                {
                    byte c = l[k];
                    if (c == (byte)'"') inQ = !inQ;
                    else if (!inQ)
                    {
                        if (c == (byte)'{') depth++;
                        else if (c == (byte)'}') depth--;
                        else if (c == (byte)':') colonOut = true;
                    }
                }
                if (depth != 0) return false;
                return colonOut && colon > q && end > colon;
            }

            var l1 = TrimBytes(line1);
            var l2 = TrimBytes(line2);
            bool j1 = LooksJsonLine(l1);
            bool j2 = LooksJsonLine(l2);
            if (j1 && j2)
            {
                var l3 = TrimBytes(line3);
                bool j3 = LooksJsonLine(l3);
                string conf = j3 ? "High" : "Medium";
                int boost = j3 ? 10 : 8;
                AddCandidate("ndjson", "application/x-ndjson", conf, "text:ndjson", j3 ? "ndjson:lines-3" : "ndjson:lines-2", scoreAdjust: boost);
            }
        }

        if (head.Length > 0 && (head[0] == (byte)'{' || head[0] == (byte)'['))
        {
            bool jsonLooksLikeLog = LooksLikeTimestamp(TrimBytes(line1)) || StartsWithLevelToken(TrimBytes(line1));
            if (!jsonLooksLikeLog)
            {
                int len = Math.Min(JSON_DETECTION_SCAN_LIMIT, head.Length);
                var slice = head.Slice(0, len);
                bool looksObject = slice[0] == (byte)'{';
                bool looksArray = slice[0] == (byte)'[';
                if (looksArray)
                {
                    bool hasClose = slice.IndexOf((byte)']') >= 0;
                    int commaCount = Count(slice, (byte)',');
                    bool hasObjectItem = slice.IndexOf((byte)'{') >= 0;
                    if ((commaCount >= 1 && hasClose) || hasObjectItem)
                    {
                        bool hasQuotedColon = HasQuotedKeyColon(slice);
                        if (hasObjectItem ? hasQuotedColon : true)
                        {
                            AddCandidate("json", "application/json", hasObjectItem ? "Medium" : "Low", "text:json", hasObjectItem ? "json:array-of-objects" : "json:array-of-primitives", scoreAdjust: (jsonValid ? 6 : 0) + jsonPenalty);
                        }
                    }
                }
                if (looksObject)
                {
                    bool hasQuotedColon = HasQuotedKeyColon(slice);
                    bool hasClose = slice.IndexOf((byte)'}') >= 0;
                    if (hasQuotedColon && hasClose)
                        AddCandidate("json", "application/json", "Medium", "text:json", "json:object-key-colon", scoreAdjust: (jsonValid ? 6 : 0) + jsonPenalty);
                }
            }
        }

        if (head.Length >= 1 && head[0] == (byte)'<')
        {
            var root = TryGetXmlRootName(headStr);
            if (root != null && root.Length > 0)
            {
                var rootLower = root.ToLowerInvariant();
                int colon = rootLower.IndexOf(':');
                if (colon >= 0 && colon < rootLower.Length - 1)
                    rootLower = rootLower.Substring(colon + 1);
                bool xmlComplete = LooksLikeCompleteXml(headLower, rootLower);
                bool xmlWellFormed = xmlComplete && TryXmlWellFormed(headStr, out _);
                if (rootLower == "policydefinitions")
                {
                    bool admxCues = LooksLikeAdmxXml(headLower);
                    bool admxStrong = admxCues || declaredAdmx;
                    var details = admxCues ? "xml:policydefinitions+schema" : (declaredAdmx ? "xml:policydefinitions+decl" : "xml:policydefinitions");
                    AddCandidate("admx", "application/xml", admxStrong ? "High" : "Medium", "text:admx", details, scoreAdjust: xmlWellFormed ? 6 : 0);
                }
                else if (rootLower == "policydefinitionresources")
                {
                    bool admlCues = LooksLikeAdmlXml(headLower);
                    bool admlStrong = admlCues || declaredAdml;
                    var details = admlCues ? "xml:policydefinitionresources+schema" : (declaredAdml ? "xml:policydefinitionresources+decl" : "xml:policydefinitionresources");
                    AddCandidate("adml", "application/xml", admlStrong ? "High" : "Medium", "text:adml", details, scoreAdjust: xmlWellFormed ? 6 : 0);
                }
            }
            if (head.Length >= 5 && head.Slice(0, 5).SequenceEqual("<?xml"u8))
            {
                var ext = declaredAdmx ? "admx" : (declaredAdml ? "adml" : "xml");
                bool xmlComplete = LooksLikeCompleteXml(headLower, null);
                bool xmlWellFormed = xmlComplete && TryXmlWellFormed(headStr, out _);
                AddCandidate(ext, "application/xml", "Medium", "text:xml", ext == "xml" ? null : $"xml:decl-{ext}", scoreAdjust: xmlWellFormed ? 6 : 0);
            }
            if (head.IndexOf("<!DOCTYPE html"u8) >= 0 || head.IndexOf("<html"u8) >= 0)
                AddCandidate("html", "text/html", "Medium", "text:html", scoreAdjust: 0, dangerousOverride: htmlHasScript);
        }

        if (!logCuesLocal)
        {
            bool yamlFront = false;
            string trimmed = headStr.TrimStart('\ufeff', ' ', '\t', '\r', '\n');
            if (trimmed.StartsWith("---", StringComparison.Ordinal))
            {
                int idx = trimmed.IndexOf("\n---", StringComparison.Ordinal);
                if (idx > 0) yamlFront = true;
            }
            CountYamlStructure(head, 8, out int yamlKeys, out int yamlLists);
            bool yamlStrong = yamlKeys >= 2 || (yamlKeys >= 1 && yamlLists >= 1) || yamlLists >= 3;
            int yamlPenalty = (logCuesLocal ? -6 : 0) + ((scriptCues && !yamlStrong) ? -4 : 0);
            if (yamlFront)
            {
                if (!scriptCues || yamlStrong)
                    AddCandidate("yml", "application/x-yaml", "Low", "text:yaml", "yaml:front-matter", scoreAdjust: yamlPenalty);
            }
            else if (yamlKeys >= 2 || yamlLists >= 2)
            {
                if (!scriptCues || yamlStrong)
                {
                    var details = yamlKeys >= 1 ? $"yaml:key-lines={yamlKeys}" : $"yaml:list-lines={yamlLists}";
                    AddCandidate("yml", "application/x-yaml", "Low", "text:yaml-keys", details, scoreAdjust: yamlPenalty);
                }
            }
        }

        if (!scriptCues && !logCuesLocal)
        {
            int tomlTables = 0;
            int tomlEquals = 0;
            int lineStart = 0;
            int inspected = 0;
            for (int i = 0; i < head.Length && inspected < 8; i++)
            {
                if (head[i] == (byte)'\n' || i == head.Length - 1)
                {
                    int end = head[i] == (byte)'\n' ? i : i + 1;
                    var raw = head.Slice(lineStart, Math.Max(0, end - lineStart));
                    lineStart = i + 1;
                    var line = TrimBytes(raw);
                    if (line.Length == 0) continue;
                    inspected++;
                    if (line[0] == (byte)'[' && line[line.Length - 1] == (byte)']') tomlTables++;
                    if (line.IndexOf((byte)'=') > 0) tomlEquals++;
                }
            }
            if (tomlTables >= 1 && tomlEquals >= 1)
            {
                int tomlAdjust = tomlTables >= 1 && tomlEquals >= 2 ? 4 : 0;
                AddCandidate("toml", "application/toml", "Low", "text:toml", scoreAdjust: tomlAdjust);
            }
        }

        {
            bool hasPsCues = HasPowerShellCues(head, headStr, headLower) || HasVerbNounCmdlet(headStr);
            if (!hasPsCues && !jsCues && !shShebang && !batCues)
            {
                bool hasSection = false;
                bool hasEquals = false;
                int meaningfulLines = 0;
                int lineStart2 = 0;
                for (int i = 0; i < head.Length && meaningfulLines < 8; i++)
                {
                    if (head[i] == (byte)'\n' || i == head.Length - 1)
                    {
                        int end = head[i] == (byte)'\n' ? i : i + 1;
                        var raw = head.Slice(lineStart2, Math.Max(0, end - lineStart2));
                        lineStart2 = i + 1;
                        var line = TrimBytes(raw);
                        if (line.Length == 0) continue;
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
                    int iniAdjust = 4;
                    AddCandidate(ext, "text/plain", "Low", "text:ini", ext == "inf" ? "inf:section+equals" : "ini:section+equals", scoreAdjust: iniAdjust);
                }
            }
        }

        if (!logCuesLocal && !scriptCues)
        {
            int commas1 = Count(line1, (byte)','); int commas2 = Count(line2, (byte)',');
            int semis1 = Count(line1, (byte)';'); int semis2 = Count(line2, (byte)';');
            int pipes1 = Count(line1, (byte)'|'); int pipes2 = Count(line2, (byte)'|');
            int tabs1 = Count(line1, (byte)'\t'); int tabs2 = Count(line2, (byte)'\t');
            if ((commas1 >= 1 && commas2 >= 1 && Math.Abs(commas1 - commas2) <= 2) ||
                (semis1 >= 1 && semis2 >= 1 && Math.Abs(semis1 - semis2) <= 2) ||
                (pipes1 >= 1 && pipes2 >= 1 && Math.Abs(pipes1 - pipes2) <= 2))
                AddCandidate("csv", "text/csv", "Low", "text:csv", "csv:delimiter-repeat-2lines");
            if (tabs1 >= 1 && tabs2 >= 1 && Math.Abs(tabs1 - tabs2) <= 2)
                AddCandidate("tsv", "text/tab-separated-values", "Low", "text:tsv", "tsv:tabs-2lines");
            if (line2.Length == 0)
            {
                static int TokenCount(ReadOnlySpan<byte> l, byte sep) { if (l.Length == 0) return 0; int tokens = 1; for (int i = 0; i < l.Length; i++) if (l[i] == sep) tokens++; return tokens; }
                if (commas1 >= 2 && TokenCount(line1, (byte)',') >= 3) AddCandidate("csv", "text/csv", "Low", "text:csv", "csv:single-line");
                if (semis1 >= 2 && TokenCount(line1, (byte)';') >= 3) AddCandidate("csv", "text/csv", "Low", "text:csv", "csv:single-line");
                if (tabs1 >= 2 && TokenCount(line1, (byte)'\t') >= 3) AddCandidate("tsv", "text/tab-separated-values", "Low", "text:tsv", "tsv:single-line");
            }
        }

        {
            var sl = headLower;
            bool looksMd = sl.StartsWith("# ") || sl.Contains("\n# ") || sl.Contains("```") || sl.Contains("](");
            int mdCues = 0;
            if (sl.StartsWith("# ") || sl.Contains("\n# ")) mdCues++;
            if (sl.Contains("```")) mdCues++;
            if (sl.Contains("](")) mdCues++;
            if (sl.Contains("\n- ") || sl.StartsWith("- ") || sl.Contains("\n* ") || sl.StartsWith("* ")) mdCues++;
            if (mdCues == 1)
            {
                var lines = headStr.Split('\n');
                if (lines.Length >= 2 && lines[1].Trim().Length > 0) mdCues++;
            }
            if (looksMd)
            {
                var okByCues = declaredMd ? mdCues >= 1 : mdCues >= 2;
                bool hasFence = sl.Contains("```");
                bool hasHeading = sl.StartsWith("# ") || sl.Contains("\n# ");
                bool mdStructural = hasFence || hasHeading;
                if (okByCues && !logCuesLocal && (!scriptCues || declaredMd || mdStructural))
                    AddCandidate("md", "text/markdown", "Low", "text:md", null, mdStructural ? 4 : 0);
            }
        }

        {
            bool psShebang = headLower.Contains("#!/usr/bin/env pwsh") || headLower.Contains("#!/usr/bin/pwsh") ||
                             headLower.Contains("#!/usr/bin/env powershell") || headLower.Contains("#!/usr/bin/powershell");
            bool declaredPsm1 = decl == "psm1";
            bool declaredPsd1 = decl == "psd1";
            bool hasVerbNoun = HasVerbNounCmdlet(headStr);
            bool hasPipeline = (headStr.IndexOf("| Where-Object", System.StringComparison.OrdinalIgnoreCase) >= 0 ||
                                headStr.IndexOf("| ForEach-Object", System.StringComparison.OrdinalIgnoreCase) >= 0 ||
                                headStr.IndexOf("| Select-Object", System.StringComparison.OrdinalIgnoreCase) >= 0) &&
                               headStr.IndexOf("$", System.StringComparison.Ordinal) >= 0;
            bool hasModuleExport = headStr.IndexOf("Export-ModuleMember", System.StringComparison.OrdinalIgnoreCase) >= 0 ||
                                   headStr.IndexOf("FunctionsToExport", System.StringComparison.OrdinalIgnoreCase) >= 0 ||
                                   headStr.IndexOf("RootModule", System.StringComparison.OrdinalIgnoreCase) >= 0;
            bool psd1Hashtable = declaredPsd1 && headStr.TrimStart().StartsWith("@{");
            int cues = 0;
            int strong = 0;
            if (headLower.Contains("[cmdletbinding]")) cues++;
            if (headLower.Contains("#requires")) cues++;
            if (headLower.Contains("param(")) { cues++; strong++; }
            if (headLower.Contains("begin{")) { cues++; strong++; }
            if (headLower.Contains("process{")) { cues++; strong++; }
            if (headLower.Contains("end{")) { cues++; strong++; }
            if (headLower.Contains("[parameter(")) { cues++; strong++; }
            if (headLower.Contains("[validate")) { cues++; strong++; }
            if (headStr.IndexOf("Write-Host", System.StringComparison.Ordinal) >= 0) cues++;
            if (headStr.IndexOf("Import-Module", System.StringComparison.OrdinalIgnoreCase) >= 0) cues++;
            if (headStr.IndexOf("New-Object", System.StringComparison.OrdinalIgnoreCase) >= 0) cues++;
            bool hasGetSet = headStr.IndexOf("Get-", System.StringComparison.OrdinalIgnoreCase) >= 0 || headStr.IndexOf("Set-", System.StringComparison.OrdinalIgnoreCase) >= 0;
            if (hasGetSet) cues++;
            if (hasVerbNoun) { cues++; strong++; }
            if (hasPipeline) { cues++; strong++; }

            if (declaredPsm1 && (hasModuleExport || hasVerbNoun))
                AddCandidate("psm1", "text/x-powershell", "Medium", "text:psm1", "psm1:module-cues", scriptPenalty);

            if (declaredPsd1 && (psd1Hashtable || hasModuleExport))
                AddCandidate("psd1", "text/x-powershell", "Low", "text:psd1", psd1Hashtable ? "psd1:hashtable" : "psd1:module-keys", scriptPenalty);

            if (psShebang || cues >= 2 || (cues >= 1 && strong >= 1))
            {
                string conf = psShebang || cues >= 3 || strong >= 2 ? "High" : "Medium";
                string details = psShebang ? "ps1:shebang" : (cues >= 3 ? "ps1:multi-cues" : (strong >= 1 && cues == 1 ? "ps1:single-strong-cue" : "ps1:common-cmdlets"));
                AddCandidate("ps1", "text/x-powershell", conf, psShebang ? "text:ps1-shebang" : "text:ps1", details, scriptPenalty);
            }
        }

        if (LooksLikeVbsScript(headLower))
        {
            var conf = (headLower.Contains("option explicit") || headLower.Contains("on error resume next") || headLower.Contains("createobject(") || headLower.Contains("wscript.")) ? "Medium" : "Low";
            bool vbsBlock = headLower.Contains("end sub") || headLower.Contains("end function");
            bool vbsToken = vbsBlock && (ContainsToken(headLower, "sub") || ContainsToken(headLower, "function"));
            int vbsAdjust = scriptPenalty + (vbsToken ? 4 : 0);
            AddCandidate("vbs", "text/vbscript", conf, "text:vbs", conf == "Medium" ? "vbs:explicit+error|createobject" : "vbs:wscript+dim|msgbox", vbsAdjust);
        }

        if (shShebang)
            AddCandidate("sh", "text/x-shellscript", "Medium", "text:sh-shebang", "sh:shebang", scriptPenalty);
        if (!shShebang && !scriptCues && (headLower.Contains("set -e") || headLower.Contains("set -u") || headLower.Contains("export ") || headLower.Contains("[[") || headLower.Contains("]]")) &&
            (headLower.Contains(" fi\n") || headLower.Contains(" esac\n") || headLower.Contains(" && ") || headLower.Contains(" case ") || headLower.Contains(" do\n")))
            AddCandidate("sh", "text/x-shellscript", "Low", "text:sh-heur", "sh:set|export+fi|esac|case|&&|do", scriptPenalty);

        if (headLower.Contains("#!/usr/bin/env node") || headLower.Contains("#!/usr/bin/node"))
            AddCandidate("js", "application/javascript", "Medium", "text:node-shebang", "js:shebang", scriptPenalty);
        else if (LooksLikeJavaScript(headStr, headLower))
            AddCandidate("js", "application/javascript", "Low", "text:js-heur", scoreAdjust: scriptPenalty);

        if (batCues)
        {
            var ext = declaredCmd ? "cmd" : "bat";
            AddCandidate(ext, "text/x-batch", "Medium", ext == "cmd" ? "text:cmd" : "text:bat", "bat:echo|setlocal|goto|rem", scriptPenalty);
        }

        if (headLower.Contains("#!/usr/bin/env python") || headLower.Contains("#!/usr/bin/python"))
            AddCandidate("py", "text/x-python", "Medium", "text:py-shebang", "py:shebang", scriptPenalty);
        else
        {
            int pyCues = 0;
            if (IndexOfToken(head, "import ") >= 0) pyCues++;
            if (IndexOfToken(head, "def ") >= 0 && head.IndexOf((byte)':') >= 0) pyCues++;
            if (IndexOfToken(head, "class ") >= 0 && head.IndexOf((byte)':') >= 0) pyCues++;
            if (IndexOfToken(head, "if __name__ == '__main__':") >= 0) pyCues += 2;
            if (pyCues >= 2) AddCandidate("py", "text/x-python", "Low", "text:py-heur", $"py:cues-{pyCues}", scriptPenalty);
        }

        if (headLower.Contains("#!/usr/bin/env ruby") || headLower.Contains("#!/usr/bin/ruby"))
            AddCandidate("rb", "text/x-ruby", "Medium", "text:rb-shebang", "rb:shebang", scriptPenalty);
        else
        {
            int rbCues = 0;
            if (IndexOfToken(head, "require ") >= 0) rbCues++;
            if (IndexOfToken(head, "def ") >= 0 && IndexOfToken(head, " end") >= 0) rbCues += 2;
            if (IndexOfToken(head, "class ") >= 0 && IndexOfToken(head, " end") >= 0) rbCues += 2;
            if (IndexOfToken(head, "module ") >= 0 && IndexOfToken(head, " end") >= 0) rbCues += 2;
            if (IndexOfToken(head, "puts ") >= 0) rbCues++;
            if (rbCues >= 2) AddCandidate("rb", "text/x-ruby", "Low", "text:rb-heur", $"rb:cues-{rbCues}", scriptPenalty);
        }

        if (headLower.Contains("#!/usr/bin/env lua") || headLower.Contains("#!/usr/bin/lua"))
            AddCandidate("lua", "text/x-lua", "Medium", "text:lua-shebang", "lua:shebang", scriptPenalty);
        else
        {
            int luaCues = 0;
            if (IndexOfToken(head, "local function ") >= 0) luaCues += 2;
            if (IndexOfToken(head, "function ") >= 0 && IndexOfToken(head, " end") >= 0) luaCues += 2;
            if (IndexOfToken(head, "require(") >= 0 || IndexOfToken(head, "require ") >= 0) luaCues++;
            if (IndexOfToken(head, " then") >= 0 && IndexOfToken(head, " end") >= 0) luaCues++;
            if (luaCues >= 2) AddCandidate("lua", "text/x-lua", "Low", "text:lua-heur", $"lua:cues-{luaCues}", scriptPenalty);
        }

        var list = new List<ContentTypeDetectionCandidate>(byExt.Values);
        list.Sort((a, b) => b.Score.CompareTo(a.Score));
        return list;
    }

}
