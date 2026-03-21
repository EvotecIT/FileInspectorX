using System.Xml;

namespace FileInspectorX;

/// <summary>
/// Extracts generic references (paths, URLs, commands, env vars, CLSIDs) from common config formats.
/// </summary>
public static partial class FileInspector
{
    private static IReadOnlyList<Reference>? BuildReferences(string path, ContentTypeDetectionResult? det)
    {
        var list = new List<Reference>(8);
        try {
            var ext = System.IO.Path.GetExtension(path).TrimStart('.').ToLowerInvariant();
            var detectedExt = (det?.Extension ?? string.Empty).Trim().TrimStart('.').ToLowerInvariant();
            var detectionReason = det?.Reason;
            bool detectionConfidenceLow = string.Equals(det?.Confidence, "Low", StringComparison.OrdinalIgnoreCase);
            bool detectedXmlLike = !detectionConfidenceLow && detectedExt == "xml";
            bool detectedHtmlLike = !detectionConfidenceLow && detectedExt is "html" or "htm";
            bool allowLowConfidenceDetectedScript = detectionConfidenceLow &&
                                                    IsReferenceFriendlyTextExtension(ext);
            bool detectedScriptLike = (!detectionConfidenceLow || allowLowConfidenceDetectedScript) &&
                                      detectedExt is "ps1" or "psm1" or "psd1" or "bat" or "cmd" or "sh" or "bash" or "zsh" or "js" or "vbs" or "css";
            bool isXmlLike = ext == "xml" || string.IsNullOrEmpty(ext) || detectedXmlLike;
            bool isHtmlLike = ext is "html" or "htm" || detectedHtmlLike;
            bool isScriptLike = ext is "ps1" or "psm1" or "psd1" or "bat" or "cmd" or "sh" or "bash" or "zsh" or "js" or "vbs" or "css"
                                || detectedScriptLike;
            var scriptSourceTag = detectedScriptLike && !string.IsNullOrWhiteSpace(detectedExt) && IsScriptTextSubtype(MapTextSubtypeFromExtension(detectedExt))
                ? detectedExt
                : ext;
            bool detectionLooksTextLike = (detectionReason ?? string.Empty).StartsWith("text:", StringComparison.OrdinalIgnoreCase);
            bool detectionLooksReliablyTextLike = detectionLooksTextLike &&
                                                  !string.Equals(det?.Confidence, "Low", StringComparison.OrdinalIgnoreCase);

            // Task Scheduler Task XML
            // Try for .xml; when ambiguous, a quick shape check happens inside
            if (isXmlLike)
            {
                if (LooksLikeTaskXml(path))
                    TryExtractTaskSchedulerXml(path, list);
            }

            // GPO scripts INI (scripts.ini, psscripts.ini)
            if (ext == "ini" || string.Equals(System.IO.Path.GetFileName(path), "scripts.ini", StringComparison.OrdinalIgnoreCase) || string.Equals(System.IO.Path.GetFileName(path), "psscripts.ini", StringComparison.OrdinalIgnoreCase))
            {
                TryExtractGpoScriptsIni(path, list);
            }

            // GPO Scripts.xml (PowerShell or Generic)
            if (isXmlLike)
            {
                TryExtractGpoScriptsXml(path, list);
            }

            // HTML: extract external links and network paths from common tags/attributes
            if (isHtmlLike)
            {
                TryExtractHtmlReferences(path, list);
            }
            // Scripts: extract URLs and UNC shares from common script types (PowerShell, batch, shell, JS)
            if (isScriptLike)
            {
                TryExtractScriptReferences(path, list, string.IsNullOrWhiteSpace(scriptSourceTag) ? "script" : scriptSourceTag);
            }

            bool isGenericTextLike =
                !isHtmlLike &&
                !isScriptLike &&
                (detectedExt is "log" or "txt" ||
                 (string.IsNullOrWhiteSpace(detectedExt) && ext is "log" or "txt") ||
                 detectionLooksReliablyTextLike);
            if (isGenericTextLike)
            {
                var genericTextSourceTag = string.Equals(det?.Reason, "text:event-txt", StringComparison.OrdinalIgnoreCase)
                    ? "log:event-txt"
                    : (detectedExt == "log" || ext == "log" ? "log:text" : "text:generic");
                TryExtractGenericTextReferences(path, list, genericTextSourceTag);
            }

            // Windows Internet Shortcut (.url)
            if (ext == "url")
            {
                TryExtractInternetShortcut(path, list);
            }

            // Windows Shell Link (.lnk) — best-effort target extraction
            if (ext == "lnk")
            {
                TryExtractWindowsLnk(path, list);
            }

            // Generic: if detection is plain text and starts with a command-ish shebang, we skip here; richer parsers can be added later
        } catch { }

        return list.Count > 0 ? list : null;
    }

    private static void TryExtractGenericTextReferences(string path, List<Reference> refs, string sourceTag)
    {
        try
        {
            string text = ReadTextForReferences(path, Settings.ReferenceExtractionMaxBytes);
            if (string.IsNullOrWhiteSpace(text)) return;

            var seenUrls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var seenUnc = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            int i = 0;
            while (i < text.Length)
            {
                int at = text.IndexOf("http", i, StringComparison.OrdinalIgnoreCase);
                if (at < 0) break;
                int end = at;
                while (end < text.Length && !char.IsWhiteSpace(text[end]) && text[end] != '"' && text[end] != '\'' && text[end] != ')' && text[end] != '<' && text[end] != '>' && text[end] != '`')
                    end++;
                var cand = text.Substring(at, end - at).TrimEnd('.', ',', ';', ':');
                if (Uri.TryCreate(cand, UriKind.Absolute, out var u) && (u.Scheme == Uri.UriSchemeHttp || u.Scheme == Uri.UriSchemeHttps) && seenUrls.Add(cand))
                {
                    refs.Add(new Reference { Kind = ReferenceKind.Url, Value = cand, SourceTag = sourceTag });
                }
                i = end + 1;
            }

            var span = text.AsSpan();
            int p = 0;
            while (p + 3 < span.Length)
            {
                if (span[p] == '\\' && span[p + 1] == '\\')
                {
                    int start = p;
                    p += 2;
                    int sHost = p;
                    while (p < span.Length && (char.IsLetterOrDigit(span[p]) || span[p] == '.' || span[p] == '-' || span[p] == '_')) p++;
                    if (p <= sHost || p >= span.Length || span[p] != '\\') { p++; continue; }
                    string server = span.Slice(sHost, p - sHost).ToString();
                    p++;
                    int sShare = p;
                    while (p < span.Length && (char.IsLetterOrDigit(span[p]) || span[p] == '.' || span[p] == '-' || span[p] == '_' || span[p] == '$')) p++;
                    if (p > sShare)
                    {
                        string share = span.Slice(sShare, p - sShare).ToString();
                        string unc = "\\\\" + server + "\\" + share;
                        if (seenUnc.Add(unc))
                        {
                            refs.Add(new Reference
                            {
                                Kind = ReferenceKind.FilePath,
                                Value = unc,
                                SourceTag = sourceTag,
                                Issues = ReferenceIssue.UncPath
                            });
                        }
                    }
                }
                else p++;
            }
        }
        catch { }
    }

    private static void TryExtractScriptReferences(string path, List<Reference> refs, string ext)
    {
        try
        {
            string text = ReadTextForReferences(path, Settings.ReferenceExtractionMaxBytes);
            if (string.IsNullOrWhiteSpace(text)) return;
            int dataUriCount = 0;
            int dataB64 = 0;
            var dataExtCounts = new Dictionary<string,int>(StringComparer.OrdinalIgnoreCase);
            // URLs (absolute http/https)
            int i = 0; var s = text;
            while (i < s.Length)
            {
                int at = s.IndexOf("http", i, StringComparison.OrdinalIgnoreCase); if (at < 0) break;
                int end = at; while (end < s.Length && !char.IsWhiteSpace(s[end]) && s[end] != '"' && s[end] != '\'' && s[end] != ')' && s[end] != '<' && s[end] != '>' && s[end] != '`') end++;
                var cand = s.Substring(at, end - at);
                if (Uri.TryCreate(cand, UriKind.Absolute, out var u) && (u.Scheme == Uri.UriSchemeHttp || u.Scheme == Uri.UriSchemeHttps))
                {
                    refs.Add(new Reference { Kind = ReferenceKind.Url, Value = cand, SourceTag = "script:" + ext });
                }
                i = end + 1;
            }
            // UNC paths (roots)
            // Simple UNC scanner (reuse minimal logic here to avoid dependencies)
            var span = text.AsSpan();
            int p = 0; while (p + 3 < span.Length)
            {
                if (span[p] == '\\' && span[p+1] == '\\')
                {
                    int start = p; p += 2; int sHost = p; while (p < span.Length && (char.IsLetterOrDigit(span[p]) || span[p] == '.' || span[p] == '-' || span[p] == '_')) p++; if (p <= sHost || p >= span.Length || span[p] != '\\') { p++; continue; }
                    string server = span.Slice(sHost, p - sHost).ToString(); p++;
                    int sShare = p; while (p < span.Length && (char.IsLetterOrDigit(span[p]) || span[p] == '.' || span[p] == '-' || span[p] == '_' || span[p] == '$')) p++;
                    if (p > sShare)
                    {
                        string share = span.Slice(sShare, p - sShare).ToString();
                        refs.Add(new Reference { Kind = ReferenceKind.FilePath, Value = "\\\\" + server + "\\" + share, SourceTag = "script:" + ext, Issues = ReferenceIssue.UncPath });
                    }
                }
                else p++;
            }

            // data: URIs inside scripts (strings or code)
            int di = 0;
            while (di < text.Length)
            {
                int at = text.IndexOf("data:", di, StringComparison.OrdinalIgnoreCase); if (at < 0) break;
                if (!LooksLikeScriptDataUriStart(text, at))
                {
                    di = at + 5;
                    continue;
                }

                var cand = ReadScriptDataUriCandidate(text, at, out int consumedEnd);
                if (TryClassifyDataUriPayload(cand, out var innerExt, out bool isBase64))
                {
                    dataUriCount++;
                    if (isBase64) dataB64++;
                    if (!string.IsNullOrWhiteSpace(innerExt))
                    {
                        var k = innerExt!.ToLowerInvariant();
                        dataExtCounts[k] = dataExtCounts.TryGetValue(k, out var c) ? c + 1 : 1;
                    }
                }
                di = Math.Max(consumedEnd + 1, at + 5);
            }

            if (dataUriCount > 0)
            {
                refs.Add(new Reference { Kind = ReferenceKind.Command, Value = $"script:data-uri={dataUriCount}", SourceTag = "summary" });
                if (dataB64 > 0)
                    refs.Add(new Reference { Kind = ReferenceKind.Command, Value = $"script:data-b64={dataB64}", SourceTag = "summary" });
                if (dataExtCounts.Count > 0)
                {
                    var headExts = string.Join(",", dataExtCounts.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key).Select(kv => kv.Key + ":" + kv.Value));
                    refs.Add(new Reference { Kind = ReferenceKind.Command, Value = $"script:data-exts={headExts}", SourceTag = "summary" });
                }
            }

            static bool LooksLikeScriptDataUriStart(string script, int index)
            {
                if (index < 0 || index >= script.Length) return false;
                if (IsInsideScriptComment(script, index)) return false;
                if (index == 0) return true;

                char prev = script[index - 1];
                return prev == '"' || prev == '\'' || prev == '`';
            }

            static bool IsInsideScriptComment(string script, int index)
            {
                bool inLineComment = false;
                bool inBlockComment = false;
                bool inSingle = false;
                bool inDouble = false;
                bool inTemplate = false;

                for (int i = 0; i < index && i < script.Length; i++)
                {
                    char c = script[i];
                    char next = i + 1 < script.Length ? script[i + 1] : '\0';

                    if (inLineComment)
                    {
                        if (c == '\r' || c == '\n')
                            inLineComment = false;
                        continue;
                    }

                    if (inBlockComment)
                    {
                        if (c == '*' && next == '/')
                        {
                            inBlockComment = false;
                            i++;
                        }
                        continue;
                    }

                    if (inSingle)
                    {
                        if (c == '\\' && i + 1 < script.Length) { i++; continue; }
                        if (c == '\'') inSingle = false;
                        continue;
                    }

                    if (inDouble)
                    {
                        if (c == '\\' && i + 1 < script.Length) { i++; continue; }
                        if (c == '"') inDouble = false;
                        continue;
                    }

                    if (inTemplate)
                    {
                        if (c == '\\' && i + 1 < script.Length) { i++; continue; }
                        if (c == '`') inTemplate = false;
                        continue;
                    }

                    if (c == '/' && next == '/')
                    {
                        inLineComment = true;
                        i++;
                        continue;
                    }

                    if (c == '/' && next == '*')
                    {
                        inBlockComment = true;
                        i++;
                        continue;
                    }

                    if (c == '\'') { inSingle = true; continue; }
                    if (c == '"') { inDouble = true; continue; }
                    if (c == '`') { inTemplate = true; continue; }
                }

                return inLineComment || inBlockComment;
            }
        }
        catch { }
    }

    private static void TryExtractHtmlReferences(string path, List<Reference> refs)
    {
        try {
            var text = ReadTextForReferences(path, Settings.ReferenceExtractionMaxBytes);
            if (string.IsNullOrWhiteSpace(text)) return;
            int cap = Math.Min(text.Length, 512 * 1024);
            var head = text.AsSpan(0, cap);

            int cdnCount = 0;
            var hostCounts = new Dictionary<string,int>(StringComparer.OrdinalIgnoreCase);
            int dataUriCount = 0;
            int dataB64Count = 0;
            var dataInnerExtCounts = new Dictionary<string,int>(StringComparer.OrdinalIgnoreCase);
            foreach (var attr in new [] { "href", "src", "data", "action" })
            {
                int idx = 0;
                while (idx < head.Length)
                {
                    int at = IndexOfAttrCI(head, attr, idx); if (at < 0) break; idx = at + attr.Length;
                    var val = ReadAttrValue(head, at + attr.Length);
                    if (string.IsNullOrWhiteSpace(val)) continue;
                    var v = val.Trim();
                    if (IsAbsoluteHttpUrl(v) || IsProtocolRelative(v))
                    {
                        string tag = "html:" + attr;
                        var host = TryGetHost(v);
                        if (!string.IsNullOrEmpty(host))
                        {
                            if (IsCdnHost(host!)) { tag += ":cdn"; cdnCount++; }
                            hostCounts[host!] = hostCounts.TryGetValue(host!, out var c) ? c + 1 : 1;
                        }
                        refs.Add(new Reference { Kind = ReferenceKind.Url, Value = v, SourceTag = tag });
                    }
                    else if (v.StartsWith("data:", StringComparison.OrdinalIgnoreCase))
                    {
                        if (TryClassifyDataUriPayload(v, out var innerExt, out bool isBase64))
                        {
                            dataUriCount++;
                            if (isBase64) dataB64Count++;
                            if (!string.IsNullOrWhiteSpace(innerExt))
                            {
                                var k = innerExt!.ToLowerInvariant();
                                dataInnerExtCounts[k] = dataInnerExtCounts.TryGetValue(k, out var c) ? c + 1 : 1;
                            }
                        }
                    }
                    else if (LooksLikeUnc(v) || v.StartsWith("file://", StringComparison.OrdinalIgnoreCase))
                    {
                        var expanded = ExpandEnv(v);
                        var issues = ReferenceIssue.UncPath;
                        bool? exists = null;
                        if (Settings.CheckNetworkPathsInReferences)
                        {
                            try { exists = Directory.Exists(GetUncShareRoot(v)); } catch { exists = null; }
                        }
                        refs.Add(new Reference { Kind = ReferenceKind.FilePath, Value = v, ExpandedValue = expanded, Exists = exists, Issues = issues, SourceTag = "html:" + attr });
                    }
                }
            }

            // CSS url(...) pattern within inline styles
            int pos = 0;
            while (pos < head.Length)
            {
                int up = IndexOfCssUrlToken(head, pos); if (up < 0) break; int start = up + 4; int end = head.Slice(start).IndexOf(')'); if (end < 0) break; end += start; var raw = head.Slice(start, Math.Max(0, end - start)).ToString().Trim('"', '\'', ' ', '\t', '\r', '\n'); pos = end + 1;
                if (string.IsNullOrWhiteSpace(raw)) continue;
                if (IsAbsoluteHttpUrl(raw) || IsProtocolRelative(raw))
                {
                    string tag = "html:css-url";
                    var host = TryGetHost(raw);
                    if (!string.IsNullOrEmpty(host))
                    {
                        if (IsCdnHost(host!)) { tag += ":cdn"; cdnCount++; }
                        hostCounts[host!] = hostCounts.TryGetValue(host!, out var c) ? c + 1 : 1;
                    }
                    refs.Add(new Reference { Kind = ReferenceKind.Url, Value = raw, SourceTag = tag });
                }
                else if (raw.StartsWith("data:", StringComparison.OrdinalIgnoreCase))
                {
                    if (TryClassifyDataUriPayload(raw, out var innerExt, out bool isBase64))
                    {
                        dataUriCount++;
                        if (isBase64) dataB64Count++;
                        if (!string.IsNullOrWhiteSpace(innerExt))
                        {
                            var k = innerExt!.ToLowerInvariant();
                            dataInnerExtCounts[k] = dataInnerExtCounts.TryGetValue(k, out var c) ? c + 1 : 1;
                        }
                    }
                }
                else if (LooksLikeUnc(raw) || raw.StartsWith("file://", StringComparison.OrdinalIgnoreCase))
                {
                    var expanded = ExpandEnv(raw);
                    bool? exists = null; if (Settings.CheckNetworkPathsInReferences) { try { exists = Directory.Exists(GetUncShareRoot(raw)); } catch { exists = null; } }
                    refs.Add(new Reference { Kind = ReferenceKind.FilePath, Value = raw, ExpandedValue = expanded, Exists = exists, Issues = ReferenceIssue.UncPath, SourceTag = "html:css-url" });
                }
            }
            // Attach summary finding for CDN usage if any
            if (cdnCount > 0)
            {
                refs.Add(new Reference { Kind = ReferenceKind.Command, Value = $"html:cdn={cdnCount}", SourceTag = "summary" });
            }
            // Top external domains summary (first 3 by frequency)
            if (hostCounts.Count > 0)
            {
                var top = hostCounts.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key).Take(3).Select(kv => kv.Key);
                var joined = string.Join(",", top);
                refs.Add(new Reference { Kind = ReferenceKind.Command, Value = $"html:hosts={joined}", SourceTag = "summary" });
            }
            // Data URI summary
            if (dataUriCount > 0)
            {
                refs.Add(new Reference { Kind = ReferenceKind.Command, Value = $"html:data-uri={dataUriCount}", SourceTag = "summary" });
                if (dataB64Count > 0)
                    refs.Add(new Reference { Kind = ReferenceKind.Command, Value = $"html:data-b64={dataB64Count}", SourceTag = "summary" });
                if (dataInnerExtCounts.Count > 0)
                {
                    var headExts = string.Join(",", dataInnerExtCounts.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key).Select(kv => kv.Key + ":" + kv.Value));
                    refs.Add(new Reference { Kind = ReferenceKind.Command, Value = $"html:data-exts={headExts}", SourceTag = "summary" });
                }
            }
        } catch { }

        static int IndexOfAttrCI(ReadOnlySpan<char> s, string attr, int from)
        {
            // find attr ignoring case and allowing whitespace before '='
            int at = IndexOfTokenCI(s, attr, from); if (at < 0) return -1;
            int p = at + attr.Length; while (p < s.Length && char.IsWhiteSpace(s[p])) p++;
            if (p < s.Length && s[p] == '=') return at; else return IndexOfAttrCI(s, attr, p);
        }
        static string ReadAttrValue(ReadOnlySpan<char> s, int afterAttr)
        {
            int p = afterAttr; while (p < s.Length && char.IsWhiteSpace(s[p])) p++; if (p >= s.Length || s[p] != '=') return string.Empty; p++; while (p < s.Length && char.IsWhiteSpace(s[p])) p++; if (p >= s.Length) return string.Empty;
            char quote = s[p]; bool quoted = quote == '"' || quote == '\''; if (quoted) p++; int start = p; while (p < s.Length) { char c = s[p]; if (quoted) { if (c == quote) break; } else { if (char.IsWhiteSpace(c) || c == '>') break; } p++; }
            var val = s.Slice(start, Math.Max(0, p - start)).ToString();
            return val;
        }
        static int IndexOfTokenCI(ReadOnlySpan<char> hay, string token, int from)
        {
            var t = token.AsSpan(); int n = hay.Length - t.Length; for (int i = Math.Max(0, from); i <= n; i++) { bool ok = true; for (int j = 0; j < t.Length; j++) { char a = char.ToLowerInvariant(hay[i + j]); char b = char.ToLowerInvariant(t[j]); if (a != b) { ok = false; break; } } if (ok) return i; } return -1;
        }
        static int IndexOfCssUrlToken(ReadOnlySpan<char> hay, int from)
        {
            bool inSingle = false, inDouble = false, inComment = false;
            for (int i = Math.Max(0, from); i <= hay.Length - 4; i++)
            {
                char c = hay[i];
                char next = i + 1 < hay.Length ? hay[i + 1] : '\0';

                if (inComment)
                {
                    if (c == '*' && next == '/')
                    {
                        inComment = false;
                        i++;
                    }
                    continue;
                }

                if (inSingle)
                {
                    if (c == '\\' && i + 1 < hay.Length) { i++; continue; }
                    if (c == '\'') inSingle = false;
                    continue;
                }

                if (inDouble)
                {
                    if (c == '\\' && i + 1 < hay.Length) { i++; continue; }
                    if (c == '"') inDouble = false;
                    continue;
                }

                if (c == '/' && next == '*')
                {
                    inComment = true;
                    i++;
                    continue;
                }

                if (c == '\'') { inSingle = true; continue; }
                if (c == '"') { inDouble = true; continue; }

                if ((c == 'u' || c == 'U') &&
                    i + 3 < hay.Length &&
                    char.ToLowerInvariant(hay[i + 1]) == 'r' &&
                    char.ToLowerInvariant(hay[i + 2]) == 'l' &&
                    hay[i + 3] == '(')
                    return i;
            }

            return -1;
        }
        static bool IsAbsoluteHttpUrl(string s) => s.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || s.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
        static bool IsProtocolRelative(string s) => s.StartsWith("//");
        static bool LooksLikeUnc(string s) => s.StartsWith("\\\\") || s.StartsWith("//");
        static string? TryGetHost(string url)
        {
            try
            {
                if (url.StartsWith("//")) url = "http:" + url;
                if (Uri.TryCreate(url, UriKind.Absolute, out var u)) return u.Host;
            } catch { }
            return null;
        }
        static bool IsCdnHost(string host)
        {
            var h = host.ToLowerInvariant();
            if (h.StartsWith("cdn.")) return true;
            // common public CDN/provider suffixes
            string[] suffixes = new [] {
                ".cloudfront.net", ".akamaihd.net", ".akamai.net", ".edgesuite.net", ".edgekey.net",
                ".fastly.net", ".cdn.jsdelivr.net", ".jsdelivr.net", ".bootstrapcdn.com", ".cdnjs.cloudflare.com",
                ".gstatic.com", ".googleapis.com", ".unpkg.com", ".cloudflare.com"
            };
            foreach (var s in suffixes) if (h.EndsWith(s)) return true;
            return false;
        }
        static string GetUncShareRoot(string s)
        {
            try {
                if (s.StartsWith("file://", StringComparison.OrdinalIgnoreCase)) s = s.Substring(7);
                s = s.Replace('/', '\\');
                if (s.StartsWith("\\\\"))
                {
                    // \\server\share\...
                    var parts = s.Split(new[]{'\\'}, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 2) return "\\\\" + parts[0] + "\\" + parts[1];
                }
            } catch { }
            return s;
        }
    }

    private static bool TryClassifyDataUriPayload(string uri, out string? innerExt, out bool isBase64)
    {
        innerExt = null;
        isBase64 = false;
        try
        {
            if (!TryParseDataUriPayload(uri, out var mediaType, out var sample, out isBase64))
                return false;

            if (sample != null && sample.Length > 0)
            {
                try
                {
                    var det = FileInspector.Detect(new ReadOnlySpan<byte>(sample, 0, Math.Min(sample.Length, Settings.EncodedDecodeMaxBytes)), null);
                    var ext = (det?.Extension ?? string.Empty).Trim().TrimStart('.').ToLowerInvariant();
                    if (!string.IsNullOrWhiteSpace(ext) && ext is not "txt" and not "log")
                        innerExt = ext;
                }
                catch { }
            }

            if (string.IsNullOrWhiteSpace(innerExt))
                innerExt = InferDataUriExtensionFromMediaType(mediaType);

            return true;
        }
        catch { return false; }
    }

    private static string ReadScriptDataUriCandidate(string text, int startAt, out int consumedEnd)
    {
        consumedEnd = startAt;
        if (string.IsNullOrEmpty(text) || startAt < 0 || startAt >= text.Length)
            return string.Empty;

        var sb = new System.Text.StringBuilder();
        int cursor = startAt;
        int segments = 0;
        while (cursor < text.Length && segments < 8)
        {
            int end = ReadDataUriSegment(text, cursor, sb, ref consumedEnd);
            if (end <= cursor)
                break;
            segments++;

            if (end >= text.Length || !IsStringDelimiter(text[end]))
                break;

            int p = end + 1;
            bool continued = false;
            while (true)
            {
                p = SkipWhitespaceAndClosers(text, p);
                if (TryConsumeConcatCall(text, p, sb, ref consumedEnd, out int concatEnd))
                {
                    p = concatEnd;
                    continued = true;
                    continue;
                }

                if (p >= text.Length || text[p] != '+')
                    break;

                p++;
                if (!TryConsumeStringExpressionPiece(text, p, sb, ref consumedEnd, out int pieceEnd))
                    break;

                p = pieceEnd;
                continued = true;
                continue;
            }

            if (!continued)
                break;

            cursor = p;
        }

        return sb.ToString();

        static int ReadDataUriSegment(string value, int start, System.Text.StringBuilder buffer, ref int consumed)
        {
            int cursor = start;
            int end = start;
            while (end < value.Length)
            {
                if (value[end] == '$' && end + 1 < value.Length && value[end + 1] == '{')
                {
                    if (end > cursor)
                        buffer.Append(value, cursor, end - cursor);

                    consumed = Math.Max(consumed, end + 1);
                    if (!TryReadSimpleStringExpression(value, end + 2, "}", out var interpolationValue, out int interpolationEnd))
                        return end;

                    buffer.Append(interpolationValue);
                    consumed = Math.Max(consumed, interpolationEnd);
                    end = interpolationEnd + 1;
                    cursor = end;
                    continue;
                }

                if (IsTerminal(value[end]))
                    break;

                end++;
            }

            if (end > cursor)
                buffer.Append(value, cursor, end - cursor);

            consumed = Math.Max(consumed, end);
            return end;
        }

        static bool TryConsumeConcatCall(string value, int start, System.Text.StringBuilder buffer, ref int consumed, out int nextIndex)
        {
            nextIndex = start;
            const string concatToken = ".concat";
            if (start < 0 || start >= value.Length) return false;
            if (!value.AsSpan(start).StartsWith(concatToken.AsSpan(), StringComparison.Ordinal))
                return false;

            int p = start + concatToken.Length;
            while (p < value.Length && char.IsWhiteSpace(value[p])) p++;
            if (p >= value.Length || value[p] != '(')
                return false;
            p++;

            bool appended = false;
            while (p < value.Length)
            {
                p = SkipWhitespaceAndOpeners(value, p);
                if (p >= value.Length) return false;
                if (value[p] == ')')
                {
                    nextIndex = p + 1;
                    consumed = Math.Max(consumed, p);
                    return appended;
                }

                if (!TryReadSimpleStringExpression(value, p, ",)", out var segment, out int segmentEnd))
                    return false;

                buffer.Append(segment);
                appended = true;
                p = segmentEnd;
                consumed = Math.Max(consumed, segmentEnd);
                if (p >= value.Length) return false;
                if (value[p] == ',')
                {
                    p++;
                    continue;
                }

                if (value[p] == ')')
                {
                    nextIndex = p + 1;
                    consumed = Math.Max(consumed, p);
                    return true;
                }

                return false;
            }

            return false;
        }

        static bool TryConsumeStringExpressionPiece(string value, int start, System.Text.StringBuilder buffer, ref int consumed, out int nextIndex)
        {
            nextIndex = start;
            int p = SkipWhitespaceAndOpeners(value, start);
            if (p >= value.Length)
                return false;

            if (IsStringDelimiter(value[p]))
            {
                if (!TryReadQuotedStringLiteral(value, p, out var literal, out int literalEnd))
                    return false;

                buffer.Append(literal);
                consumed = Math.Max(consumed, literalEnd);
                nextIndex = literalEnd + 1;
                return true;
            }

            if (!TryReadSimpleArrayJoinExpression(value, p, out var joined, out int joinEnd))
                return false;

            buffer.Append(joined);
            consumed = Math.Max(consumed, joinEnd - 1);
            nextIndex = joinEnd;
            return true;
        }

        static bool TryReadSimpleStringExpression(string value, int start, string terminators, out string result, out int endIndex)
        {
            result = string.Empty;
            endIndex = start;
            var local = new System.Text.StringBuilder();
            int p = start;
            int parenDepth = 0;

            while (p < value.Length)
            {
                p = SkipWhitespace(value, p);
                while (p < value.Length && value[p] == '(')
                {
                    parenDepth++;
                    p++;
                    p = SkipWhitespace(value, p);
                }

                if (!TryConsumeStringExpressionPiece(value, p, local, ref endIndex, out int pieceEnd))
                    return false;

                p = pieceEnd;
                p = SkipWhitespace(value, p);
                while (true)
                {
                    while (parenDepth > 0 && p < value.Length && value[p] == ')')
                    {
                        parenDepth--;
                        p++;
                        p = SkipWhitespace(value, p);
                    }

                    int concatConsumed = p;
                    if (!TryConsumeConcatCall(value, p, local, ref concatConsumed, out int concatEnd))
                        break;

                    p = SkipWhitespace(value, concatEnd);
                }

                if (p >= value.Length)
                    return false;

                if (value[p] == '+')
                {
                    p++;
                    continue;
                }

                if (terminators.IndexOf(value[p]) >= 0)
                {
                    result = local.ToString();
                    endIndex = p;
                    return result.Length > 0;
                }

                return false;
            }

            return false;
        }

        static bool TryReadSimpleArrayJoinExpression(string value, int start, out string result, out int nextIndex)
        {
            result = string.Empty;
            nextIndex = start;
            if (start < 0 || start >= value.Length || value[start] != '[')
                return false;

            var local = new System.Text.StringBuilder();
            bool hasItems = false;
            int p = start + 1;
            while (p < value.Length)
            {
                p = SkipWhitespace(value, p);
                if (p >= value.Length)
                    return false;

                if (value[p] == ']')
                {
                    p++;
                    break;
                }

                if (!TryReadQuotedStringLiteral(value, p, out var item, out int itemEnd))
                    return false;

                local.Append(item);
                hasItems = true;
                p = itemEnd + 1;
                p = SkipWhitespace(value, p);
                if (p >= value.Length)
                    return false;

                if (value[p] == ',')
                {
                    p++;
                    continue;
                }

                if (value[p] == ']')
                {
                    p++;
                    break;
                }

                return false;
            }

            if (!hasItems)
                return false;

            p = SkipWhitespace(value, p);
            const string joinToken = ".join";
            if (p >= value.Length || !value.AsSpan(p).StartsWith(joinToken.AsSpan(), StringComparison.Ordinal))
                return false;

            p += joinToken.Length;
            p = SkipWhitespace(value, p);
            if (p >= value.Length || value[p] != '(')
                return false;

            p++;
            p = SkipWhitespace(value, p);
            if (!TryReadQuotedStringLiteral(value, p, out var separator, out int separatorEnd))
                return false;

            if (separator.Length != 0)
                return false;

            p = separatorEnd + 1;
            p = SkipWhitespace(value, p);
            if (p >= value.Length || value[p] != ')')
                return false;

            nextIndex = p + 1;
            result = local.ToString();
            return true;
        }

        static bool TryReadQuotedStringLiteral(string value, int start, out string result, out int endIndex)
        {
            result = string.Empty;
            endIndex = start;
            if (start >= value.Length || !IsStringDelimiter(value[start]))
                return false;

            char delimiter = value[start];
            var local = new System.Text.StringBuilder();
            for (int i = start + 1; i < value.Length; i++)
            {
                char ch = value[i];
                if (ch == '\\')
                {
                    if (i + 1 >= value.Length)
                        return false;

                    local.Append(value[i + 1]);
                    i++;
                    continue;
                }

                if (delimiter == '`' && ch == '$' && i + 1 < value.Length && value[i + 1] == '{')
                    return false;

                if (ch == delimiter)
                {
                    result = local.ToString();
                    endIndex = i;
                    return true;
                }

                local.Append(ch);
            }

            return false;
        }

        static bool IsTerminal(char c)
            => c == '"' || c == '\'' || c == '`' || char.IsWhiteSpace(c) || c == ')' || c == '<' || c == '>';

        static bool IsStringDelimiter(char c) => c == '"' || c == '\'' || c == '`';
        static int SkipWhitespaceAndClosers(string value, int index)
        {
            int p = index;
            while (p < value.Length)
            {
                if (char.IsWhiteSpace(value[p]) || value[p] == ')')
                {
                    p++;
                    continue;
                }

                break;
            }

            return p;
        }

        static int SkipWhitespace(string value, int index)
        {
            int p = index;
            while (p < value.Length && char.IsWhiteSpace(value[p]))
                p++;
            return p;
        }

        static int SkipWhitespaceAndOpeners(string value, int index)
        {
            int p = index;
            while (p < value.Length)
            {
                if (char.IsWhiteSpace(value[p]) || value[p] == '(')
                {
                    p++;
                    continue;
                }

                break;
            }

            return p;
        }
    }

    private static bool TryParseDataUriPayload(string uri, out string? mediaType, out byte[]? sample, out bool isBase64)
    {
        mediaType = null;
        sample = null;
        isBase64 = false;
        try
        {
            if (!uri.StartsWith("data:", StringComparison.OrdinalIgnoreCase)) return false;
            int comma = uri.IndexOf(','); if (comma < 0) return false;
            var header = uri.Substring(5, comma - 5); // between data: and comma
            var lower = header.ToLowerInvariant();
            // Extract media type before first ';'
            int sc = header.IndexOf(';');
            if (sc > 0) mediaType = header.Substring(0, sc).Trim();
            else if (!string.IsNullOrWhiteSpace(header)) mediaType = header.Trim();
            string payload = uri.Substring(comma + 1);
            int maxDecodedBytes = Math.Max(1, Settings.EncodedDecodeMaxBytes);
            isBase64 = lower.Contains(";base64");
            if (isBase64)
            {
                int maxBase64Chars = ((maxDecodedBytes + 2) / 3) * 4 + 8;
                var sb = new System.Text.StringBuilder(Math.Min(payload.Length, maxBase64Chars));
                foreach (var ch in payload)
                {
                    if (sb.Length >= maxBase64Chars) break;
                    if (ch == '-') sb.Append('+');
                    else if (ch == '_') sb.Append('/');
                    else if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '+' || ch == '/' || ch == '=') sb.Append(ch);
                }
                var s = sb.ToString(); int mod = s.Length % 4; if (mod != 0) s = s.PadRight(s.Length + (4 - mod), '=');
                var raw = Convert.FromBase64String(s);
                int max = Math.Min(raw.Length, maxDecodedBytes);
                sample = raw.Take(max).ToArray();
                return sample.Length > 0;
            }

            var bytes = new List<byte>(Math.Min(maxDecodedBytes, Math.Max(16, payload.Length)));
            for (int i = 0; i < payload.Length && bytes.Count < maxDecodedBytes; i++)
            {
                char ch = payload[i];
                if (ch == '%' && i + 2 < payload.Length && Uri.IsHexDigit(payload[i + 1]) && Uri.IsHexDigit(payload[i + 2]))
                {
                    bytes.Add(Convert.ToByte(payload.Substring(i + 1, 2), 16));
                    i += 2;
                    continue;
                }

                if (ch <= 0x7F)
                {
                    bytes.Add((byte)ch);
                    continue;
                }

                var utf8 = System.Text.Encoding.UTF8.GetBytes(ch.ToString());
                foreach (var b in utf8)
                {
                    if (bytes.Count >= maxDecodedBytes) break;
                    bytes.Add(b);
                }
            }

            sample = bytes.Count > 0 ? bytes.ToArray() : Array.Empty<byte>();
            return sample.Length > 0;
        } catch { return false; }
    }

    private static string? InferDataUriExtensionFromMediaType(string? mediaType)
    {
        if (string.IsNullOrWhiteSpace(mediaType)) return null;
        var normalized = mediaType!.Trim().ToLowerInvariant();
        return normalized switch
        {
            "application/javascript" or "text/javascript" or "application/x-javascript" => "js",
            "text/html" => "html",
            "application/json" or "text/json" => "json",
            "application/xml" or "text/xml" => "xml",
            "image/svg+xml" => "svg",
            "text/css" => "css",
            "text/plain" => "txt",
            "text/x-powershell" or "application/x-powershell" => "ps1",
            "text/vbscript" => "vbs",
            "text/x-shellscript" or "application/x-sh" => "sh",
            _ => null
        };
    }

    private static void TryExtractInternetShortcut(string path, List<Reference> refs)
    {
        try
        {
            var text = ReadTextForReferences(path, Settings.ReferenceExtractionMaxBytes);
            if (string.IsNullOrWhiteSpace(text)) return;
            var lines = text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
            foreach (var line in lines)
            {
                var t = line.Trim();
                if (t.StartsWith("URL=", StringComparison.OrdinalIgnoreCase))
                {
                    var url = t.Substring(4).Trim();
                    if (!string.IsNullOrWhiteSpace(url)) refs.Add(new Reference { Kind = ReferenceKind.Url, Value = url, SourceTag = "url:file" });
                }
            }
        } catch { }
    }

    private static void TryExtractWindowsLnk(string path, List<Reference> refs)
    {
        try
        {
            using var fs = File.OpenRead(path);
            var hdr = new byte[Math.Min(4096, fs.Length)];
            int n = fs.Read(hdr, 0, hdr.Length);
            if (n < 32) return;
            // Quick signature: header size 0x4C at offset 0
            if (hdr[0] != 0x4C || hdr[1] != 0x00) { /* not strict */ }
            // Best-effort: scan ASCII for plausible target path
            string ascii = System.Text.Encoding.ASCII.GetString(hdr, 0, n);
            string? best = null;
            foreach (var token in new [] { ":\\", "\\\\" })
            {
                int idx = ascii.IndexOf(token, StringComparison.Ordinal);
                if (idx > 0)
                {
                    // backtrack to start of token (letter for drive or \\\\)
                    int start = idx;
                    while (start > 0 && ascii[start-1] >= 32 && ascii[start-1] < 127) start--;
                    int end = idx + token.Length;
                    while (end < ascii.Length && ascii[end] >= 32 && ascii[end] < 127) end++;
                    var cand = ascii.Substring(start, end - start).Trim('\0');
                    if (cand.Length >= 3) { best = cand; break; }
                }
            }
            if (!string.IsNullOrEmpty(best))
            {
                var exp = ExpandEnv(best!);
                var issues = ComputePathIssues(best!, exp, treatAsCommandHead: true);
                bool exi = FileExistsSafe(exp);
                refs.Add(new Reference { Kind = ReferenceKind.FilePath, Value = best!, ExpandedValue = exp, Exists = exi, Issues = issues, SourceTag = "lnk:target" });
            }
        } catch { }
    }

    private static bool LooksLikeTaskXml(string path)
    {
        try {
            using var fs = File.OpenRead(path);
            var head = new byte[Math.Min(8192, (int)Math.Min(fs.Length, 8192))];
            int n = fs.Read(head, 0, head.Length);
            var s = System.Text.Encoding.UTF8.GetString(head, 0, n);
            return s.IndexOf("<Task", StringComparison.OrdinalIgnoreCase) >= 0 && (s.IndexOf("<Exec", StringComparison.OrdinalIgnoreCase) >= 0 || s.IndexOf("<Actions", StringComparison.OrdinalIgnoreCase) >= 0);
        } catch { return false; }
    }

    private static void TryExtractGpoScriptsXml(string path, List<Reference> refs)
    {
        try {
            var text = ReadTextForReferences(path, Settings.ReferenceExtractionMaxBytes);
            // Look for <Scripts> ... <Script ...> or <PowerShellScript ...>
            if (IndexOfCI(text, "<Scripts") < 0 && IndexOfCI(text, "<PowerShellScript") < 0) return;

            // Extract common elements/attributes: Command, Parameters, Script, Path
            static IEnumerable<string> ExtractMany(string hay, string tag)
            {
                int start = 0;
                while (true)
                {
                    var open = "<" + tag + ">"; var close = "</" + tag + ">";
                    int a = hay.IndexOf(open, start, StringComparison.OrdinalIgnoreCase); if (a < 0) yield break; a += open.Length;
                    int b = hay.IndexOf(close, a, StringComparison.OrdinalIgnoreCase); if (b < 0) yield break;
                    yield return hay.Substring(a, b - a).Trim();
                    start = b + close.Length;
                }
            }

            foreach (var cmd in ExtractMany(text, "Command").Concat(ExtractMany(text, "Script").Concat(ExtractMany(text, "Path"))))
            {
                refs.Add(new Reference { Kind = ReferenceKind.Command, Value = cmd, SourceTag = "gpo:scripts.xml" });
                if (LooksLikePath(cmd))
                {
                    var exp = ExpandEnv(cmd);
                    var iss = ComputePathIssues(cmd, exp, treatAsCommandHead: true);
                    bool exi = FileExistsSafe(exp);
                    refs.Add(new Reference { Kind = ReferenceKind.FilePath, Value = cmd, ExpandedValue = exp, Exists = exi, Issues = iss, SourceTag = "gpo:scripts.xml" });
                }
            }
            foreach (var par in ExtractMany(text, "Parameters"))
            {
                foreach (var tok in TokenizeArgs(par))
                {
                    if (IsUrl(tok)) refs.Add(new Reference { Kind = ReferenceKind.Url, Value = tok, SourceTag = "gpo:scripts.xml" });
                    else if (LooksLikePath(tok))
                    {
                        var exp = ExpandEnv(tok);
                        var iss = ComputePathIssues(tok, exp, treatAsCommandHead: false);
                        bool exi = FileExistsSafe(exp);
                        refs.Add(new Reference { Kind = ReferenceKind.FilePath, Value = tok, ExpandedValue = exp, Exists = exi, Issues = iss, SourceTag = "gpo:scripts.xml" });
                    }
                }
            }
        } catch { }
    }

    private static void TryExtractTaskSchedulerXml(string path, List<Reference> refs)
    {
        // Preferred: parse as XML with namespace awareness; fallback to lenient text extraction
        if (!TryExtractTaskSchedulerXmlDoc(path, refs))
        {
            try {
                var text = ReadTextForReferences(path, Settings.ReferenceExtractionMaxBytes);
                string? ExtractCI(string tag)
                {
                    var open = "<" + tag + ">"; var close = "</" + tag + ">";
                    int a = IndexOfCI(text, open); if (a < 0) return null; a += open.Length;
                    int b = IndexOfCI(text, close, a); if (b < 0) return null;
                    return text.Substring(a, b - a).Trim();
                }
                var command = ExtractCI("Command");
                var arguments = ExtractCI("Arguments");
                var workingDir = ExtractCI("WorkingDirectory");
                var clsid = ExtractCI("ClassId");
                EmitTaskRefs(command, arguments, workingDir, clsid, refs);
            } catch { }
        }
    }

    private static bool TryExtractTaskSchedulerXmlDoc(string path, List<Reference> refs)
    {
        try {
            var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, IgnoreComments = true, IgnoreProcessingInstructions = true, IgnoreWhitespace = true, CloseInput = true, XmlResolver = null };
            using var fs = File.OpenRead(path);
            using var xr = XmlReader.Create(fs, settings);
            var doc = new XmlDocument { XmlResolver = null };
            doc.Load(xr);

            var root = doc.DocumentElement; if (root == null || !root.Name.EndsWith("Task", StringComparison.OrdinalIgnoreCase)) return false;
            string ns = root.NamespaceURI ?? string.Empty;
            var nsm = new XmlNamespaceManager(doc.NameTable);
            if (!string.IsNullOrEmpty(ns)) nsm.AddNamespace("t", ns);

            // Exec nodes (there may be multiple)
            var execNodes = !string.IsNullOrEmpty(ns)
                ? doc.SelectNodes("//t:Actions/t:Exec", nsm)
                : doc.SelectNodes("//Actions/Exec");

            if (execNodes != null)
            {
                foreach (XmlNode exec in execNodes)
                {
                    string? command = null, args = null, work = null;
                    var cmdNode = !string.IsNullOrEmpty(ns) ? exec.SelectSingleNode("t:Command", nsm) : exec.SelectSingleNode("Command");
                    var argNode = !string.IsNullOrEmpty(ns) ? exec.SelectSingleNode("t:Arguments", nsm) : exec.SelectSingleNode("Arguments");
                    var wdNode  = !string.IsNullOrEmpty(ns) ? exec.SelectSingleNode("t:WorkingDirectory", nsm) : exec.SelectSingleNode("WorkingDirectory");
                    if (cmdNode != null) command = cmdNode.InnerText;
                    if (argNode != null) args = argNode.InnerText;
                    if (wdNode  != null) work = wdNode.InnerText;
                    EmitTaskRefs(command, args, work, clsid: null, refs);
                }
            }

            // ComHandler ClassId
            var clsidNode = !string.IsNullOrEmpty(ns)
                ? doc.SelectSingleNode("//t:Actions/t:ComHandler/t:ClassId", nsm)
                : doc.SelectSingleNode("//Actions/ComHandler/ClassId");
            if (clsidNode != null)
            {
                EmitTaskRefs(null, null, null, clsidNode.InnerText, refs);
            }

            // Hints: RunLevel and LogonType
            var rlNode = !string.IsNullOrEmpty(ns) ? doc.SelectSingleNode("//t:Principals/t:Principal/t:RunLevel", nsm) : doc.SelectSingleNode("//Principals/Principal/RunLevel");
            var ltNode = !string.IsNullOrEmpty(ns) ? doc.SelectSingleNode("//t:Principals/t:Principal/@logonType", nsm) : doc.SelectSingleNode("//Principals/Principal/@logonType");
            if (rlNode != null) refs.Add(new Reference { Kind = ReferenceKind.Command, Value = "task:runlevel=" + rlNode.InnerText, SourceTag = "task:hints" });
            if (ltNode != null) refs.Add(new Reference { Kind = ReferenceKind.Command, Value = "task:logontype=" + ltNode.Value, SourceTag = "task:hints" });
            return refs.Count > 0;
        } catch { return false; }
    }

    private static void EmitTaskRefs(string? command, string? arguments, string? workingDir, string? clsid, List<Reference> refs)
    {
        if (!string.IsNullOrWhiteSpace(clsid))
        {
            refs.Add(new Reference { Kind = ReferenceKind.Clsid, Value = clsid!, SourceTag = "task:com-handler" });
        }
        if (!string.IsNullOrWhiteSpace(command))
        {
            refs.Add(new Reference { Kind = ReferenceKind.Command, Value = command!, SourceTag = "task:exec" });
            var img = command!.Trim();
            var expanded = ExpandEnv(img);
            var issues = ComputePathIssues(img, expanded, treatAsCommandHead: true);
            bool exists = FileExistsSafe(expanded);
            if (LooksLikePath(img))
            {
                refs.Add(new Reference { Kind = ReferenceKind.FilePath, Value = img, ExpandedValue = expanded, Exists = exists, Issues = issues, SourceTag = "task:exec" });
            }
            if (!string.IsNullOrWhiteSpace(arguments))
            {
                foreach (var tok in TokenizeArgs(arguments!))
                {
                    if (IsUrl(tok)) refs.Add(new Reference { Kind = ReferenceKind.Url, Value = tok, SourceTag = "task:args" });
                    else if (LooksLikePath(tok))
                    {
                        var exp = ExpandEnv(tok);
                        var iss = ComputePathIssues(tok, exp, treatAsCommandHead: false);
                        bool exi = FileExistsSafe(exp);
                        refs.Add(new Reference { Kind = ReferenceKind.FilePath, Value = tok, ExpandedValue = exp, Exists = exi, Issues = iss, SourceTag = "task:args" });
                    }
                }
            }
        }
    }

    private static int IndexOfCI(string hay, string needle, int startIndex = 0)
    {
        return hay.IndexOf(needle, startIndex, StringComparison.OrdinalIgnoreCase);
    }

    private static void TryExtractGpoScriptsIni(string path, List<Reference> refs)
    {
        try {
            var text = ReadTextForReferences(path, Settings.ReferenceExtractionMaxBytes);
            if (string.IsNullOrWhiteSpace(text)) return;
            // Very small INI parser: look for lines like nCmd=..., nParameters=...
            // See MS-GPSCR for scripts.ini/psscripts.ini layout.
            var lines = text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
            foreach (var line in lines)
            {
                var trimmed = line.Trim();
                if (trimmed.Length == 0 || trimmed.StartsWith(";")) continue;
                int eq = trimmed.IndexOf('='); if (eq <= 0) continue;
                var key = trimmed.Substring(0, eq).Trim();
                var val = trimmed.Substring(eq + 1).Trim();
                // Match keys like 0Cmd, 1Cmd, 0Parameters, etc.
                if (key.EndsWith("Cmd", StringComparison.OrdinalIgnoreCase))
                {
                    refs.Add(new Reference { Kind = ReferenceKind.Command, Value = val, SourceTag = "gpo:scripts.ini" });
                    if (LooksLikePath(val))
                    {
                        var exp = ExpandEnv(val);
                        var iss = ComputePathIssues(val, exp, treatAsCommandHead: true);
                        bool exi = FileExistsSafe(exp);
                        refs.Add(new Reference { Kind = ReferenceKind.FilePath, Value = val, ExpandedValue = exp, Exists = exi, Issues = iss, SourceTag = "gpo:scripts.ini" });
                    }
                }
                else if (key.EndsWith("Parameters", StringComparison.OrdinalIgnoreCase))
                {
                    foreach (var tok in TokenizeArgs(val))
                    {
                        if (IsUrl(tok)) refs.Add(new Reference { Kind = ReferenceKind.Url, Value = tok, SourceTag = "gpo:params" });
                        else if (LooksLikePath(tok))
                        {
                            var exp = ExpandEnv(tok);
                            var iss = ComputePathIssues(tok, exp, treatAsCommandHead: false);
                            bool exi = FileExistsSafe(exp);
                            refs.Add(new Reference { Kind = ReferenceKind.FilePath, Value = tok, ExpandedValue = exp, Exists = exi, Issues = iss, SourceTag = "gpo:params" });
                        }
                    }
                }
            }
        } catch { }
    }

    private static string ExpandEnv(string value)
    {
        var normalized = NormalizePathToken(value);
        try { return Environment.ExpandEnvironmentVariables(normalized); } catch { return normalized; }
    }

    private static string ReadTextForReferences(string path, int maxBytes)
    {
        int cap = maxBytes > 0 ? maxBytes : 512 * 1024;
        return ReadHeadText(path, cap);
    }

    private static bool LooksLikePath(string token)
    {
        if (string.IsNullOrWhiteSpace(token)) return false;
        var t = NormalizePathToken(token);
        if (t.StartsWith("\\\\")) return true; // UNC
        if (t.Length >= 2 && char.IsLetter(t[0]) && t[1] == ':') return true; // drive
        if (t.StartsWith("/") || t.StartsWith(".\\") || t.StartsWith("..\\") || t.StartsWith("./") || t.StartsWith("../")) return true;
        if (t.Contains('%')) return true; // env var present
        // Heuristic: has a directory separator and a dot extension
        int slash = t.IndexOfAny(new[] { '/', '\\' });
        int dot = t.LastIndexOf('.');
        return slash >= 0 && dot > slash && dot < t.Length - 1;
    }

    private static bool IsUrl(string token)
    {
        if (string.IsNullOrWhiteSpace(token)) return false;
        return token.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || token.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
    }

    private static ReferenceIssue ComputePathIssues(string raw, string expanded, bool treatAsCommandHead)
    {
        var issues = ReferenceIssue.None;
        var t = NormalizePathToken(raw);
        var expandedNormalized = NormalizePathToken(expanded);
        bool hasSpaces = t.Contains(' ');
        bool wasQuoted = IsQuotedToken(raw);
        if (treatAsCommandHead && hasSpaces && !wasQuoted) issues |= ReferenceIssue.UnquotedPathWithSpaces;
        if (t.StartsWith("\\\\")) issues |= ReferenceIssue.UncPath;
        if (System.IO.Path.IsPathRooted(t) && !t.StartsWith(".\\") && !t.StartsWith("..\\") && !t.StartsWith("./") && !t.StartsWith("../"))
            issues |= ReferenceIssue.AbsolutePath;
        if (t.StartsWith(".\\") || t.StartsWith("..\\") || t.StartsWith("./") || t.StartsWith("../")) issues |= ReferenceIssue.RelativePath;
        if (t.IndexOf('%') >= 0 && string.Equals(expandedNormalized, t, StringComparison.Ordinal)) issues |= ReferenceIssue.ContainsEnvVars;

        try {
            var dir = System.IO.Path.GetDirectoryName(expandedNormalized) ?? string.Empty;
            if (dir.Length > 0) {
                var dl = dir.ToLowerInvariant();
                if (dl.Contains("\\temp") || dl.Contains("/tmp") || dl.Contains("/var/tmp") || dl.Contains("/private/tmp")) issues |= ReferenceIssue.InsecureDirectory;
            }
        } catch { }
        return issues;
    }

    private static bool FileExistsSafe(string? p)
    {
        try
        {
            var normalized = NormalizePathToken(p);
            return !string.IsNullOrWhiteSpace(normalized) && File.Exists(normalized);
        }
        catch { return false; }
    }

    private static bool IsReferenceFriendlyTextExtension(string? extension)
    {
        var ext = (extension ?? string.Empty).Trim().TrimStart('.').ToLowerInvariant();
        return string.IsNullOrEmpty(ext) ||
               ext is "txt" or "text" or "log" or "cfg" or "conf" or "ini" or "inf" or
                   "md" or "markdown" or "csv" or "tsv" or "json" or "xml" or
                   "yml" or "yaml" or "toml";
    }

    private static string NormalizePathToken(string? value)
    {
        var trimmed = (value ?? string.Empty).Trim();
        if (trimmed.Length >= 2 &&
            ((trimmed[0] == '"' && trimmed[trimmed.Length - 1] == '"') ||
             (trimmed[0] == '\'' && trimmed[trimmed.Length - 1] == '\'')))
        {
            trimmed = trimmed.Substring(1, trimmed.Length - 2).Trim();
        }

        return trimmed;
    }

    private static bool IsQuotedToken(string? value)
    {
        var trimmed = (value ?? string.Empty).Trim();
        return trimmed.Length >= 2 &&
               ((trimmed[0] == '"' && trimmed[trimmed.Length - 1] == '"') ||
                (trimmed[0] == '\'' && trimmed[trimmed.Length - 1] == '\''));
    }

    private static IEnumerable<string> TokenizeArgs(string args)
    {
        if (string.IsNullOrWhiteSpace(args)) yield break;
        int i = 0; int n = args.Length;
        while (i < n)
        {
            while (i < n && char.IsWhiteSpace(args[i])) i++;
            if (i >= n) break;
            char quote = '\0';
            if (args[i] == '"' || args[i] == '\'') { quote = args[i]; i++; }
            int start = i;
            while (i < n)
            {
                char c = args[i];
                if (quote != '\0') { if (c == quote) { break; } }
                else if (char.IsWhiteSpace(c)) break;
                i++;
            }
            int end = i;
            string tok = args.Substring(start, Math.Max(0, end - start));
            if (quote != '\0' && i < n && args[i] == quote) i++;
            if (!string.IsNullOrWhiteSpace(tok)) yield return tok;
            while (i < n && char.IsWhiteSpace(args[i])) i++;
        }
    }
}
