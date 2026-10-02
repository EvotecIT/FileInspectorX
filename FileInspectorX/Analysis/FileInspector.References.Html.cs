using System.Xml;

namespace FileInspectorX;

public static partial class FileInspector
{
    private static void TryExtractHtmlReferences(InspectionInput input, List<Reference> refs)
    {
        var path = input.Name;
        try {
            var text = ReadTextForReferences(input, OperationSettings.ReferenceExtractionMaxBytes);
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
                        if (OperationSettings.CheckNetworkPathsInReferences)
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
                    bool? exists = null; if (OperationSettings.CheckNetworkPathsInReferences) { try { exists = Directory.Exists(GetUncShareRoot(raw)); } catch { exists = null; } }
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

}
