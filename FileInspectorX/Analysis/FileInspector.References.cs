using System.Xml;

namespace FileInspectorX;

/// <summary>
/// Extracts generic references (paths, URLs, commands, env vars, CLSIDs) from common config formats.
/// </summary>
public static partial class FileInspector
{
    private static IReadOnlyList<Reference>? BuildReferences(InspectionInput input, ContentTypeDetectionResult? det)
    {
        var path = input.Name;
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
                                      (IsScriptLikeExtension(detectedExt) || detectedExt == "css");
            bool isXmlLike = ext == "xml" || string.IsNullOrEmpty(ext) || detectedXmlLike;
            bool isHtmlLike = ext is "html" or "htm" || detectedHtmlLike;
            bool isScriptLike = IsScriptLikeExtension(ext) || ext == "css"
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
                TryExtractTaskSchedulerXml(input, list);
            }

            // GPO scripts INI (scripts.ini, psscripts.ini)
            if (ext == "ini" || string.Equals(System.IO.Path.GetFileName(path), "scripts.ini", StringComparison.OrdinalIgnoreCase) || string.Equals(System.IO.Path.GetFileName(path), "psscripts.ini", StringComparison.OrdinalIgnoreCase))
            {
                TryExtractGpoScriptsIni(input, list);
            }

            // GPO Scripts.xml (PowerShell or Generic)
            if (isXmlLike)
            {
                TryExtractGpoScriptsXml(input, list);
            }

            // HTML: extract external links and network paths from common tags/attributes
            if (isHtmlLike)
            {
                TryExtractHtmlReferences(input, list);
            }
            // Scripts: extract URLs and UNC shares from common script types (PowerShell, batch, shell, JS)
            if (isScriptLike)
            {
                TryExtractScriptReferences(input, list, string.IsNullOrWhiteSpace(scriptSourceTag) ? "script" : scriptSourceTag);
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
                TryExtractGenericTextReferences(input, list, genericTextSourceTag);
            }

            // Windows Internet Shortcut (.url)
            if (ext == "url")
            {
                TryExtractInternetShortcut(input, list);
            }

            // Windows Shell Link (.lnk) — best-effort target extraction
            if (ext == "lnk")
            {
                TryExtractWindowsLnk(input, list);
            }

            // Generic: if detection is plain text and starts with a command-ish shebang, we skip here; richer parsers can be added later
        } catch { }

        return list.Count > 0 ? list : null;
    }

    private static void TryExtractGenericTextReferences(InspectionInput input, List<Reference> refs, string sourceTag)
    {
        var path = input.Name;
        try
        {
            string text = ReadTextForReferences(input, OperationSettings.ReferenceExtractionMaxBytes);
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

    private static void TryExtractScriptReferences(InspectionInput input, List<Reference> refs, string ext)
    {
        var path = input.Name;
        try
        {
            string text = ReadTextForReferences(input, OperationSettings.ReferenceExtractionMaxBytes);
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
            var scriptCommentMap = BuildScriptCommentMap(text);
            int di = 0;
            while (di < text.Length)
            {
                int at = text.IndexOf("data:", di, StringComparison.OrdinalIgnoreCase); if (at < 0) break;
                if (scriptCommentMap[at] || !LooksLikeScriptDataUriStart(text, at))
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
                if (index == 0) return true;

                char prev = script[index - 1];
                return prev == '"' || prev == '\'' || prev == '`';
            }

            static bool[] BuildScriptCommentMap(string script)
            {
                var comments = new bool[script.Length];
                bool inLineComment = false, inBlockComment = false;
                bool inSingle = false, inDouble = false, inTemplate = false;
                for (int index = 0; index < script.Length; index++)
                {
                    char current = script[index];
                    char next = index + 1 < script.Length ? script[index + 1] : '\0';
                    if (inLineComment)
                    {
                        comments[index] = true;
                        if (current is '\r' or '\n') inLineComment = false;
                        continue;
                    }
                    if (inBlockComment)
                    {
                        comments[index] = true;
                        if (current == '*' && next == '/')
                        {
                            comments[index + 1] = true;
                            inBlockComment = false;
                            index++;
                        }
                        continue;
                    }
                    if (inSingle)
                    {
                        if (current == '\\' && index + 1 < script.Length) { index++; continue; }
                        if (current == '\'') inSingle = false;
                        continue;
                    }
                    if (inDouble)
                    {
                        if (current == '\\' && index + 1 < script.Length) { index++; continue; }
                        if (current == '"') inDouble = false;
                        continue;
                    }
                    if (inTemplate)
                    {
                        if (current == '\\' && index + 1 < script.Length) { index++; continue; }
                        if (current == '`') inTemplate = false;
                        continue;
                    }
                    if (current == '/' && next == '/')
                    {
                        comments[index] = comments[index + 1] = true;
                        inLineComment = true;
                        index++;
                    }
                    else if (current == '/' && next == '*')
                    {
                        comments[index] = comments[index + 1] = true;
                        inBlockComment = true;
                        index++;
                    }
                    else if (current == '\'') inSingle = true;
                    else if (current == '"') inDouble = true;
                    else if (current == '`') inTemplate = true;
                }
                return comments;
            }

        }
        catch { }
    }

    private static void TryExtractInternetShortcut(InspectionInput input, List<Reference> refs)
    {
        var path = input.Name;
        try
        {
            var text = ReadTextForReferences(input, OperationSettings.ReferenceExtractionMaxBytes);
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

    private static void TryExtractWindowsLnk(InspectionInput input, List<Reference> refs)
    {
        var path = input.Name;
        try
        {
            using var fs = input.OpenRead();
            var hdr = new byte[Math.Min(4096, fs.Length)];
            int n = ReadAvailable(fs, hdr, 0, hdr.Length);
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
                bool? exi = FileExistsSafe(exp);
                refs.Add(new Reference { Kind = ReferenceKind.FilePath, Value = best!, ExpandedValue = exp, Exists = exi, Issues = issues, SourceTag = "lnk:target" });
            }
        } catch { }
    }

    private static string ExpandEnv(string value)
    {
        var normalized = NormalizePathToken(value);
        try { return Environment.ExpandEnvironmentVariables(normalized); } catch { return normalized; }
    }

    private static string ReadTextForReferences(InspectionInput input, int maxBytes)
    {
        var path = input.Name;
        int cap = maxBytes > 0 ? maxBytes : 512 * 1024;
        return ReadHeadText(input, cap);
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
        bool windowsDriveRooted = t.Length >= 3 && char.IsLetter(t[0]) && t[1] == ':' &&
                                  (t[2] == '\\' || t[2] == '/');
        if ((System.IO.Path.IsPathRooted(t) || windowsDriveRooted) &&
            !t.StartsWith(".\\") && !t.StartsWith("..\\") && !t.StartsWith("./") && !t.StartsWith("../"))
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

    private static bool? FileExistsSafe(string? p)
    {
        if (!OperationSettings.ReferencePathExistenceChecksEnabled) return null;
        try
        {
            var normalized = NormalizePathToken(p);
            if (string.IsNullOrWhiteSpace(normalized)) return null;
            if (normalized.StartsWith("\\\\", StringComparison.Ordinal)) return null;
#if NET8_0_OR_GREATER || NET472
            if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
            {
                var root = Path.GetPathRoot(normalized);
                if (!string.IsNullOrWhiteSpace(root))
                {
                    var drive = new DriveInfo(root);
                    if (drive.DriveType == DriveType.Network) return null;
                }
            }
#endif
            return File.Exists(normalized);
        }
        catch { return null; }
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
