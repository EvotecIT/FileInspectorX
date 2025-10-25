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

            // Task Scheduler Task XML
            // Try for .xml; when ambiguous, a quick shape check happens inside
            if (ext == "xml" || string.IsNullOrEmpty(ext))
            {
                if (LooksLikeTaskXml(path) || true)
                    TryExtractTaskSchedulerXml(path, list);
            }

            // GPO scripts INI (scripts.ini, psscripts.ini)
            if (ext == "ini" || string.Equals(System.IO.Path.GetFileName(path), "scripts.ini", StringComparison.OrdinalIgnoreCase) || string.Equals(System.IO.Path.GetFileName(path), "psscripts.ini", StringComparison.OrdinalIgnoreCase))
            {
                TryExtractGpoScriptsIni(path, list);
            }

            // GPO Scripts.xml (PowerShell or Generic)
            if (ext == "xml" || string.IsNullOrEmpty(ext))
            {
                TryExtractGpoScriptsXml(path, list);
            }

            // HTML: extract external links and network paths from common tags/attributes
            if (ext == "html" || ext == "htm")
            {
                TryExtractHtmlReferences(path, list);
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

    private static void TryExtractHtmlReferences(string path, List<Reference> refs)
    {
        try {
            var text = File.ReadAllText(path);
            if (string.IsNullOrWhiteSpace(text)) return;
            int cap = Math.Min(text.Length, 512 * 1024);
            var head = text.AsSpan(0, cap);

            int cdnCount = 0;
            var hostCounts = new Dictionary<string,int>(StringComparer.OrdinalIgnoreCase);
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
                int up = IndexOfTokenCI(head, "url(", pos); if (up < 0) break; int start = up + 4; int end = head.Slice(start).IndexOf(')'); if (end < 0) break; end += start; var raw = head.Slice(start, Math.Max(0, end - start)).ToString().Trim('"', '\'', ' ', '\t'); pos = end + 1;
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

    private static void TryExtractInternetShortcut(string path, List<Reference> refs)
    {
        try
        {
            var lines = File.ReadAllLines(path);
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
            var text = File.ReadAllText(path);
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
                var text = File.ReadAllText(path);
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
            var text = File.ReadAllText(path);
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
        try { return Environment.ExpandEnvironmentVariables(value); } catch { return value; }
    }

    private static bool LooksLikePath(string token)
    {
        if (string.IsNullOrWhiteSpace(token)) return false;
        var t = token.Trim();
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
        var t = raw.Trim();
        bool hasSpaces = t.Contains(' ');
        bool isQuoted = t.Length >= 2 && ((t[0] == '"' && t[t.Length - 1] == '"') || (t[0] == '\'' && t[t.Length - 1] == '\''));
        if (treatAsCommandHead && hasSpaces && !isQuoted) issues |= ReferenceIssue.UnquotedPathWithSpaces;
        if (t.StartsWith("\\\\")) issues |= ReferenceIssue.UncPath;
        if (t.Length >= 2 && char.IsLetter(t[0]) && t[1] == ':') issues |= ReferenceIssue.AbsolutePath;
        if (t.StartsWith(".\\") || t.StartsWith("..\\") || t.StartsWith("./") || t.StartsWith("../")) issues |= ReferenceIssue.RelativePath;
        if (t.IndexOf('%') >= 0 && string.Equals(expanded, raw, StringComparison.Ordinal)) issues |= ReferenceIssue.ContainsEnvVars;

        try {
            var dir = System.IO.Path.GetDirectoryName(expanded) ?? string.Empty;
            if (dir.Length > 0) {
                var dl = dir.ToLowerInvariant();
                if (dl.Contains("\\temp") || dl.Contains("/tmp") || dl.Contains("/var/tmp") || dl.Contains("/private/tmp")) issues |= ReferenceIssue.InsecureDirectory;
            }
        } catch { }
        return issues;
    }

    private static bool FileExistsSafe(string? p)
    {
        try { return !string.IsNullOrWhiteSpace(p) && File.Exists(p); } catch { return false; }
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
