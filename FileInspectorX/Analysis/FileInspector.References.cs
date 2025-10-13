using System.Xml;

namespace FileInspectorX;

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

            // Generic: if detection is plain text and starts with a command-ish shebang, we skip here; richer parsers can be added later
        } catch { }

        return list.Count > 0 ? list : null;
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
