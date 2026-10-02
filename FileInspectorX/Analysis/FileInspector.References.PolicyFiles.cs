using System.Xml;

namespace FileInspectorX;

public static partial class FileInspector
{
    private static bool LooksLikeTaskXml(InspectionInput input)
    {
        var path = input.Name;
        try {
            using var fs = input.OpenRead();
            var head = new byte[Math.Min(8192, (int)Math.Min(fs.Length, 8192))];
            int n = ReadAvailable(fs, head, 0, head.Length);
            var s = System.Text.Encoding.UTF8.GetString(head, 0, n);
            return s.IndexOf("<Task", StringComparison.OrdinalIgnoreCase) >= 0 && (s.IndexOf("<Exec", StringComparison.OrdinalIgnoreCase) >= 0 || s.IndexOf("<Actions", StringComparison.OrdinalIgnoreCase) >= 0);
        } catch { return false; }
    }

    private static void TryExtractGpoScriptsXml(InspectionInput input, List<Reference> refs)
    {
        var path = input.Name;
        try {
            var text = ReadTextForReferences(input, OperationSettings.ReferenceExtractionMaxBytes);
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
                    bool? exi = FileExistsSafe(exp);
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
                        bool? exi = FileExistsSafe(exp);
                        refs.Add(new Reference { Kind = ReferenceKind.FilePath, Value = tok, ExpandedValue = exp, Exists = exi, Issues = iss, SourceTag = "gpo:scripts.xml" });
                    }
                }
            }
        } catch { }
    }

    private static void TryExtractTaskSchedulerXml(InspectionInput input, List<Reference> refs)
    {
        var path = input.Name;
        // Parse every XML candidate with the secure reader. This handles BOM/encoding
        // declarations and late Actions nodes without a lossy UTF-8 prefix precheck.
        TryExtractTaskSchedulerXmlDoc(input, refs);
    }

    private static bool TryExtractTaskSchedulerXmlDoc(InspectionInput input, List<Reference> refs)
    {
        var path = input.Name;
        try {
            var maxBytes = OperationSettings.ReferenceExtractionMaxBytes > 0
                ? OperationSettings.ReferenceExtractionMaxBytes
                : 512 * 1024;
            using var fs = input.OpenRead();
            if (!BoundedXmlDocument.TryLoad(fs, maxBytes, out var doc)) return false;

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
            bool? exists = FileExistsSafe(expanded);
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
                        bool? exi = FileExistsSafe(exp);
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

    private static void TryExtractGpoScriptsIni(InspectionInput input, List<Reference> refs)
    {
        var path = input.Name;
        try {
            var text = ReadTextForReferences(input, OperationSettings.ReferenceExtractionMaxBytes);
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
                        bool? exi = FileExistsSafe(exp);
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
                            bool? exi = FileExistsSafe(exp);
                            refs.Add(new Reference { Kind = ReferenceKind.FilePath, Value = tok, ExpandedValue = exp, Exists = exi, Issues = iss, SourceTag = "gpo:params" });
                        }
                    }
                }
            }
        } catch { }
    }

}
