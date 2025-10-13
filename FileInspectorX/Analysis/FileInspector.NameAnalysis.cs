namespace FileInspectorX;

/// <summary>
/// Filename/path heuristics to flag suspicious traits (double extension, BiDi override, mismatch, etc.).
/// </summary>
public static partial class FileInspector
{
    private static NameIssues AnalyzeName(string path, ContentTypeDetectionResult? det)
    {
        var issues = NameIssues.None;
        try {
            var name = System.IO.Path.GetFileName(path);
            if (string.IsNullOrEmpty(name)) return issues;

            // Leading dot hidden
            if (name.Length > 1 && name[0] == '.' && name != "." && name != "..") issues |= NameIssues.LeadingDotHidden;

            // Suspicious whitespace
            if (char.IsWhiteSpace(name[0]) || char.IsWhiteSpace(name[name.Length - 1]) || name.Contains("  ")) issues |= NameIssues.SuspiciousWhitespace;

            // BiDi override/control characters (RLO/LRO/PDF etc.)
            foreach (var ch in name)
            {
                if (ch == '\u202A' || ch == '\u202B' || ch == '\u202D' || ch == '\u202E' || ch == '\u202C') { issues |= NameIssues.BiDiOverride; break; }
            }

            // Extension mismatch and double-extension
            var dot1 = name.LastIndexOf('.');
            if (dot1 > 0 && dot1 < name.Length - 1)
            {
                var ext = name.Substring(dot1 + 1).ToLowerInvariant();
                var baseNoExt = name.Substring(0, dot1);
                var dot0 = baseNoExt.LastIndexOf('.');
                if (dot0 > 0)
                {
                    // Two dots present => double extension
                    issues |= NameIssues.DoubleExtension;
                }
                if (det != null && !string.IsNullOrEmpty(det.Extension) && !ext.Equals(det.Extension, System.StringComparison.OrdinalIgnoreCase))
                {
                    issues |= NameIssues.ExtensionMismatch;
                }
            }
        } catch { }
        return issues;
    }
}
