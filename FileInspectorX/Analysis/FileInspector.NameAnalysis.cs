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
                    // Only flag multiple dots when the extra segment looks like an embedded extension,
                    // not a benign dotted product/version name such as Foo.Bar_1.2.3_x64.msi.
                    if (!LooksLikeBenignVersionedName(baseNoExt) &&
                        !LooksLikeCrashDumpArtifactName(baseNoExt, ext))
                        issues |= NameIssues.DoubleExtension;
                }
                if (det != null && !string.IsNullOrEmpty(det.Extension))
                {
                    var cmp = CompareDeclared(ext, det);
                    if (cmp.Mismatch) issues |= NameIssues.ExtensionMismatch;
                }
            }
        } catch { }
        return issues;
    }

    private static bool LooksLikeBenignVersionedName(string baseNoExt)
    {
        if (string.IsNullOrWhiteSpace(baseNoExt)) return false;
        var parts = baseNoExt.Split(new[] { '.' }, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2) return false;

        bool sawVersionLike = false;
        for (int i = 1; i < parts.Length; i++)
        {
            var part = parts[i].Trim();
            if (string.IsNullOrEmpty(part)) return false;
            if (LooksLikeEmbeddedExtensionToken(part)) return false;
            if (!IsVersionLikeNameToken(part)) return false;
            sawVersionLike = true;
        }

        return sawVersionLike;
    }

    private static bool LooksLikeEmbeddedExtensionToken(string segment)
    {
        var normalized = NormalizeExtension(segment);
        if (string.IsNullOrEmpty(normalized)) return false;
        var key = normalized!;
        if (DangerousExtensions.IsDangerous(key)) return true;
        if (MimeMaps.Default.ContainsKey(key)) return true;
        return ExtraMime.Crypto.ContainsKey(key);
    }

    private static bool IsVersionLikeNameToken(string segment)
    {
        bool hasDigit = false;
        for (int i = 0; i < segment.Length; i++)
        {
            char c = segment[i];
            if (char.IsDigit(c)) hasDigit = true;
            if (!(char.IsLetterOrDigit(c) || c == '_' || c == '-')) return false;
        }
        return hasDigit;
    }

    private static bool LooksLikeCrashDumpArtifactName(string baseNoExt, string ext)
    {
        if (string.IsNullOrWhiteSpace(baseNoExt) || string.IsNullOrWhiteSpace(ext))
            return false;

        if (!ext.Equals("dmp", StringComparison.OrdinalIgnoreCase) &&
            !ext.Equals("mdmp", StringComparison.OrdinalIgnoreCase) &&
            !ext.Equals("hdmp", StringComparison.OrdinalIgnoreCase))
            return false;

        var normalized = baseNoExt.Trim();
        bool protectedSuffix = normalized.EndsWith(".protected", StringComparison.OrdinalIgnoreCase);
        if (protectedSuffix)
            normalized = normalized.Substring(0, normalized.Length - ".protected".Length);

        var parts = normalized.Split(new[] { '.' }, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 3)
            return false;

        var pidPart = parts[parts.Length - 1];
        if (!pidPart.All(char.IsDigit))
            return false;

        var embeddedExt = NormalizeExtension(parts[parts.Length - 2]);
        if (string.IsNullOrWhiteSpace(embeddedExt))
            return false;

        return string.Equals(embeddedExt, "exe", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(embeddedExt, "dll", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(embeddedExt, "sys", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(embeddedExt, "com", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(embeddedExt, "scr", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(embeddedExt, "cpl", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(embeddedExt, "drv", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(embeddedExt, "ocx", StringComparison.OrdinalIgnoreCase);
    }
}
