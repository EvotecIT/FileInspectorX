using System.Collections.Generic;

namespace FileInspectorX;

public static partial class FileInspector
{
    /// <summary>
    /// Compares a declared extension with a detected content type and exposes strong alternatives/danger flags.
    /// </summary>
    public static DeclaredTypeComparison CompareDeclaredDetailed(
        string? declaredExtension,
        ContentTypeDetectionResult? detected,
        ISet<string>? dangerousExtensions = null)
    {
        var decl = NormalizeExtension(declaredExtension);
        var detExt = NormalizeExtension(detected?.Extension);
        var detGuess = NormalizeExtension(detected?.GuessedExtension);

        var cmp = new DeclaredTypeComparison
        {
            DeclaredExtension = decl,
            DetectedExtension = detExt ?? detGuess,
            DetectedGuessedExtension = detGuess,
            DetectedMimeType = detected?.MimeType,
            DetectedConfidence = detected?.Confidence,
            DetectedReason = detected?.Reason
        };

        var baseCmp = CompareDeclared(declaredExtension, detected);
        cmp.Mismatch = baseCmp.Mismatch;
        cmp.Reason = baseCmp.Reason ?? string.Empty;

        if (detected == null || string.IsNullOrEmpty(decl))
            return cmp;

        var strong = GetStrongAlternatives(detected, detExt);
        if (strong.Count > 0)
        {
            cmp.StrongAlternatives = strong;
            foreach (var alt in strong)
            {
                var ext = NormalizeExtension(alt.Extension);
                if (string.IsNullOrEmpty(ext)) continue;
                if (string.Equals(ext, decl, StringComparison.OrdinalIgnoreCase))
                {
                    cmp.DeclaredMatchesAlternative = true;
                    break;
                }
            }
        }

        bool IsDangerous(string? ext)
        {
            if (string.IsNullOrWhiteSpace(ext)) return false;
            return dangerousExtensions != null
                ? dangerousExtensions.Contains(ext!)
                : DangerousExtensions.IsDangerous(ext);
        }

        var dangerousAlt = GetStrongDangerousAlternativeExts(strong, IsDangerous);
        if (dangerousAlt.Count > 0)
            cmp.StrongDangerousAlternativeExtensions = dangerousAlt;

        cmp.IsDeclaredDangerous = !string.IsNullOrEmpty(decl) && IsDangerous(decl);
        bool detectedDanger = detected.IsDangerous ||
                              (!string.IsNullOrEmpty(detExt) && IsDangerous(detExt));
        if (dangerousAlt.Count > 0) detectedDanger = true;
        cmp.IsDetectedDangerous = detectedDanger;

        if (cmp.Mismatch && cmp.DeclaredMatchesAlternative)
        {
            cmp.Mismatch = false;
            cmp.Reason = AppendReason(cmp.Reason, "alt-match:declared");
        }

        if (!cmp.Mismatch && !cmp.IsDeclaredDangerous && IsPlainTextFamily(decl) && dangerousAlt.Count > 0)
        {
            cmp.Mismatch = true;
            cmp.Reason = AppendReason(cmp.Reason, "declared-bypass:strong-dangerous-alt");
        }

        if (dangerousAlt.Count > 0)
            cmp.Reason = AppendReason(cmp.Reason, $"alt-danger:{string.Join(",", dangerousAlt)}");

        return cmp;
    }

    private static List<ContentTypeDetectionCandidate> GetStrongAlternatives(
        ContentTypeDetectionResult detected,
        string? primaryExt)
    {
        var list = new List<ContentTypeDetectionCandidate>();
        var candidates = detected.Candidates ?? detected.Alternatives;
        if (candidates == null || candidates.Count == 0) return list;
        foreach (var candidate in candidates)
        {
            if (!IsStrongCandidate(candidate)) continue;
            var ext = NormalizeExtension(candidate.Extension);
            if (!string.IsNullOrEmpty(primaryExt) &&
                !string.IsNullOrEmpty(ext) &&
                string.Equals(ext, primaryExt, StringComparison.OrdinalIgnoreCase))
                continue;
            list.Add(candidate);
        }
        return list;
    }

    private static List<string> GetStrongDangerousAlternativeExts(
        IReadOnlyList<ContentTypeDetectionCandidate> candidates,
        Func<string?, bool> isDangerous)
    {
        var list = new List<string>();
        if (candidates == null || candidates.Count == 0) return list;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var candidate in candidates)
        {
            var ext = NormalizeExtension(candidate.Extension);
            if (ext == null || ext.Length == 0) continue;
            if (!isDangerous(ext)) continue;
            if (seen.Add(ext)) list.Add(ext);
            if (list.Count >= 3) break;
        }
        return list;
    }

    private static bool IsStrongCandidate(ContentTypeDetectionCandidate candidate)
    {
        if (candidate.Score >= Settings.DetectionStrongCandidateScoreThreshold) return true;
        if (!string.IsNullOrEmpty(candidate.Confidence) &&
            candidate.Confidence.Equals("High", StringComparison.OrdinalIgnoreCase))
            return true;
        return false;
    }

    private static bool IsPlainTextFamily(string? ext)
    {
        switch ((ext ?? string.Empty).ToLowerInvariant())
        {
            case "txt":
            case "text":
            case "log":
            case "cfg":
            case "conf":
            case "ini":
            case "md":
            case "markdown":
            case "properties":
            case "prop":
            case "csv":
            case "tsv":
                return true;
            default:
                return false;
        }
    }

}
