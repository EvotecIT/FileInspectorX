namespace FileInspectorX;

internal static partial class Signatures
{
    static ContentTypeDetectionResult AttachAlternatives(ContentTypeDetectionResult det, ReadOnlySpan<byte> head, string headStr, string headLower, string decl)
    {
        if (!det.Score.HasValue) det.Score = ScoreFromConfidence(det.Confidence);
        if (!IsAltEligibleExtension(det.Extension))
        {
            det.IsDangerous = DangerousExtensions.IsDangerous(det.Extension);
            return det;
        }

        if (Settings.DetectionMaxAlternatives <= 0 &&
            Settings.DetectionPrimaryScoreMargin <= 0 &&
            Settings.DetectionDeclaredTieBreakerMargin <= 0 &&
            !Settings.DetectionLogCandidates)
        {
            det.IsDangerous = DangerousExtensions.IsDangerous(det.Extension);
            return det;
        }

        var all = CollectCandidates(head, headStr, headLower, decl);
        if (all.Count == 0) return det;
        det.Candidates = all;

        var primaryExt = det.Extension ?? string.Empty;
        ContentTypeDetectionCandidate? primary = null;
        if (!string.IsNullOrWhiteSpace(primaryExt))
        {
            foreach (var c in all)
            {
                if (string.Equals(c.Extension, primaryExt, StringComparison.OrdinalIgnoreCase))
                {
                    primary = c;
                    break;
                }
            }
        }
        ContentTypeDetectionCandidate? declaredCandidate = null;
        if (!string.IsNullOrWhiteSpace(decl))
        {
            foreach (var c in all)
            {
                if (string.Equals(c.Extension, decl, StringComparison.OrdinalIgnoreCase))
                {
                    declaredCandidate = c;
                    break;
                }
            }
        }
        ContentTypeDetectionCandidate? best = null;
        foreach (var c in all)
        {
            if (best == null || c.Score > best.Score) best = c;
        }
        if (primary != null)
        {
            det.Score = primary.Score;
            det.IsDangerous = primary.IsDangerous;
            bool allowUpgrade = det.Reason == null ||
                                (!det.Reason.Contains("malformed", StringComparison.OrdinalIgnoreCase) &&
                                 !det.Reason.Contains("validation-error", StringComparison.OrdinalIgnoreCase));
            if (allowUpgrade && ConfidenceRank(primary.Confidence) > ConfidenceRank(det.Confidence))
                det.Confidence = primary.Confidence;
        }
        else
        {
            det.IsDangerous = DangerousExtensions.IsDangerous(det.Extension);
        }

        int scoreMargin = Math.Max(0, Settings.DetectionPrimaryScoreMargin);
        int tieMargin = Math.Max(0, Settings.DetectionDeclaredTieBreakerMargin);
        bool allowReplace = det.Reason == null ||
                            (!det.Reason.Contains("malformed", StringComparison.OrdinalIgnoreCase) &&
                             !det.Reason.Contains("validation-error", StringComparison.OrdinalIgnoreCase));
        bool replaced = false;
        if (allowReplace && primary != null && best != null &&
            !string.Equals(best.Extension, primaryExt, StringComparison.OrdinalIgnoreCase) &&
            best.Score >= primary.Score + scoreMargin)
        {
            ApplyPrimaryCandidate(best, "primary:score");
            primaryExt = best.Extension;
            primary = best;
            replaced = true;
        }
        if (!replaced && declaredCandidate != null &&
            !string.Equals(declaredCandidate.Extension, primaryExt, StringComparison.OrdinalIgnoreCase))
        {
            int topScore = best?.Score ?? primary?.Score ?? det.Score ?? 0;
            if (topScore - declaredCandidate.Score <= tieMargin)
            {
                ApplyPrimaryCandidate(declaredCandidate, "primary:declared");
                primaryExt = declaredCandidate.Extension;
                primary = declaredCandidate;
            }
        }

        var alternatives = new List<ContentTypeDetectionCandidate>();
        foreach (var c in all)
        {
            if (!string.Equals(c.Extension, primaryExt, StringComparison.OrdinalIgnoreCase))
                alternatives.Add(c);
        }
        if (alternatives.Count > 0)
        {
            alternatives.Sort((a, b) => b.Score.CompareTo(a.Score));
            int maxAlt = Math.Max(0, Settings.DetectionMaxAlternatives);
            if (maxAlt == 0) alternatives.Clear();
            else if (alternatives.Count > maxAlt) alternatives.RemoveRange(maxAlt, alternatives.Count - maxAlt);
            if (alternatives.Count > 0) det.Alternatives = alternatives;
        }
        if (Settings.DetectionLogCandidates)
        {
            var sb = new System.Text.StringBuilder();
            sb.Append("detect:text primary=").Append(det.Extension)
              .Append(" score=").Append(det.Score ?? 0)
              .Append(" conf=").Append(det.Confidence ?? string.Empty);
            if (det.Alternatives != null && det.Alternatives.Count > 0)
            {
                sb.Append(" alts=[");
                for (int i = 0; i < det.Alternatives.Count; i++)
                {
                    var a = det.Alternatives[i];
                    if (i > 0) sb.Append(", ");
                    sb.Append(a.Extension).Append(":").Append(a.Score);
                }
                sb.Append(']');
            }
            Settings.Logger.WriteDebug(sb.ToString());
        }
        return det;

        void ApplyPrimaryCandidate(ContentTypeDetectionCandidate candidate, string tag)
        {
            det.Extension = candidate.Extension;
            det.MimeType = candidate.MimeType;
            det.Confidence = candidate.Confidence;
            det.Reason = AppendReason(candidate.Reason, tag);
            det.ReasonDetails = candidate.ReasonDetails;
            det.Score = candidate.Score;
            det.IsDangerous = candidate.IsDangerous;
        }

        static string AppendReason(string? reason, string tag)
            => string.IsNullOrEmpty(reason) ? tag : (reason + ";" + tag);
    }

    static int ConfidenceRank(string? confidence)
    {
        if (string.Equals(confidence, "High", StringComparison.OrdinalIgnoreCase)) return 3;
        if (string.Equals(confidence, "Medium", StringComparison.OrdinalIgnoreCase)) return 2;
        if (string.Equals(confidence, "Low", StringComparison.OrdinalIgnoreCase)) return 1;
        return 0;
    }

    static int ScoreFromConfidence(string? confidence)
    {
        if (string.Equals(confidence, "High", StringComparison.OrdinalIgnoreCase)) return 90;
        if (string.Equals(confidence, "Medium", StringComparison.OrdinalIgnoreCase)) return 70;
        if (string.Equals(confidence, "Low", StringComparison.OrdinalIgnoreCase)) return 50;
        return 40;
    }

    static int ClampScore(int score, string? confidence)
    {
        int min = 40; int max = 100;
        if (string.Equals(confidence, "High", StringComparison.OrdinalIgnoreCase)) { min = 80; max = 100; }
        else if (string.Equals(confidence, "Medium", StringComparison.OrdinalIgnoreCase)) { min = 60; max = 79; }
        else if (string.Equals(confidence, "Low", StringComparison.OrdinalIgnoreCase)) { min = 40; max = 59; }
        if (score < min) return min;
        if (score > max) return max;
        return score;
    }

    static int GetScoreAdjustment(string ext, string reason, string? details)
    {
        var map = Settings.DetectionScoreAdjustments;
        if (map == null || map.Count == 0) return 0;
        int adjust = 0;
        if (!string.IsNullOrEmpty(ext))
        {
            if (map.TryGetValue(ext, out var vExtPlain)) adjust += vExtPlain;
            if (map.TryGetValue("ext:" + ext, out var vExt)) adjust += vExt;
        }
        if (!string.IsNullOrEmpty(reason))
        {
            if (map.TryGetValue(reason, out var vReasonPlain)) adjust += vReasonPlain;
            if (map.TryGetValue("reason:" + reason, out var vReason)) adjust += vReason;
        }
        if (!string.IsNullOrEmpty(details))
        {
            var detailKey = details!;
            if (map.TryGetValue(detailKey, out var vDetailPlain)) adjust += vDetailPlain;
            if (map.TryGetValue("detail:" + detailKey, out var vDetail)) adjust += vDetail;
        }
        return adjust;
    }

    static bool IsAltEligibleExtension(string? ext)
    {
        var normalized = (ext ?? string.Empty).Trim().TrimStart('.').ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(normalized)) return false;
        switch (normalized)
        {
            case "txt":
            case "text":
            case "log":
            case "md":
            case "markdown":
            case "ps1":
            case "psm1":
            case "psd1":
            case "vbs":
            case "js":
            case "sh":
            case "bat":
            case "cmd":
            case "py":
            case "rb":
            case "lua":
            case "xml":
            case "admx":
            case "adml":
            case "html":
            case "json":
            case "ndjson":
            case "csv":
            case "tsv":
            case "ini":
            case "inf":
            case "toml":
            case "yml":
            case "yaml":
                return true;
            default:
                return false;
        }
    }

}
