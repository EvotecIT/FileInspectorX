namespace FileInspectorX;

/// <summary>
/// Flattened projection of a heuristic or nested finding for display and host integration.
/// </summary>
public sealed class FindingView
{
    /// <summary>Stable finding code emitted by FileInspectorX.</summary>
    public string Code { get; set; } = string.Empty;
    /// <summary>Short human-friendly label for compact displays.</summary>
    public string? SummaryShort { get; set; }
    /// <summary>Long human-friendly description for detailed displays.</summary>
    public string? SummaryLong { get; set; }
    /// <summary>Category grouping when the legend provides one.</summary>
    public string? Category { get; set; }
    /// <summary>Rough severity score when the legend provides one.</summary>
    public int? Severity { get; set; }

    /// <summary>One-based source line number when evidence is available.</summary>
    public int? Line { get; set; }

    /// <summary>Short, redacted source snippet when evidence is available.</summary>
    public string? Snippet { get; set; }

    /// <summary>Optional source tag describing where the evidence was observed.</summary>
    public string? SourceTag { get; set; }

    /// <summary>Number of matched source occurrences observed within the bounded scan window.</summary>
    public int? HitCount { get; set; }

    /// <summary>Up to a few one-based source lines for repeated behavior.</summary>
    public IReadOnlyList<int>? Lines { get; set; }

    /// <summary>Up to a few redacted source snippets for repeated behavior.</summary>
    public IReadOnlyList<string>? Snippets { get; set; }

    /// <summary>Behavior classes such as Persistence, DefenseEvasion, CredentialAccess, Destructive, or NetworkStaging.</summary>
    public IReadOnlyList<string>? BehaviorTags { get; set; }

    internal static IEnumerable<FindingView> From(IReadOnlyList<string>? findings, IReadOnlyList<FindingEvidence>? evidence = null)
    {
        if (findings is null || findings.Count == 0) yield break;

        var legend = Legend.GetHeuristicsLegend();
        var evidenceByCode = BuildEvidenceLookup(evidence);
        foreach (var finding in findings)
        {
            if (string.IsNullOrWhiteSpace(finding))
            {
                continue;
            }

            var code = finding.Trim();
            evidenceByCode.TryGetValue(code, out var detail);
            var singleFinding = new[] { code };
            var legendEntry = legend.FirstOrDefault(entry => string.Equals(entry.Code, code, StringComparison.OrdinalIgnoreCase));

            var shortSummary = Legend.HumanizeFindings(singleFinding, HumanizeStyle.Short, limit: 1, separator: ", ");
            var longSummary = Legend.HumanizeFindings(singleFinding, HumanizeStyle.Long, limit: 1, separator: ", ");

            yield return new FindingView
            {
                Code = code,
                SummaryShort = string.IsNullOrWhiteSpace(shortSummary) ? null : shortSummary,
                SummaryLong = string.IsNullOrWhiteSpace(longSummary) ? null : longSummary,
                Category = legendEntry?.Category,
                Severity = legendEntry?.Severity,
                Line = detail?.Line,
                Snippet = string.IsNullOrWhiteSpace(detail?.Snippet) ? null : detail?.Snippet,
                SourceTag = string.IsNullOrWhiteSpace(detail?.SourceTag) ? null : detail?.SourceTag,
                HitCount = detail?.HitCount,
                Lines = detail?.Lines,
                Snippets = detail?.Snippets,
                BehaviorTags = detail?.BehaviorTags
            };
        }
    }

    private static Dictionary<string, FindingEvidence> BuildEvidenceLookup(IReadOnlyList<FindingEvidence>? evidence)
    {
        var lookup = new Dictionary<string, FindingEvidence>(StringComparer.OrdinalIgnoreCase);
        if (evidence == null || evidence.Count == 0)
        {
            return lookup;
        }

        foreach (var item in evidence)
        {
            if (item == null || string.IsNullOrWhiteSpace(item.Code) || lookup.ContainsKey(item.Code))
            {
                continue;
            }

            lookup[item.Code.Trim()] = item;
        }

        return lookup;
    }
}
