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

    internal static IEnumerable<FindingView> From(IReadOnlyList<string>? findings)
    {
        if (findings is null || findings.Count == 0) yield break;

        foreach (var finding in findings)
        {
            if (string.IsNullOrWhiteSpace(finding))
            {
                continue;
            }

            var code = finding.Trim();
            var legend = Legend.GetHeuristicsLegend()
                .FirstOrDefault(entry => string.Equals(entry.Code, code, StringComparison.OrdinalIgnoreCase));

            var shortSummary = Legend.HumanizeFindings(new[] { code }, HumanizeStyle.Short, limit: 1, separator: ", ");
            var longSummary = Legend.HumanizeFindings(new[] { code }, HumanizeStyle.Long, limit: 1, separator: ", ");

            yield return new FindingView
            {
                Code = code,
                SummaryShort = string.IsNullOrWhiteSpace(shortSummary) ? null : shortSummary,
                SummaryLong = string.IsNullOrWhiteSpace(longSummary) ? null : longSummary,
                Category = legend?.Category,
                Severity = legend?.Severity
            };
        }
    }
}
