using System;
using System.Collections.Generic;
using System.Linq;

namespace FileInspectorX;

/// <summary>
/// Flattened projection of an assessment driver code for host integration and display.
/// </summary>
public sealed class AssessmentCodeView
{
    /// <summary>Stable assessment code emitted by FileInspectorX.</summary>
    public string Code { get; set; } = string.Empty;
    /// <summary>Short human-friendly label for compact displays.</summary>
    public string? SummaryShort { get; set; }
    /// <summary>Long human-friendly description for detailed displays.</summary>
    public string? SummaryLong { get; set; }
    /// <summary>Category grouping when the assessment legend provides one.</summary>
    public string? Category { get; set; }
    /// <summary>Rough severity score when the assessment legend provides one.</summary>
    public int? Severity { get; set; }
    /// <summary>Score contribution for this code when known.</summary>
    public int? ScoreContribution { get; set; }

    internal static IEnumerable<AssessmentCodeView> From(
        IReadOnlyList<string>? codes,
        IReadOnlyDictionary<string, int>? factors)
    {
        if (codes is null || codes.Count == 0)
        {
            yield break;
        }

        var legend = AssessmentLegend.GetLegend();
        foreach (var codeValue in codes)
        {
            if (string.IsNullOrWhiteSpace(codeValue))
            {
                continue;
            }

            var code = codeValue.Trim();
            var entry = legend.FirstOrDefault(item => string.Equals(item.Code, code, StringComparison.OrdinalIgnoreCase));
            int? contribution = null;
            if (factors != null && factors.TryGetValue(code, out var factorValue))
            {
                contribution = factorValue;
            }

            yield return new AssessmentCodeView
            {
                Code = code,
                SummaryShort = string.IsNullOrWhiteSpace(AssessmentLegend.HumanizeCodes(new[] { code }, HumanizeStyle.Short))
                    ? null
                    : AssessmentLegend.HumanizeCodes(new[] { code }, HumanizeStyle.Short),
                SummaryLong = string.IsNullOrWhiteSpace(AssessmentLegend.HumanizeCodes(new[] { code }, HumanizeStyle.Long))
                    ? null
                    : AssessmentLegend.HumanizeCodes(new[] { code }, HumanizeStyle.Long),
                Category = entry?.Category,
                Severity = entry?.Severity,
                ScoreContribution = contribution
            };
        }
    }
}
