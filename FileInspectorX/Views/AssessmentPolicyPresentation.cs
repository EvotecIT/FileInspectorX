using System;
using System.Collections.Generic;
using System.Linq;

namespace FileInspectorX;

/// <summary>
/// Shared helpers that turn assessment driver details into operator-facing policy summaries.
/// </summary>
internal static class AssessmentPolicyPresentation
{
    public static string? FormatTopDrivers(IReadOnlyList<AssessmentCodeView>? details, int limit = 3)
        => FormatTopDrivers(details, includeLongText: false, limit: limit);

    public static string? FormatTopDriversLong(IReadOnlyList<AssessmentCodeView>? details, int limit = 3)
        => FormatTopDrivers(details, includeLongText: true, limit: limit);

    public static string? FormatCategories(IReadOnlyList<AssessmentCodeView>? details, int limit = 4)
    {
        if (details == null || details.Count == 0)
        {
            return null;
        }

        var categories = details
            .Where(detail => detail != null && !string.IsNullOrWhiteSpace(detail.Category))
            .GroupBy(detail => detail.Category!.Trim(), StringComparer.OrdinalIgnoreCase)
            .Select(group => new
            {
                Category = group.First().Category!.Trim(),
                MaxScore = group.Max(detail => Math.Abs(detail.ScoreContribution ?? 0)),
                MaxSeverity = group.Max(detail => detail.Severity ?? 0)
            })
            .OrderByDescending(item => item.MaxScore)
            .ThenByDescending(item => item.MaxSeverity)
            .ThenBy(item => item.Category, StringComparer.OrdinalIgnoreCase)
            .Select(item => item.Category)
            .ToList();

        return JoinLimited(categories, limit);
    }

    public static string? BuildRecommendedAction(string? decision, int? score)
    {
        return ParseDecision(decision) switch
        {
            AssessmentDecision.Allow when !score.HasValue || score.Value <= 15 => "Allow automatically and keep routine logging.",
            AssessmentDecision.Allow => "Allow, but keep routine logging and spot-check if the source is unusual.",
            AssessmentDecision.Warn => "Allow only after manual review of the top risk drivers.",
            AssessmentDecision.Block => "Block by default and investigate before any manual release.",
            AssessmentDecision.Defer => "Hold for manual review until policy or operator guidance is available.",
            _ => null
        };
    }

    public static bool? IsSafeForAutomation(string? decision, int? score)
    {
        return ParseDecision(decision) switch
        {
            AssessmentDecision.Allow => !score.HasValue || score.Value <= 15,
            AssessmentDecision.Warn => false,
            AssessmentDecision.Block => false,
            AssessmentDecision.Defer => false,
            _ => null
        };
    }

    private static string? FormatTopDrivers(IReadOnlyList<AssessmentCodeView>? details, bool includeLongText, int limit)
    {
        if (details == null || details.Count == 0)
        {
            return null;
        }

        var drivers = details
            .Where(detail => detail != null)
            .Select(detail => new
            {
                Detail = detail!,
                Score = Math.Abs(detail!.ScoreContribution ?? 0),
                Severity = detail.Severity ?? 0,
                Label = FirstNonEmpty(detail.SummaryShort, detail.SummaryLong, detail.Code),
                LongLabel = FirstNonEmpty(detail.SummaryLong, detail.SummaryShort, detail.Code)
            })
            .Where(item => !string.IsNullOrWhiteSpace(item.Label))
            .OrderByDescending(item => item.Score)
            .ThenByDescending(item => item.Severity)
            .ThenBy(item => item.Label, StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (drivers.Count == 0)
        {
            return null;
        }

        var rendered = new List<string>();
        foreach (var item in drivers)
        {
            var label = AppendScore(item.Label!.Trim(), item.Detail.ScoreContribution);
            if (includeLongText)
            {
                var longLabel = item.LongLabel?.Trim();
                if (!string.IsNullOrWhiteSpace(longLabel) &&
                    !string.Equals(longLabel, item.Label, StringComparison.OrdinalIgnoreCase))
                {
                    label += $": {longLabel}";
                }
            }

            if (!rendered.Contains(label, StringComparer.OrdinalIgnoreCase))
            {
                rendered.Add(label);
            }
        }

        return JoinLimited(rendered, limit);
    }

    private static string AppendScore(string label, int? score)
    {
        if (!score.HasValue || score.Value == 0)
        {
            return label;
        }

        return $"{label} ({FormatSignedScore(score.Value)})";
    }

    private static string FormatSignedScore(int score)
        => score >= 0 ? $"+{score}" : score.ToString();

    private static AssessmentDecision? ParseDecision(string? decision)
    {
        return Enum.TryParse<AssessmentDecision>(decision, ignoreCase: true, out var parsed)
            ? parsed
            : null;
    }

    private static string? FirstNonEmpty(params string?[] values)
    {
        foreach (var value in values)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return null;
    }

    private static string? JoinLimited(IReadOnlyList<string> values, int limit)
    {
        if (values.Count == 0)
        {
            return null;
        }

        if (limit <= 0 || values.Count <= limit)
        {
            return string.Join(", ", values);
        }

        var head = values.Take(limit).ToList();
        head.Add($"+{values.Count - limit} more");
        return string.Join(", ", head);
    }
}
