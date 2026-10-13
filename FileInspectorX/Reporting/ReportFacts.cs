using System.Globalization;

namespace FileInspectorX;

internal static class ReportFacts
{
    internal static IReadOnlyList<ReportFact> FromMetadata(Dictionary<string, string> metadata, InspectionReportOptions options, HashSet<string> issues)
    {
        var result = new List<ReportFact>();
        foreach (var pair in metadata.OrderBy(p => p.Key, StringComparer.Ordinal))
        {
            if (pair.Key == "Scope") continue;
            if (result.Count >= options.MaxFacts) { issues.Add("content:fact-count-limit"); break; }
            var value = pair.Value;
            var kind = long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out _) ? ReportFactKind.Integer : ReportFactKind.Text;
            bool truncated = value.Length > options.MaxFactCharacters;
            if (truncated)
            {
                issues.Add("content:fact-character-limit");
                if (kind != ReportFactKind.Text) continue;
                value = ReportReadContext.Prefix(value, options.MaxFactCharacters);
            }
            result.Add(new ReportFact { Name = pair.Key, Value = value,
                Kind = kind, Truncated = truncated, Origin = ReportFactOrigin.Derived });
        }
        return result;
    }
}
