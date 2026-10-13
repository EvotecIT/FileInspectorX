using System.Text;
using System.Text.RegularExpressions;

namespace FileInspectorX;

internal static class ReportText
{
    private static readonly HashSet<string> Common = new("the and with from this that have will your they are for not into was were has you its can file".Split(' '), StringComparer.OrdinalIgnoreCase);

    internal static void Enrich(ContentProfile profile)
    {
        var counts = new Dictionary<string, int>(StringComparer.Ordinal);
        var tokens = new List<string>();
        foreach (Match match in Regex.Matches(profile.Text, @"[\p{L}\p{N}_-]{3,64}", RegexOptions.None, TimeSpan.FromSeconds(1)))
        {
            InspectionOperation.CheckCancellation();
            var token = match.Value.ToLowerInvariant();
            tokens.Add(token);
            if (!Common.Contains(token)) counts[token] = counts.TryGetValue(token, out var count) ? count + 1 : 1;
        }
        profile.Keywords = counts.OrderByDescending(p => p.Value).ThenBy(p => p.Key, StringComparer.Ordinal).Take(12).Select(p => p.Key).ToArray();
        // Bottom-k hashes of three-word shingles: stable, bounded and comparable across differently ordered reports.
        var hashes = new SortedSet<string>(StringComparer.Ordinal);
        for (var i = 0; i + 2 < tokens.Count; i++)
        {
            InspectionOperation.CheckCancellation();
            hashes.Add(FileInspector.ReportHash(Encoding.UTF8.GetBytes(tokens[i] + " " + tokens[i + 1] + " " + tokens[i + 2])).Substring(0, 16));
            if (hashes.Count > 128) hashes.Remove(hashes.Max!);
        }
        profile.TextFingerprint = hashes.ToArray();
    }
}

/// <summary>Similarity of exact bytes or extracted text samples. This is not a safety or semantic equivalence verdict.</summary>
public static class ReportSimilarity
{
    /// <summary>Returns 1 for exact SHA-256 equality. Otherwise estimates text shingle overlap in [0,1].
    /// Null means insufficient comparable text. Report versions 1 and 2 are supported.</summary>
    public static double? Compare(InspectionReport first, InspectionReport second)
    {
        if (first == null) throw new ArgumentNullException(nameof(first));
        if (second == null) throw new ArgumentNullException(nameof(second));
        if (!InspectionReport.SupportsSchema(first.SchemaVersion) || !InspectionReport.SupportsSchema(second.SchemaVersion)) throw new NotSupportedException("Unsupported report schema.");
        if (first.File.Sha256.Length == 64 && first.File.Sha256 == second.File.Sha256) return 1;
        if (first.Content.TextFingerprint.Count < 3 || second.Content.TextFingerprint.Count < 3) return null;
        var union = new SortedSet<string>(first.Content.TextFingerprint, StringComparer.Ordinal);
        union.UnionWith(second.Content.TextFingerprint);
        var sample = union.Take(128).ToArray();
        var a = new HashSet<string>(first.Content.TextFingerprint, StringComparer.Ordinal);
        var b = new HashSet<string>(second.Content.TextFingerprint, StringComparer.Ordinal);
        return sample.Count(hash => a.Contains(hash) && b.Contains(hash)) / (double)sample.Length;
    }
}
