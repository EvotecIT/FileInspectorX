namespace FileInspectorX;

/// <summary>One explanatory comparison basis. Scores describe inspected evidence, not purpose or behavior.</summary>
public sealed class ReportComparisonEvidence
{
    /// <summary>Comparison basis, such as exact-bytes, whole-archive-members or whole-pe-sections.</summary>
    public string Basis { get; set; } = string.Empty;
    /// <summary>Algorithm and comparison-policy version.</summary>
    public string Algorithm { get; set; } = string.Empty;
    /// <summary>Overlap within the named compared sample, in [0,1].</summary>
    public double Score { get; set; }
    /// <summary>Number of comparable source items on the left.</summary>
    public int ComparedLeft { get; set; }
    /// <summary>Number of comparable source items on the right.</summary>
    public int ComparedRight { get; set; }
    /// <summary>Observed source items on the left lacking a whole hash.</summary>
    public int UncomparedLeft { get; set; }
    /// <summary>Observed source items on the right lacking a whole hash.</summary>
    public int UncomparedRight { get; set; }
    /// <summary>Whole-region or expanded-member bytes compared on the left; null for text shingles.</summary>
    public long? ComparedBytesLeft { get; set; }
    /// <summary>Whole-region or expanded-member bytes compared on the right; null for text shingles.</summary>
    public long? ComparedBytesRight { get; set; }
    /// <summary>True when extraction, region hashing or inventory coverage was incomplete.</summary>
    public bool Partial { get; set; }
    /// <summary>Whole-region matches, preserving names and physical offsets where available.</summary>
    public IReadOnlyList<ReportRegionMatch> Matches { get; set; } = Array.Empty<ReportRegionMatch>();
}

/// <summary>Two whole regions or members with the same exact bytes.</summary>
public sealed class ReportRegionMatch
{
    /// <summary>Source name on the left; may be duplicated in an archive.</summary>
    public string LeftName { get; set; } = string.Empty;
    /// <summary>Source name on the right.</summary>
    public string RightName { get; set; } = string.Empty;
    /// <summary>Source ordinal on the left.</summary>
    public int LeftOrdinal { get; set; }
    /// <summary>Source ordinal on the right.</summary>
    public int RightOrdinal { get; set; }
    /// <summary>Physical left offset when this is a binary region.</summary>
    public long? LeftOffset { get; set; }
    /// <summary>Physical right offset when this is a binary region.</summary>
    public long? RightOffset { get; set; }
    /// <summary>Whole matched length.</summary>
    public long ByteLength { get; set; }
    /// <summary>Whole-region SHA-256.</summary>
    public string Sha256 { get; set; } = string.Empty;
}

/// <summary>Exact identity, text and independently named whole-region comparisons.</summary>
public static class ReportComparison
{
    /// <summary>Returns every available comparison basis, including zero overlap. Empty means no comparable evidence.</summary>
    public static IReadOnlyList<ReportComparisonEvidence> Compare(InspectionReport left, InspectionReport right)
    {
        if (left == null) throw new ArgumentNullException(nameof(left));
        if (right == null) throw new ArgumentNullException(nameof(right));
        if (!InspectionReport.SupportsSchema(left.SchemaVersion) || !InspectionReport.SupportsSchema(right.SchemaVersion))
            throw new NotSupportedException("Unsupported report schema.");
        var result = new List<ReportComparisonEvidence>();
        if (ValidHash(left.File.Sha256) && string.Equals(left.File.Sha256, right.File.Sha256, StringComparison.OrdinalIgnoreCase))
            result.Add(new ReportComparisonEvidence { Basis = "exact-bytes", Algorithm = "sha256", Score = 1,
                ComparedLeft = 1, ComparedRight = 1, ComparedBytesLeft = left.File.SizeBytes, ComparedBytesRight = right.File.SizeBytes });
        else
        {
            var text = ReportSimilarity.Compare(left, right);
            if (text.HasValue) result.Add(new ReportComparisonEvidence { Basis = "extracted-text-shingles", Algorithm = "bottom-k-word-sha256-128/v1",
                Score = text.Value, ComparedLeft = left.Content.TextFingerprint.Count, ComparedRight = right.Content.TextFingerprint.Count,
                Partial = left.Outcome == InspectionOutcome.Partial || right.Outcome == InspectionOutcome.Partial });
        }
        AddComparison(result, "whole-archive-members", Members(left), Members(right), left, right);
        foreach (var kind in new[] { "pe-section", "fixed-block" })
            AddComparison(result, kind == "pe-section" ? "whole-pe-sections" : "sampled-fixed-blocks", Regions(left, kind), Regions(right, kind), left, right);
        return result;
    }

    private sealed class Item
    {
        internal string Name = string.Empty;
        internal string? Hash;
        internal int Ordinal;
        internal long Length;
        internal long? Offset;
    }
    private static Item[] Members(InspectionReport report) => report.Content.Entries.Select((entry, index) => new { entry, index })
        .Where(item => report.SchemaVersion == 1 ? !item.entry.Name.EndsWith("/", StringComparison.Ordinal) : item.entry.Kind != ReportArchiveEntryKind.Directory)
        .Select(item => new Item { Name = item.entry.Name, Hash = item.entry.Sha256, Length = item.entry.SizeBytes,
            Ordinal = report.SchemaVersion == 1 ? item.index : item.entry.Ordinal }).ToArray();
    private static Item[] Regions(InspectionReport report, string kind) => report.Content.Regions.Where(r => r.Kind == kind)
        .Select((r, i) => new Item { Name = r.Name, Hash = r.HashBytes == r.ByteLength && r.Status == InspectionStageStatus.Completed ? r.Sha256 : null,
            Length = r.ByteLength, Offset = r.ByteOffset, Ordinal = i }).ToArray();
    private static bool ValidHash(string? hash) => hash is { Length: 64 } && hash.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F');

    private static void AddComparison(List<ReportComparisonEvidence> output, string basis, Item[] left, Item[] right,
        InspectionReport leftReport, InspectionReport rightReport)
    {
        var a = left.Where(i => i.Length >= 0 && ValidHash(i.Hash)).ToArray();
        var b = right.Where(i => i.Length >= 0 && ValidHash(i.Hash)).ToArray();
        if (a.Length == 0 || b.Length == 0) return;
        var available = b.GroupBy(i => i.Hash!.ToLowerInvariant() + ":" + i.Length.ToString(System.Globalization.CultureInfo.InvariantCulture))
            .ToDictionary(g => g.Key, g => new Queue<Item>(g));
        var matches = new List<ReportRegionMatch>();
        foreach (var item in a)
        {
            var key = item.Hash!.ToLowerInvariant() + ":" + item.Length.ToString(System.Globalization.CultureInfo.InvariantCulture);
            if (!available.TryGetValue(key, out var candidates) || candidates.Count == 0) continue;
            var other = candidates.Dequeue();
            matches.Add(new ReportRegionMatch { LeftName = item.Name, RightName = other.Name, LeftOrdinal = item.Ordinal, RightOrdinal = other.Ordinal,
                LeftOffset = item.Offset, RightOffset = other.Offset, ByteLength = item.Length, Sha256 = item.Hash.ToLowerInvariant() });
        }
        output.Add(new ReportComparisonEvidence { Basis = basis, Algorithm = "sha256-multiset-overlap/v1", Score = matches.Count / (double)(a.Length + b.Length - matches.Count),
            ComparedLeft = a.Length, ComparedRight = b.Length, UncomparedLeft = left.Length - a.Length, UncomparedRight = right.Length - b.Length,
            ComparedBytesLeft = a.Sum(i => i.Length), ComparedBytesRight = b.Sum(i => i.Length), Matches = matches,
            Partial = left.Length != a.Length || right.Length != b.Length || leftReport.Outcome == InspectionOutcome.Partial || rightReport.Outcome == InspectionOutcome.Partial });
    }
}
