namespace FileInspectorX;

/// <summary>Whole-root admission accounting shared by all nested content readers.</summary>
internal sealed class ReportReadContext
{
    private readonly InspectionReportOptions _options;
    private readonly FileInspector.DetectionOptions _detection;
    private int _nestedReports;
    private int _expandedBytes;
    private int _contentCharacters;
    internal ReportReadContext(InspectionReportOptions options, FileInspector.DetectionOptions detection)
    { _options = options; _detection = detection; }
    internal int RemainingExpandedBytes => Math.Max(0, _options.MaxExpandedBytes - _expandedBytes);
    internal void AccountExpandedBytes(int count) => _expandedBytes = checked(_expandedBytes + count);

    internal ReportArchiveEntry Member(string name, long size, long compressed, int ordinal, ReportArchiveEntryKind kind, HashSet<string> issues)
    {
        bool truncated = name.Length > _options.MaxEntryNameCharacters;
        if (truncated) issues.Add("content:member-name-limit");
        return new ReportArchiveEntry { Name = truncated ? Prefix(name, _options.MaxEntryNameCharacters) : name, Kind = kind,
            SourceNameCharacters = name.Length, NameTruncated = truncated, SizeBytes = size, CompressedBytes = compressed, Ordinal = ordinal };
    }

    internal void BoundContent(ContentProfile profile, Dictionary<string, string> metadata, HashSet<string> issues)
    {
        int Remaining() => Math.Max(0, _options.MaxTotalContentCharacters - _contentCharacters);
        var text = profile.Text;
        if (text.Length > Remaining()) { text = Prefix(text, Remaining()); issues.Add("content:aggregate-character-limit"); }
        profile.Text = text; _contentCharacters += text.Length;
        var facts = new List<ReportFact>();
        foreach (var fact in profile.Facts)
        {
            int allowance = Remaining() - fact.Name.Length;
            if (allowance < 0 || fact.Value.Length > allowance && fact.Kind != ReportFactKind.Text)
            { issues.Add("content:aggregate-character-limit"); continue; }
            if (fact.Value.Length > allowance)
            { fact.Value = Prefix(fact.Value, allowance); fact.Truncated = true; issues.Add("content:aggregate-character-limit"); }
            _contentCharacters += fact.Name.Length + fact.Value.Length; facts.Add(fact);
        }
        profile.Facts = facts;
        var retained = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var pair in metadata)
        {
            int allowance = Remaining() - pair.Key.Length;
            if (allowance < pair.Value.Length) { issues.Add("content:aggregate-character-limit"); continue; }
            retained.Add(pair.Key, pair.Value); _contentCharacters += pair.Key.Length + pair.Value.Length;
        }
        profile.Metadata = retained;
    }

    internal static string Prefix(string value, int length)
    {
        length = Math.Min(value.Length, Math.Max(0, length));
        if (length > 0 && char.IsHighSurrogate(value[length - 1])) length--;
        return value.Substring(0, length);
    }

    internal InspectionReport? ReadChild(byte[] bytes, string name, int parentDepth, HashSet<string> issues)
    {
        if (_options.MaxNestedReports == 0 || _options.MaxNestedDepth == 0) return null;
        if (parentDepth >= _options.MaxNestedDepth || _nestedReports >= _options.MaxNestedReports)
        { issues.Add("content:nested-report-limit"); return null; }
        _nestedReports++;
        using var stream = new MemoryStream(bytes, writable: false);
        return FileInspector.AnalyzeReportSnapshot(stream, FileInspector.ReportHash(bytes), FileInspector.DisplayFileName(name),
            _detection.Copy(), _options, this, parentDepth + 1);
    }
}
