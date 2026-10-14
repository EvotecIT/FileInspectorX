namespace FileInspectorX;

/// <summary>Whole-root admission accounting shared by all nested content readers.</summary>
internal sealed partial class ReportReadContext
{
    private readonly InspectionReportOptions _options;
    private readonly FileInspector.DetectionOptions _detection;
    private int _nestedReports;
    private int _expandedBytes;
    private int _contentCharacters;
    private long _nativeExpandedBytes;
    private long _nativeReadBytes;
    private long _decompressionWorkBytes;
    internal ReportReadContext(InspectionReportOptions options, FileInspector.DetectionOptions detection)
    { _options = options; _detection = detection; }
    internal int RemainingExpandedBytes => Math.Max(0, _options.MaxExpandedBytes - _expandedBytes);
    internal int RemainingContentCharacters => Math.Max(0, _options.MaxTotalContentCharacters - _contentCharacters);
    internal int RemainingNestedReports => Math.Max(0, _options.MaxNestedReports - _nestedReports);
    internal void AccountExpandedBytes(int count)
    {
        if (count < 0 || count > RemainingExpandedBytes)
            throw new InspectionContentLimitException(InspectionContentLimitDomain.Resource, "content:expanded-byte-limit",
                nameof(InspectionReportOptions.MaxExpandedBytes), _options.MaxExpandedBytes, (long)_expandedBytes + count);
        _expandedBytes = checked(_expandedBytes + count);
    }

    internal bool TryAccountCharacters(int count)
    {
        if (count < 0) throw new InvalidOperationException("A content character count cannot be negative.");
        if (count > RemainingContentCharacters) return false;
        _contentCharacters = checked(_contentCharacters + count);
        return true;
    }

    internal InspectionContentBudgets ReserveNative(int depth)
    {
        var expanded = Math.Min(_options.MaxNativeExpandedBytes, _options.MaxTotalNativeExpandedBytes - _nativeExpandedBytes);
        var read = _options.MaxNativeReadBytes - _nativeReadBytes;
        var work = _options.MaxDecompressionWorkBytes - _decompressionWorkBytes;
        var budgets = new InspectionContentBudgets(_options.MaxInputBytes, _options.MaxTextCharacters, _options.MaxFacts,
            _options.MaxFactCharacters, _options.MaxArchiveEntries, _options.MaxEntryBytes, RemainingExpandedBytes,
            RemainingContentCharacters, RemainingNestedReports, Math.Max(0, _options.MaxNestedDepth - depth),
            _options.MaxEntryNameCharacters, _options.MaxDocumentUnits, _options.MaxDiagnostics, expanded, read, work, _options.MaxIdentifierCharacters);
        _nativeExpandedBytes = checked(_nativeExpandedBytes + expanded);
        _nativeReadBytes = checked(_nativeReadBytes + read);
        _decompressionWorkBytes = checked(_decompressionWorkBytes + work);
        return budgets;
    }

    // Unmeasured/failed work keeps its reservation. Only a successful measured result releases unused allowance.
    internal void CompleteNative(InspectionContentBudgets budgets, InspectionContentWork work)
    {
        CheckNative(work.DecodedBytes, budgets.NativeExpandedBytes, nameof(InspectionReportOptions.MaxNativeExpandedBytes));
        CheckNative(work.ReadBytes, budgets.NativeReadBytes, nameof(InspectionReportOptions.MaxNativeReadBytes));
        CheckNative(work.DecompressionWorkBytes, budgets.DecompressionWorkBytes, nameof(InspectionReportOptions.MaxDecompressionWorkBytes));
        _nativeExpandedBytes -= budgets.NativeExpandedBytes - work.DecodedBytes;
        _nativeReadBytes -= budgets.NativeReadBytes - work.ReadBytes;
        _decompressionWorkBytes -= budgets.DecompressionWorkBytes - work.DecompressionWorkBytes;
        if (work.SelectedBytes > RemainingExpandedBytes)
            throw new InspectionContentLimitException(InspectionContentLimitDomain.Resource, "content:expanded-byte-limit",
                nameof(InspectionReportOptions.MaxExpandedBytes), _options.MaxExpandedBytes, (long)_expandedBytes + work.SelectedBytes);
        AccountExpandedBytes(checked((int)work.SelectedBytes));
    }

    private static void CheckNative(long actual, long maximum, string limit)
    {
        if (actual > maximum)
            throw new InspectionContentLimitException(InspectionContentLimitDomain.Resource, "content:native-work-limit", limit, maximum, actual);
    }

    internal ReportArchiveEntry Member(string name, long size, long compressed, int ordinal, ReportArchiveEntryKind kind, HashSet<string> issues)
    {
        bool truncated = name.Length > _options.MaxEntryNameCharacters;
        if (truncated) issues.Add("content:member-name-limit");
        return new ReportArchiveEntry { Name = truncated ? Prefix(name, _options.MaxEntryNameCharacters) : name, Kind = kind,
            DeclaredSizeBytes = size,
            SourceNameCharacters = name.Length, NameTruncated = truncated, SizeBytes = size, CompressedBytes = compressed, Ordinal = ordinal };
    }

    internal ContentProfile AdmitContent(ContentProfile profile, HashSet<string> issues, bool optionalReader, bool suppressText = false)
        => new ReportContentAdmission(_options, this, issues, optionalReader).Copy(profile, suppressText);

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
