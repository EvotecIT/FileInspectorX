namespace FileInspectorX;

/// <summary>Explicit bounded extraction policy. No external services or engines are invoked.</summary>
public sealed class InspectionReportOptions
{
    /// <summary>Maximum whole input buffered for a stable byte identity. Default 64 MiB.</summary>
    public int MaxInputBytes { get; set; } = 64 * 1024 * 1024;
    /// <summary>Maximum text characters retained. Default 64 Ki characters.</summary>
    public int MaxTextCharacters { get; set; } = 64 * 1024;
    /// <summary>Maximum inventory/OOXML parts visited. Default 256.</summary>
    public int MaxArchiveEntries { get; set; } = 256;
    /// <summary>Maximum expanded bytes per member. Default 1 MiB.</summary>
    public int MaxEntryBytes { get; set; } = 1024 * 1024;
    /// <summary>Maximum expanded member bytes read in total. Default 16 MiB.</summary>
    public int MaxExpandedBytes { get; set; } = 16 * 1024 * 1024;
    /// <summary>Maximum bytes retained in memory before the exact snapshot spills to a private temporary file. Default 64 MiB.</summary>
    public int MaxMemorySnapshotBytes { get; set; } = 64 * 1024 * 1024;
    /// <summary>Optional existing directory for private temporary snapshots. Null uses the host's temporary directory.</summary>
    public string? SnapshotDirectory { get; set; }
    /// <summary>Maximum cumulative bytes probed by a media metadata reader. Payloads are skipped by seeking.</summary>
    public int MaxMetadataBytes { get; set; } = 1024 * 1024;
    /// <summary>Maximum typed facts retained by each content reader.</summary>
    public int MaxFacts { get; set; } = 256;
    /// <summary>Maximum characters in one retained fact value.</summary>
    public int MaxFactCharacters { get; set; } = 4096;
    /// <summary>Maximum aggregate text/fact/metadata characters across root and descendant content profiles.</summary>
    public int MaxTotalContentCharacters { get; set; } = 256 * 1024;
    /// <summary>Maximum characters retained in each decoded archive member display name.</summary>
    public int MaxEntryNameCharacters { get; set; } = 1024;
    /// <summary>Maximum characters in a complete reader, member, field or location identifier. Identifiers are omitted, never shortened.</summary>
    public int MaxIdentifierCharacters { get; set; } = 1024;
    /// <summary>Maximum region or fixed-block records emitted for one input.</summary>
    public int MaxRegions { get; set; } = 32;
    /// <summary>Maximum bytes hashed for one complete binary region.</summary>
    public int MaxRegionBytes { get; set; } = 2 * 1024 * 1024;
    /// <summary>Maximum aggregate region bytes hashed for one input.</summary>
    public int MaxRegionHashBytes { get; set; } = 16 * 1024 * 1024;
    /// <summary>Maximum descendant reports across one root report. Zero disables nested analysis.</summary>
    public int MaxNestedReports { get; set; } = 32;
    /// <summary>Maximum descendant depth; the root is depth zero. Zero disables nested analysis.</summary>
    public int MaxNestedDepth { get; set; } = 2;
    /// <summary>Maximum logical document units retained for one input.</summary>
    public int MaxDocumentUnits { get; set; } = 256;
    /// <summary>Maximum structured diagnostics and omissions retained for one input.</summary>
    public int MaxDiagnostics { get; set; } = 256;
    /// <summary>Maximum native model/source expansion reserved for one optional-reader invocation. Default 64 MiB.</summary>
    public long MaxNativeExpandedBytes { get; set; } = 64L * 1024 * 1024;
    /// <summary>Maximum native model/source expansion across the root and descendants. Default 256 MiB.</summary>
    public long MaxTotalNativeExpandedBytes { get; set; } = 256L * 1024 * 1024;
    /// <summary>Maximum cumulative optional-reader source bytes read across the root, including repeated reads.</summary>
    public long MaxNativeReadBytes { get; set; } = 256L * 1024 * 1024;
    /// <summary>Maximum cumulative optional-reader decompression work across the root, including unretained output.</summary>
    public long MaxDecompressionWorkBytes { get; set; } = 256L * 1024 * 1024;
    /// <summary>Optional operation-scoped content reader. The caller owns its lifetime; calls on one instance are serialized.</summary>
    public IInspectionContentReader? ContentReader { get; set; }
    /// <summary>Existing core settings. Null uses bounded, portable analysis without filesystem enrichment.</summary>
    public FileInspector.DetectionOptions? Detection { get; set; }

    internal InspectionReportOptions Copy()
    {
        if (MaxInputBytes <= 0 || MaxTextCharacters <= 0 || MaxArchiveEntries <= 0 || MaxEntryBytes <= 0 || MaxExpandedBytes <= 0 ||
            MaxMemorySnapshotBytes <= 0 || MaxMetadataBytes <= 0 || MaxFacts <= 0 || MaxFactCharacters <= 0 ||
            MaxRegions <= 0 || MaxRegionBytes <= 0 || MaxRegionHashBytes <= 0 || MaxNestedReports < 0 || MaxNestedDepth < 0 ||
            MaxTotalContentCharacters <= 0 || MaxEntryNameCharacters <= 0 || MaxIdentifierCharacters <= 0 || MaxDocumentUnits <= 0 || MaxDiagnostics <= 0 ||
            MaxNativeExpandedBytes < 0 || MaxTotalNativeExpandedBytes < 0 || MaxNativeReadBytes < 0 || MaxDecompressionWorkBytes < 0)
            throw new ArgumentOutOfRangeException(nameof(InspectionReportOptions), "Report output budgets must be positive; nesting and native allowances may be zero.");
        return new InspectionReportOptions
        {
            MaxInputBytes = MaxInputBytes, MaxTextCharacters = MaxTextCharacters,
            MaxArchiveEntries = MaxArchiveEntries, MaxEntryBytes = MaxEntryBytes, MaxExpandedBytes = MaxExpandedBytes,
            MaxMemorySnapshotBytes = MaxMemorySnapshotBytes, SnapshotDirectory = SnapshotDirectory,
            MaxMetadataBytes = MaxMetadataBytes, MaxFacts = MaxFacts, MaxFactCharacters = MaxFactCharacters,
            MaxTotalContentCharacters = MaxTotalContentCharacters, MaxEntryNameCharacters = MaxEntryNameCharacters,
            MaxIdentifierCharacters = MaxIdentifierCharacters,
            MaxRegions = MaxRegions, MaxRegionBytes = MaxRegionBytes, MaxRegionHashBytes = MaxRegionHashBytes,
            MaxNestedReports = MaxNestedReports, MaxNestedDepth = MaxNestedDepth,
            MaxDocumentUnits = MaxDocumentUnits, MaxDiagnostics = MaxDiagnostics,
            MaxNativeExpandedBytes = MaxNativeExpandedBytes, MaxTotalNativeExpandedBytes = MaxTotalNativeExpandedBytes,
            MaxNativeReadBytes = MaxNativeReadBytes, MaxDecompressionWorkBytes = MaxDecompressionWorkBytes,
            ContentReader = ContentReader
        };
    }
}
