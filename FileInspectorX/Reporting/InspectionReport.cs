namespace FileInspectorX;

/// <summary>A portable, versioned report shared by API, local service and report consumers.</summary>
public sealed class InspectionReport
{
    /// <summary>Current portable report contract. Version 1 remains readable by current consumers.</summary>
    public const int CurrentSchemaVersion = 2;
    /// <summary>Whether the supplied saved-report version can be interpreted by this library.</summary>
    public static bool SupportsSchema(int version) => version is 1 or CurrentSchemaVersion;
    /// <summary>Schema contract version. Consumers must reject unsupported major versions.</summary>
    public int SchemaVersion { get; set; } = CurrentSchemaVersion;
    /// <summary>Version of the analysis library that produced this report.</summary>
    public string AnalyzerVersion { get; set; } = string.Empty;
    /// <summary>UTC creation time.</summary>
    public DateTimeOffset CreatedUtc { get; set; }
    /// <summary>Identity of the exact bytes analyzed, without a host filesystem path.</summary>
    public ReportFileIdentity File { get; set; } = new();
    /// <summary>Existing detection, validation, flags, signatures and stage evidence.</summary>
    public FileAnalysis Analysis { get; set; } = new();
    /// <summary>Bounded content understanding and its explicit coverage.</summary>
    public ContentProfile Content { get; set; } = new();
    /// <summary>Plain language observations, each linked to report evidence.</summary>
    public IReadOnlyList<ReportObservation> Observations { get; set; } = Array.Empty<ReportObservation>();
    /// <summary>Partial when either the existing analysis or content extraction is partial.</summary>
    public InspectionOutcome Outcome => Analysis.Outcome == InspectionOutcome.InputUnavailable ? InspectionOutcome.InputUnavailable :
        Analysis.Outcome == InspectionOutcome.Partial || Content.Status is InspectionStageStatus.Partial or InspectionStageStatus.Failed or InspectionStageStatus.Unavailable
            ? InspectionOutcome.Partial : InspectionOutcome.Complete;
}

/// <summary>Stable identity and original display name of one analyzed input.</summary>
public sealed class ReportFileIdentity
{
    /// <summary>Display name only. Never a server or source filesystem path.</summary>
    public string Name { get; set; } = string.Empty;
    /// <summary>Length in bytes of the analyzed input.</summary>
    public long SizeBytes { get; set; }
    /// <summary>Lowercase SHA-256 of the entire analyzed input.</summary>
    public string Sha256 { get; set; } = string.Empty;
}

/// <summary>Text, structure and metadata extracted without executing file content.</summary>
public sealed class ContentProfile
{
    /// <summary>Reader identifier, for example ooxml-word or utf-text.</summary>
    public string Reader { get; set; } = "unsupported";
    /// <summary>Completion of this reader, independently of detection and assessment.</summary>
    public InspectionStageStatus Status { get; set; } = InspectionStageStatus.NotApplicable;
    /// <summary>Stable limits, failures and unsupported features. Absence is never a claim of full format fidelity.</summary>
    public IReadOnlyList<string> Issues { get; set; } = Array.Empty<string>();
    /// <summary>Bounded readable text. May contain sensitive input data; consumers control retention.</summary>
    public string Text { get; set; } = string.Empty;
    /// <summary>Format-specific facts and counts; sampled counts are explicitly named as such.</summary>
    public IReadOnlyDictionary<string, string> Metadata { get; set; } = new Dictionary<string, string>();
    /// <summary>Bounded inventory of ZIP entries, never extracted to the filesystem.</summary>
    public IReadOnlyList<ReportArchiveEntry> Entries { get; set; } = Array.Empty<ReportArchiveEntry>();
    /// <summary>Most frequent words in the extracted text, excluding a small common-word list.</summary>
    public IReadOnlyList<string> Keywords { get; set; } = Array.Empty<string>();
    /// <summary>Deterministic text shingles for similarity of extracted samples, not a semantic embedding.</summary>
    public IReadOnlyList<string> TextFingerprint { get; set; } = Array.Empty<string>();
    /// <summary>Typed facts with embedded/derived provenance and locations in the analyzed snapshot.</summary>
    public IReadOnlyList<ReportFact> Facts { get; set; } = Array.Empty<ReportFact>();
    /// <summary>Whole-region hashes and explicit inspected-byte coverage; no execution-equivalence claim.</summary>
    public IReadOnlyList<ReportRegion> Regions { get; set; } = Array.Empty<ReportRegion>();
}

/// <summary>Inventory evidence for an archive member.</summary>
public enum ReportArchiveEntryKind
{
    /// <summary>Member type was not recorded, including saved schema-1 reports.</summary>
    Unknown,
    /// <summary>Regular file payload.</summary>
    File,
    /// <summary>Directory record, with no file payload to compare.</summary>
    Directory,
    /// <summary>Another inert archive record, such as a TAR symbolic link.</summary>
    Other
}

/// <summary>Inventory evidence for an archive member.</summary>
public sealed class ReportArchiveEntry
{
    /// <summary>Member name, retained as data and never interpreted as a path to write.</summary>
    public string Name { get; set; } = string.Empty;
    /// <summary>Source member kind, independent of the retained display-name prefix.</summary>
    public ReportArchiveEntryKind Kind { get; set; }
    /// <summary>Declared expanded length.</summary>
    public long SizeBytes { get; set; }
    /// <summary>Declared compressed length.</summary>
    public long CompressedBytes { get; set; }
    /// <summary>Whole-member hash when the member could be read within the budget; otherwise null.</summary>
    public string? Sha256 { get; set; }
    /// <summary>Zero-based member ordinal, retaining identity when names are duplicated.</summary>
    public int Ordinal { get; set; }
    /// <summary>Independent report for this inert member when aggregate nesting budgets permit it.</summary>
    public InspectionReport? Report { get; set; }
    /// <summary>True when the decoded source name exceeded the retained-name budget.</summary>
    public bool NameTruncated { get; set; }
    /// <summary>Full decoded source-name character count; ordinal retains exact member identity.</summary>
    public int SourceNameCharacters { get; set; }
}

/// <summary>A factual explanation and the property that supports it.</summary>
public sealed class ReportObservation
{
    /// <summary>Stable observation code.</summary>
    public string Code { get; set; } = string.Empty;
    /// <summary>Plain text explanation, never HTML or Markdown.</summary>
    public string Text { get; set; } = string.Empty;
    /// <summary>Property path within this schema, for example Analysis.Detection.</summary>
    public string Evidence { get; set; } = string.Empty;
}

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
    /// <summary>Maximum characters retained in each decoded archive member name.</summary>
    public int MaxEntryNameCharacters { get; set; } = 1024;
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
    /// <summary>Existing core settings. Null uses bounded, portable analysis without filesystem enrichment.</summary>
    public FileInspector.DetectionOptions? Detection { get; set; }
}
