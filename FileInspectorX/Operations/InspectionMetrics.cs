namespace FileInspectorX;

/// <summary>Immutable, opt-in measurements of a synchronous inspection and its nested library work.</summary>
public sealed class InspectionMetrics
{
    /// <summary>Elapsed wall time through result creation, measured with a monotonic clock.</summary>
    public TimeSpan Elapsed { get; }
    /// <summary>Read calls on instrumented library input streams, including calls returning zero bytes.</summary>
    public long ReadOperations { get; }
    /// <summary>Bytes returned by instrumented library input streams, including repeated probes and memory-backed streams. This is not input size or physical disk I/O.</summary>
    public long StreamBytesRead { get; }
    /// <summary>Bytes appended to SHA-256 across this inspection and nested inspections.</summary>
    public long HashBytes { get; }
    /// <summary>Entries accepted for analysis by archive budgets, including nested inspections. Directory preflight headers are not included.</summary>
    public long ArchiveEntriesVisited { get; }
    /// <summary>Expanded payload bytes returned by archive-budget streams. They may also contribute to StreamBytesRead for TAR inputs.</summary>
    public long ArchivePayloadBytesRead { get; }
    /// <summary>Distinct archive limit codes reached per budget instance. Malformed archive codes are not limits.</summary>
    public long ArchiveLimitHits { get; }
    /// <summary>Actual calls to the learned classifier. Waiting for a serialized provider is not an attempt.</summary>
    public long ClassifierAttempts { get; }
    /// <summary>Classifier calls that threw or returned an unusable prediction.</summary>
    public long ClassifierFailures { get; }
    /// <summary>Measured stage calls. Durations include nested work and can overlap; do not sum them as total elapsed time.</summary>
    public IReadOnlyList<InspectionStageMetric> Stages { get; }

    internal InspectionMetrics(TimeSpan elapsed, long[] counts, InspectionStageMetric[] stages)
    {
        Elapsed = elapsed;
        ReadOperations = counts[0]; StreamBytesRead = counts[1]; HashBytes = counts[2];
        ArchiveEntriesVisited = counts[3]; ArchivePayloadBytesRead = counts[4]; ArchiveLimitHits = counts[5];
        ClassifierAttempts = counts[6]; ClassifierFailures = counts[7];
        Stages = Array.AsReadOnly(stages);
    }
}

/// <summary>Immutable inclusive duration and invocation count for a measured stage.</summary>
public sealed class InspectionStageMetric
{
    /// <summary>The measured boundary.</summary>
    public InspectionStage Stage { get; }
    /// <summary>Number of measured invocations.</summary>
    public long Invocations { get; }
    /// <summary>Sum of inclusive invocation durations, measured with a monotonic clock.</summary>
    public TimeSpan Elapsed { get; }

    internal InspectionStageMetric(InspectionStage stage, long invocations, TimeSpan elapsed)
    { Stage = stage; Invocations = invocations; Elapsed = elapsed; }
}
