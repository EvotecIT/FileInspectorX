#if NET8_0_OR_GREATER
using System.Text.Json.Serialization;

namespace FileInspectorX;

// Preserve immutable evidence when a saved report is read using the inbox .NET 8 JSON serializer.
// Older targets retain their serializer-neutral API without introducing a JSON package dependency.
public sealed partial class InspectionStageResult
{
    [JsonConstructor]
    private InspectionStageResult(InspectionStage stage, InspectionStageStatus status, IReadOnlyList<string> issues)
        : this(stage, status, issues?.ToArray() ?? Array.Empty<string>()) { }
}

public sealed partial class InspectionMetrics
{
    [JsonConstructor]
    private InspectionMetrics(TimeSpan elapsed, long readOperations, long streamBytesRead, long hashBytes,
        long archiveEntriesVisited, long archivePayloadBytesRead, long archiveLimitHits,
        long classifierAttempts, long classifierFailures, IReadOnlyList<InspectionStageMetric> stages)
        : this(elapsed, new[] { readOperations, streamBytesRead, hashBytes, archiveEntriesVisited,
            archivePayloadBytesRead, archiveLimitHits, classifierAttempts, classifierFailures },
            stages?.ToArray() ?? Array.Empty<InspectionStageMetric>()) { }
}
#endif
