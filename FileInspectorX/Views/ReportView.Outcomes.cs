namespace FileInspectorX;

public sealed partial class ReportView
{
    /// <summary>Typed input recognition/readability status.</summary>
    public InspectionInputStatus InputStatus { get; set; }
    /// <summary>Typed inspection completion.</summary>
    public InspectionOutcome Outcome { get; set; }
    /// <summary>Immutable completion evidence for the recorded inspection stages.</summary>
    public IReadOnlyList<InspectionStageResult> StageOutcomes { get; set; } = Array.Empty<InspectionStageResult>();
    /// <summary>Opt-in immutable per-operation measurements.</summary>
    public InspectionMetrics? Metrics { get; set; }
}
