namespace FileInspectorX;

/// <summary>Whether readable input was recognized. Recognition does not imply structural validity.</summary>
public enum InspectionInputStatus
{
    /// <summary>The input was readable, but its content type was not recognized.</summary>
    Unrecognized,
    /// <summary>A content type was recognized.</summary>
    Recognized,
    /// <summary>The input could not be read.</summary>
    Unreadable
}

/// <summary>Completion of the requested inspection boundaries.</summary>
public enum InspectionOutcome
{
    /// <summary>The requested boundaries completed, including any negative validation result.</summary>
    Complete,
    /// <summary>At least one requested boundary failed, was unavailable, or stopped at a safety limit.</summary>
    Partial,
    /// <summary>The input could not be read. No content-based decision is available.</summary>
    InputUnavailable
}

/// <summary>Typed counterpart of the compatibility validation-status string.</summary>
public enum StructuredValidationOutcome
{
    /// <summary>No structured validation result was recorded.</summary>
    NotAttempted,
    /// <summary>Validation passed.</summary>
    Passed,
    /// <summary>Validation rejected the content.</summary>
    Failed,
    /// <summary>Validation was skipped or incomplete within its configured read budget.</summary>
    Skipped,
    /// <summary>Validation exceeded its time budget.</summary>
    TimedOut
}

/// <summary>Observable inspection boundaries. Format-specific best-effort enrichers are not separate stages.</summary>
public enum InspectionStage
{
    /// <summary>Content-type detection, including its requested enrichment.</summary>
    Detection,
    /// <summary>Structured text validation, when applicable.</summary>
    StructuredValidation,
    /// <summary>Whole-input SHA-256 computation.</summary>
    Sha256,
    /// <summary>Optional learned classification.</summary>
    LearnedClassification,
    /// <summary>Supported ZIP/OOXML and TAR container inspection.</summary>
    Container,
    /// <summary>Risk assessment and assessment profiles.</summary>
    Assessment
}

/// <summary>Completion of one inspection boundary.</summary>
public enum InspectionStageStatus
{
    /// <summary>The caller did not request this stage.</summary>
    NotRequested,
    /// <summary>This stage does not apply to the detected format.</summary>
    NotApplicable,
    /// <summary>The stage completed. Validation may still reject the content.</summary>
    Completed,
    /// <summary>The stage stopped at a configured safety limit or could only inspect part of the content.</summary>
    Partial,
    /// <summary>The requested stage could not run with the available input or execution mode.</summary>
    Unavailable,
    /// <summary>The stage failed to execute successfully.</summary>
    Failed
}

/// <summary>Immutable completion evidence for one stage, with stable issue codes.</summary>
public sealed class InspectionStageResult
{
    /// <summary>The inspected boundary.</summary>
    public InspectionStage Stage { get; }
    /// <summary>Completion status.</summary>
    public InspectionStageStatus Status { get; }
    /// <summary>Stable issue codes, without input paths or provider exception text.</summary>
    public IReadOnlyList<string> Issues { get; }

    internal InspectionStageResult(InspectionStage stage, InspectionStageStatus status, params string[] issues)
    {
        Stage = stage;
        Status = status;
        Issues = Array.AsReadOnly((string[])issues.Clone());
    }
}
