namespace FileInspectorX;

/// <summary>Severity of a reader diagnostic, independent of recovery.</summary>
public enum ReportDiagnosticSeverity
{
    /// <summary>Informational evidence.</summary>
    Info,
    /// <summary>A limitation or questionable source condition.</summary>
    Warning,
    /// <summary>A failed reader operation.</summary>
    Error
}

/// <summary>Recovery actually performed for a diagnostic.</summary>
public enum ReportRecoveryKind
{
    /// <summary>No recovery was performed.</summary>
    None,
    /// <summary>Source structure was repaired.</summary>
    Repaired,
    /// <summary>The affected source item was skipped.</summary>
    Skipped,
    /// <summary>A partial logical projection was retained.</summary>
    PartialProjection
}

/// <summary>Coordinate space for physical source-byte evidence.</summary>
public enum ReportByteSpace
{
    /// <summary>The reader did not establish the byte coordinate space.</summary>
    Unknown,
    /// <summary>Offsets refer to the original immutable snapshot.</summary>
    SnapshotBytes,
    /// <summary>Offsets refer to an identified decoded package part.</summary>
    PartBytes,
    /// <summary>Offsets refer to bytes supplied by a declared native profile.</summary>
    ProfileBytes
}

/// <summary>Structured reader evidence that must not become primary text.</summary>
public sealed class ReportDiagnostic
{
    /// <summary>Severity of the source condition.</summary>
    public ReportDiagnosticSeverity Severity { get; set; }
    /// <summary>Reader-qualified diagnostic category.</summary>
    public string Category { get; set; } = string.Empty;
    /// <summary>Stable native or mapped diagnostic code.</summary>
    public string Code { get; set; } = string.Empty;
    /// <summary>Bounded diagnostic explanation.</summary>
    public string Message { get; set; } = string.Empty;
    /// <summary>Physical source coordinates when established.</summary>
    public ReportSourceLocation? Source { get; set; }
    /// <summary>Logical document coordinates when available.</summary>
    public ReportLogicalLocation? LogicalSource { get; set; }
    /// <summary>Whether the condition permits recovery, independently of whether it occurred.</summary>
    public bool IsRecoverable { get; set; }
    /// <summary>Recovery actually performed.</summary>
    public ReportRecoveryKind Recovery { get; set; }
    /// <summary>Reader-qualified scalar diagnostic details.</summary>
    public IReadOnlyDictionary<string, string> Attributes { get; set; } = new Dictionary<string, string>();
}

/// <summary>A bounded omission from a reader's projection or inventory.</summary>
public sealed class ReportContentOmission
{
    /// <summary>Stable omission reason.</summary>
    public string Code { get; set; } = string.Empty;
    /// <summary>Reader-qualified affected scope.</summary>
    public string Scope { get; set; } = string.Empty;
    /// <summary>Number omitted when known; null preserves an unknown count.</summary>
    public long? Count { get; set; }
    /// <summary>Affected logical source location.</summary>
    public ReportLogicalLocation? LogicalSource { get; set; }
}
