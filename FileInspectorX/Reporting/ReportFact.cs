namespace FileInspectorX;

/// <summary>The representation of a canonical invariant-culture scalar in a report.</summary>
public enum ReportFactKind { Text, Integer, Decimal, Boolean, Timestamp, Uri, Sha256 }

/// <summary>How a report fact was obtained. Embedded values remain file claims.</summary>
public enum ReportFactOrigin { Embedded, Derived, Default, Inferred }

/// <summary>A bounded scalar fact with the source necessary to inspect or explain it.</summary>
public sealed class ReportFact
{
    /// <summary>Stable format-qualified field name.</summary>
    public string Name { get; set; } = string.Empty;
    /// <summary>Canonical scalar representation.</summary>
    public ReportFactKind Kind { get; set; }
    /// <summary>Invariant scalar text; a typed representation does not establish authenticity.</summary>
    public string Value { get; set; } = string.Empty;
    /// <summary>Embedded source value or derivation category.</summary>
    public ReportFactOrigin Origin { get; set; }
    /// <summary>Optional source location, never a host filesystem path.</summary>
    public ReportSourceLocation? Source { get; set; }
    /// <summary>Logical document location, independent of physical byte offsets.</summary>
    public ReportLogicalLocation? LogicalSource { get; set; }
    /// <summary>Reader-qualified scalar annotations. Embedded annotations remain source claims.</summary>
    public IReadOnlyDictionary<string, string> Attributes { get; set; } = new Dictionary<string, string>();
    /// <summary>True when a text value is a budget-limited prefix. Numeric values are omitted rather than shortened.</summary>
    public bool Truncated { get; set; }
}

/// <summary>A native container, part or byte location in the exact analyzed input.</summary>
public sealed class ReportSourceLocation
{
    /// <summary>Container-relative identity, such as a package part or media track.</summary>
    public string? Part { get; set; }
    /// <summary>Optional source record ordinal or identifier.</summary>
    public string? Record { get; set; }
    /// <summary>Coordinate space of byte offsets. Unknown when the reader did not declare it.</summary>
    public ReportByteSpace ByteSpace { get; set; }
    /// <summary>Zero-based physical byte offset when meaningful for this reader.</summary>
    public long? ByteOffset { get; set; }
    /// <summary>Source byte length, distinct from output character length.</summary>
    public long? ByteLength { get; set; }
}

/// <summary>Exact hash of one complete bounded binary region, with omissions kept visible.</summary>
public sealed class ReportRegion
{
    /// <summary>Source name or ordinal, retained as data.</summary>
    public string Name { get; set; } = string.Empty;
    /// <summary>Comparison basis, such as pe-section or fixed-block.</summary>
    public string Kind { get; set; } = string.Empty;
    /// <summary>Physical offset in the snapshot.</summary>
    public long ByteOffset { get; set; }
    /// <summary>Whole declared region length.</summary>
    public long ByteLength { get; set; }
    /// <summary>Bytes actually hashed. Partial regions never receive a whole-region hash.</summary>
    public long HashBytes { get; set; }
    /// <summary>Whole-region SHA-256, or null for skipped/invalid regions.</summary>
    public string? Sha256 { get; set; }
    /// <summary>Completion of this particular region.</summary>
    public InspectionStageStatus Status { get; set; }
    /// <summary>Stable omission or invalid-range codes.</summary>
    public IReadOnlyList<string> Issues { get; set; } = Array.Empty<string>();
}
