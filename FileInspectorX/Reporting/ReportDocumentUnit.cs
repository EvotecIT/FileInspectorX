namespace FileInspectorX;

/// <summary>A logical document unit or occurrence, including failed or duplicate page requests.</summary>
public sealed class ReportDocumentUnit
{
    /// <summary>Reader-scoped identity for this occurrence.</summary>
    public string Id { get; set; } = string.Empty;
    /// <summary>Reader-qualified unit kind, such as page, sheet, slide or story.</summary>
    public string Kind { get; set; } = string.Empty;
    /// <summary>Zero-based occurrence ordinal.</summary>
    public int Ordinal { get; set; }
    /// <summary>Logical location in the document.</summary>
    public ReportLogicalLocation? Location { get; set; }
    /// <summary>Completion of this particular occurrence.</summary>
    public InspectionStageStatus Status { get; set; } = InspectionStageStatus.NotApplicable;
    /// <summary>Zero-based character start in retained Content.Text; null when no span is retained.</summary>
    public int? TextStart { get; set; }
    /// <summary>Retained character length, adjusted when primary text is truncated.</summary>
    public int? TextLength { get; set; }
}

/// <summary>Logical document coordinates. Character and line coordinates never imply snapshot byte offsets.</summary>
public sealed class ReportLogicalLocation
{
    /// <summary>Container-relative document part identity.</summary>
    public string? Part { get; set; }
    /// <summary>Document story, such as body, header or notes.</summary>
    public string? Story { get; set; }
    /// <summary>Source worksheet name or identity.</summary>
    public string? Sheet { get; set; }
    /// <summary>Source cell or cell range in A1 notation.</summary>
    public string? A1Range { get; set; }
    /// <summary>Reader-provided stable block anchor.</summary>
    public string? BlockAnchor { get; set; }
    /// <summary>Native source block kind.</summary>
    public string? SourceBlockKind { get; set; }
    /// <summary>Reader-provided heading path.</summary>
    public string? HeadingPath { get; set; }
    /// <summary>Heading path that preserves source hierarchy.</summary>
    public string? HierarchyHeadingPath { get; set; }
    /// <summary>Reader-provided heading slug.</summary>
    public string? HeadingSlug { get; set; }
    /// <summary>Reader-defined logical order.</summary>
    public int? LogicalOrder { get; set; }
    /// <summary>Projected block index.</summary>
    public int? BlockIndex { get; set; }
    /// <summary>Native source block index.</summary>
    public int? SourceBlockIndex { get; set; }
    /// <summary>First source line, using the reader's declared coordinate convention.</summary>
    public int? StartLine { get; set; }
    /// <summary>Last source line.</summary>
    public int? EndLine { get; set; }
    /// <summary>First line after reader normalization.</summary>
    public int? NormalizedStartLine { get; set; }
    /// <summary>Last line after reader normalization.</summary>
    public int? NormalizedEndLine { get; set; }
    /// <summary>Source page number.</summary>
    public int? Page { get; set; }
    /// <summary>Source slide number.</summary>
    public int? Slide { get; set; }
    /// <summary>Reader-defined table index.</summary>
    public int? TableIndex { get; set; }
    /// <summary>Character offset in the reader's source text, never a byte offset.</summary>
    public long? SourceCharacterOffset { get; set; }
    /// <summary>Character length in the reader's source text.</summary>
    public long? SourceCharacterLength { get; set; }
}
