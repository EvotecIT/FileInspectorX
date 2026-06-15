namespace FileInspectorX;

/// <summary>
/// Best-effort source evidence for a heuristic finding.
/// Evidence is bounded and intended for operator review, not for reconstructing file content.
/// </summary>
public sealed class FindingEvidence
{
    /// <summary>Stable finding code this evidence explains.</summary>
    public string Code { get; set; } = string.Empty;

    /// <summary>One-based source line number when the finding came from text content.</summary>
    public int? Line { get; set; }

    /// <summary>Short, redacted snippet from the source line that triggered the finding.</summary>
    public string? Snippet { get; set; }

    /// <summary>Optional source tag describing where the evidence came from.</summary>
    public string? SourceTag { get; set; }

    /// <summary>Number of matched source occurrences observed within the bounded scan window.</summary>
    public int? HitCount { get; set; }

    /// <summary>Up to a few one-based source line numbers that explain repeated behavior.</summary>
    public IReadOnlyList<int>? Lines { get; set; }

    /// <summary>Up to a few short, redacted snippets that explain repeated behavior.</summary>
    public IReadOnlyList<string>? Snippets { get; set; }

    /// <summary>Behavior classes such as Persistence, DefenseEvasion, CredentialAccess, Destructive, or NetworkStaging.</summary>
    public IReadOnlyList<string>? BehaviorTags { get; set; }
}
