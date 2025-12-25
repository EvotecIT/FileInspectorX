namespace FileInspectorX;

/// <summary>
/// Secondary content type candidate for ambiguous or multi-signal detections.
/// </summary>
public sealed class ContentTypeDetectionCandidate
{
    /// <summary>Detected canonical extension (without leading dot), e.g., "ps1".</summary>
    public string Extension { get; set; } = string.Empty;
    /// <summary>Detected mime type, e.g., "text/x-powershell".</summary>
    public string MimeType { get; set; } = string.Empty;
    /// <summary>Confidence: High/Medium/Low.</summary>
    public string Confidence { get; set; } = string.Empty;
    /// <summary>Short reason, e.g., text:ps1, text:md.</summary>
    public string Reason { get; set; } = string.Empty;
    /// <summary>Optional detail about which exact heuristic/signature triggered the detection.</summary>
    public string? ReasonDetails { get; set; }
    /// <summary>Score (0-100) used to rank candidates; higher is stronger.</summary>
    public int Score { get; set; }
    /// <summary>True when candidate matches a commonly risky/dangerous type.</summary>
    public bool IsDangerous { get; set; }
}
