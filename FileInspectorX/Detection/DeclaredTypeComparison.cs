namespace FileInspectorX;

/// <summary>
/// Detailed comparison between a declared extension and detected content type.
/// </summary>
public sealed class DeclaredTypeComparison
{
    /// <summary>Declared extension (normalized, without leading dot).</summary>
    public string? DeclaredExtension { get; set; }
    /// <summary>Detected primary extension (normalized).</summary>
    public string? DetectedExtension { get; set; }
    /// <summary>Detected guessed extension (normalized), when available.</summary>
    public string? DetectedGuessedExtension { get; set; }
    /// <summary>Detected MIME type, when available.</summary>
    public string? DetectedMimeType { get; set; }
    /// <summary>Detected confidence, when available.</summary>
    public string? DetectedConfidence { get; set; }
    /// <summary>Detected reason, when available.</summary>
    public string? DetectedReason { get; set; }
    /// <summary>True when declared and detected types mismatch.</summary>
    public bool Mismatch { get; set; }
    /// <summary>Comparison reason string.</summary>
    public string Reason { get; set; } = string.Empty;
    /// <summary>True when declared extension matches a strong alternative.</summary>
    public bool DeclaredMatchesAlternative { get; set; }
    /// <summary>Strong alternative candidates (score/Confidence high).</summary>
    public IReadOnlyList<ContentTypeDetectionCandidate>? StrongAlternatives { get; set; }
    /// <summary>Dangerous alternative extensions detected with strong confidence.</summary>
    public IReadOnlyList<string>? StrongDangerousAlternativeExtensions { get; set; }
    /// <summary>True when the declared extension is considered dangerous.</summary>
    public bool IsDeclaredDangerous { get; set; }
    /// <summary>True when the detected content or strong alternatives are dangerous.</summary>
    public bool IsDetectedDangerous { get; set; }
}
