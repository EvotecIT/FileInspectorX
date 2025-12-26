namespace FileInspectorX;

/// <summary>
/// Flattened, display-friendly detection view to avoid wide, mostly-null tables.
/// </summary>
public sealed class DetectionView
{
    /// <summary>File path.</summary>
    public string Path { get; set; } = string.Empty;
    /// <summary>Detected extension.</summary>
    public string Extension { get; set; } = string.Empty;
    /// <summary>Detected MIME type.</summary>
    public string MimeType { get; set; } = string.Empty;
    /// <summary>Confidence level.</summary>
    public string Confidence { get; set; } = string.Empty;
    /// <summary>Short reason for detection.</summary>
    public string Reason { get; set; } = string.Empty;
    /// <summary>Detailed reason (heuristic/signal).</summary>
    public string? ReasonDetails { get; set; }
    /// <summary>Total bytes inspected from the header.</summary>
    public int BytesInspected { get; set; }
    /// <summary>Best-guess extension when ambiguous.</summary>
    public string? GuessedExtension { get; set; }
    /// <summary>Score (0-100) used to rank candidates.</summary>
    public int? Score { get; set; }
    /// <summary>True when the detected type is commonly considered risky/dangerous.</summary>
    public bool IsDangerous { get; set; }
    /// <summary>Alternative candidates when multiple formats are plausible.</summary>
    public IReadOnlyList<ContentTypeDetectionCandidate>? Alternatives { get; set; }
    /// <summary>Ranked candidates including the primary, when available.</summary>
    public IReadOnlyList<ContentTypeDetectionCandidate>? Candidates { get; set; }
    /// <summary>Optional SHA-256 hash (when requested).</summary>
    public string? Sha256Hex { get; set; }
    /// <summary>Optional magic header bytes as hex (when requested).</summary>
    public string? MagicHeaderHex { get; set; }
    /// <summary>The full analysis object for deep inspection.</summary>
    public FileAnalysis? Raw { get; set; }

    /// <summary>
    /// Creates a <see cref="DetectionView"/> from a <see cref="ContentTypeDetectionResult"/>.
    /// </summary>
    public static DetectionView From(string path, ContentTypeDetectionResult r) => new DetectionView {
        Path = path,
        Extension = r.Extension,
        MimeType = r.MimeType,
        Confidence = r.Confidence,
        Reason = r.Reason,
        ReasonDetails = r.ReasonDetails,
        BytesInspected = r.BytesInspected,
        GuessedExtension = r.GuessedExtension,
        Score = r.Score,
        IsDangerous = r.IsDangerous,
        Alternatives = r.Alternatives,
        Candidates = r.Candidates,
        Sha256Hex = r.Sha256Hex,
        MagicHeaderHex = r.MagicHeaderHex,
        Raw = null
    };
}
