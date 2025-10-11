namespace FileInspectorX;

/// <summary>
/// Result of content type detection using built-in FileInspector.
/// </summary>
public class ContentTypeDetectionResult {
    /// <summary>Detected canonical extension (without leading dot), e.g., "png".</summary>
    public string Extension { get; set; } = string.Empty;

    /// <summary>Detected mime type, e.g., "image/png".</summary>
    public string MimeType { get; set; } = string.Empty;

    /// <summary>Confidence: High/Medium/Low.</summary>
    public string Confidence { get; set; } = string.Empty;

    /// <summary>Short reason, e.g., magic:png, riff:webp.</summary>
    public string Reason { get; set; } = string.Empty;

    /// <summary>
    /// Optional detail about which exact heuristic/signature triggered the detection.
    /// Example values: "json:object-key-colon", "yaml:front-matter", "log:levels-3".
    /// Null or empty when not applicable.
    /// </summary>
    public string? ReasonDetails { get; set; }

    /// <summary>Optional SHA-256 of the full file (lowercase hex). Only set when requested via options.</summary>
    public string? Sha256Hex { get; set; }

    /// <summary>Optional first N bytes as hex (uppercase, no separators). Only set when requested via options.</summary>
    public string? MagicHeaderHex { get; set; }

    /// <summary>Total header bytes read for detection (not the file size).</summary>
    public int BytesInspected { get; set; }

    /// <summary>Best-guess extension when MIME/heuristic is ambiguous. Null when not applicable.</summary>
    public string? GuessedExtension { get; set; }
}
