namespace FileInspectorX;

/// <summary>
/// A learned classifier prediction. Probability is deliberately separate from
/// <see cref="ContentTypeDetectionResult.Score"/>, which ranks deterministic heuristics.
/// </summary>
public sealed class LearnedContentPrediction
{
    /// <summary>Stable provider name, for example <c>Magika</c>.</summary>
    public string Provider { get; set; } = string.Empty;

    /// <summary>Stable model identifier including its upstream version.</summary>
    public string ModelId { get; set; } = string.Empty;

    /// <summary>Raw label selected by the model before thresholds or overwrite rules.</summary>
    public string RawLabel { get; set; } = string.Empty;

    /// <summary>Final label after provider thresholds and overwrite rules.</summary>
    public string OutputLabel { get; set; } = string.Empty;

    /// <summary>Canonical extension without a leading dot, when the label has one.</summary>
    public string? Extension { get; set; }

    /// <summary>MIME type associated with the final output label.</summary>
    public string? MimeType { get; set; }

    /// <summary>Model probability for <see cref="RawLabel"/>, in the inclusive range 0 through 1.</summary>
    public double Probability { get; set; }

    /// <summary>Threshold used by the selected prediction mode.</summary>
    public double Threshold { get; set; }

    /// <summary>True when the raw prediction met the selected threshold.</summary>
    public bool ThresholdMet { get; set; }

    /// <summary>Provider-specific prediction mode, for example <c>HighConfidence</c>.</summary>
    public string PredictionMode { get; set; } = string.Empty;

    /// <summary>Why the final label differs from the raw model label, when applicable.</summary>
    public string? OverwriteReason { get; set; }

    /// <summary>True when the final label describes text content.</summary>
    public bool IsText { get; set; }
}
