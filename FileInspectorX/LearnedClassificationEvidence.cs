namespace FileInspectorX;

/// <summary>
/// Preserves learned evidence and the deterministic detection that was in effect before arbitration.
/// </summary>
public sealed class LearnedClassificationEvidence
{
    /// <summary>How the learned prediction affected the effective detection.</summary>
    public LearnedClassificationDisposition Disposition { get; set; }

    /// <summary>The provider prediction, or null when the provider failed.</summary>
    public LearnedContentPrediction? Prediction { get; set; }

    /// <summary>Deterministic extension before learned arbitration.</summary>
    public string? DeterministicExtension { get; set; }

    /// <summary>Deterministic MIME type before learned arbitration.</summary>
    public string? DeterministicMimeType { get; set; }

    /// <summary>Deterministic confidence before learned arbitration.</summary>
    public string? DeterministicConfidence { get; set; }

    /// <summary>Deterministic reason before learned arbitration.</summary>
    public string? DeterministicReason { get; set; }

    /// <summary>
    /// Deterministic extension that agreed with the learned prediction. This can be the primary
    /// extension, a refined subtype, or a strong alternative.
    /// </summary>
    public string? DeterministicAgreementExtension { get; set; }

    /// <summary>Stable diagnostic message for a conflict or provider failure.</summary>
    public string? Message { get; set; }
}
