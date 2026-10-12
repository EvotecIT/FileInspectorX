namespace FileInspectorX;

public sealed partial class ReportView
{
    /// <summary>Whole-input SHA-256 when requested and available.</summary>
    public string? Sha256Hex { get; set; }

    /// <summary>Requested input header bytes as hexadecimal. This can expose sensitive content.</summary>
    public string? MagicHeaderHex { get; set; }

    /// <summary>Learned-provider prediction, arbitration and failure evidence when enabled.</summary>
    public LearnedClassificationEvidence? LearnedClassification { get; set; }

    /// <summary>Typed structural validation outcome; recognition alone does not establish validity.</summary>
    public StructuredValidationOutcome StructuredValidation { get; set; }

    private void CaptureDetectionEvidence(ContentTypeDetectionResult detection)
    {
        Sha256Hex = detection.Sha256Hex;
        MagicHeaderHex = detection.MagicHeaderHex;
        LearnedClassification = detection.LearnedClassification;
        StructuredValidation = detection.StructuredValidation;
    }

    private void AddDetectionEvidence(IDictionary<string, object?> fields)
    {
        if (!string.IsNullOrEmpty(Sha256Hex)) fields[nameof(Sha256Hex)] = Sha256Hex;
        if (!string.IsNullOrEmpty(MagicHeaderHex)) fields[nameof(MagicHeaderHex)] = MagicHeaderHex;
        if (LearnedClassification != null) fields[nameof(LearnedClassification)] = LearnedClassification;
        fields[nameof(StructuredValidation)] = StructuredValidation;
    }
}
