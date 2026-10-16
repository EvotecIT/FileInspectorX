namespace FileInspectorX;

/// <summary>The declared basis of primary text. Compatibility also requires the complete extraction descriptor.</summary>
public enum ReportTextBasis
{
    /// <summary>No extraction provenance was recorded.</summary>
    Unknown,
    /// <summary>The reader intentionally emits no primary text.</summary>
    None,
    /// <summary>Text decoded by the built-in plain-text profile.</summary>
    BuiltinPlainText,
    /// <summary>Canonical logical document text from a declared reader profile.</summary>
    CanonicalDocumentText
}

/// <summary>Reader and settings that determine the meaning of retained primary text.</summary>
public sealed class ReportExtractionDescriptor
{
    /// <summary>Stable reader identifier.</summary>
    public string ReaderId { get; set; } = string.Empty;
    /// <summary>Reader implementation version.</summary>
    public string ReaderVersion { get; set; } = string.Empty;
    /// <summary>Stable profile identifier, including its compatibility version.</summary>
    public string ProfileId { get; set; } = string.Empty;
    /// <summary>Declared primary-text basis. Unknown never implies comparability.</summary>
    public ReportTextBasis TextBasis { get; set; }
    /// <summary>All settings that can change primary text; credentials must never be included.</summary>
    public IReadOnlyDictionary<string, string> Settings { get; set; } = new Dictionary<string, string>();
}
