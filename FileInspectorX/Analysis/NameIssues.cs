namespace FileInspectorX;

/// <summary>
/// Flags describing suspicious traits of a file name/path (generic; library-agnostic).
/// </summary>
[System.Flags]
public enum NameIssues
{
    /// <summary>No issues recognized.</summary>
    None = 0,
    /// <summary>File has a double extension like ".pdf.exe".</summary>
    DoubleExtension = 1 << 0,
    /// <summary>File name contains bi-directional override/control characters.</summary>
    BiDiOverride = 1 << 1,
    /// <summary>File name contains suspicious/unusual whitespace (leading/trailing or multiple spaces).</summary>
    SuspiciousWhitespace = 1 << 2,
    /// <summary>File is hidden by a leading dot (Unix-like). </summary>
    LeadingDotHidden = 1 << 3,
    /// <summary>Declared extension does not match detected extension.</summary>
    ExtensionMismatch = 1 << 4,
}
