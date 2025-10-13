namespace FileInspectorX;

/// <summary>
/// Summary of code signing presence/metadata (best-effort, no full chain validation).
/// </summary>
public sealed class SignatureSummary {
    /// <summary>True when a signature blob (certificate table) is present.</summary>
    public bool IsSigned { get; set; }
    /// <summary>Size in bytes of the PE certificate table entry.</summary>
    public int CertificateTableSize { get; set; }
    /// <summary>SHA-256 hash of the raw certificate blob (when captured).</summary>
    public string? CertificateBlobSha256 { get; set; }
}
