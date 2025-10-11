namespace FileInspectorX;

/// <summary>
/// Summary of code signing presence/metadata (best-effort, no full chain validation).
/// </summary>
public sealed class SignatureSummary {
    public bool IsSigned { get; set; }
    public int CertificateTableSize { get; set; }
    public string? CertificateBlobSha256 { get; set; }
}

