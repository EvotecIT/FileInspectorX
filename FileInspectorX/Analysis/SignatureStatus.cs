namespace FileInspectorX;

/// <summary>
/// Lightweight summary of signature presence and validity.
/// </summary>
public sealed class SignatureStatus
{
    /// <summary>True when a signature is present.</summary>
    public bool? IsSigned { get; set; }
    /// <summary>True when the signature validates (policy or chain).</summary>
    public bool? IsValid { get; set; }
    /// <summary>Signer subject common name or full subject.</summary>
    public string? SignerSubject { get; set; }
    /// <summary>Signer certificate thumbprint.</summary>
    public string? SignerThumbprint { get; set; }
    /// <summary>Signature timestamp (UTC) when present.</summary>
    public DateTime? SigningTimeUtc { get; set; }
}
