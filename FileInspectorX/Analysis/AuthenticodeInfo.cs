namespace FileInspectorX;

/// <summary>
/// Summary of Authenticode signer and optional timestamp.
/// </summary>
public sealed class AuthenticodeInfo
{
    /// <summary>True when an Authenticode signature is present in the file.</summary>
    public bool Present { get; set; }
    /// <summary>True when the PKCS#7 envelope validates (best‑effort, cross‑platform).</summary>
    public bool? EnvelopeSignatureValid { get; set; }
    /// <summary>True when certificate chain builds to a trusted root (when validation is attempted).</summary>
    public bool? ChainValid { get; set; }

    /// <summary>Friendly name of the digest algorithm used for the PKCS#7 signature (e.g., SHA256).</summary>
    public string? DigestAlgorithm { get; set; }
    /// <summary>OID of the file content digest algorithm as recorded in the Authenticode content (SpcIndirectDataContent).</summary>
    public string? FileDigestAlgorithmOid { get; set; }
    /// <summary>Friendly name of the file content digest algorithm (e.g., SHA256).</summary>
    public string? FileDigestAlgorithm { get; set; }

    /// <summary>Subject DN of the signer certificate.</summary>
    public string? SignerSubject { get; set; }
    /// <summary>Issuer DN of the signer certificate.</summary>
    public string? SignerIssuer { get; set; }
    /// <summary>Common Name (CN) component of the signer subject, when available.</summary>
    public string? SignerSubjectCN { get; set; }
    /// <summary>Organization (O) component of the signer subject, when available.</summary>
    public string? SignerSubjectO { get; set; }
    /// <summary>Common Name (CN) component of the issuer, when available.</summary>
    public string? IssuerCN { get; set; }
    /// <summary>Organization (O) component of the issuer, when available.</summary>
    public string? IssuerO { get; set; }
    /// <summary>True when the certificate is self‑signed.</summary>
    public bool? IsSelfSigned { get; set; }
    /// <summary>Thumbprint of the signer certificate.</summary>
    public string? SignerThumbprint { get; set; }
    /// <summary>Serial number of the signer certificate (hex).</summary>
    public string? SignerSerialHex { get; set; }
    /// <summary>Signature algorithm used in the signer certificate.</summary>
    public string? SignatureAlgorithm { get; set; }
    /// <summary>Start of signer certificate validity period.</summary>
    public DateTimeOffset? NotBefore { get; set; }
    /// <summary>End of signer certificate validity period.</summary>
    public DateTimeOffset? NotAfter { get; set; }

    /// <summary>True when a timestamp countersignature is present.</summary>
    public bool? TimestampPresent { get; set; }
    /// <summary>Time reported by the timestamp authority, when present.</summary>
    public DateTimeOffset? TimestampTime { get; set; }
    /// <summary>Distinguished name or URL of the timestamp authority.</summary>
    public string? TimestampAuthority { get; set; }

    /// <summary>
    /// Note about what was verified; cross‑platform builds only verify the PKCS#7 envelope and chain, not the file re-hash.
    /// </summary>
    public string? VerificationNote { get; set; }

    /// <summary>Windows WinVerifyTrust overall policy result (true == trusted) when available.</summary>
    public bool? IsTrustedWindowsPolicy { get; set; }
    /// <summary>Raw WinVerifyTrust status code when available (0 == TRUST_E_SUCCESS).</summary>
    public int? WinTrustStatusCode { get; set; }
    /// <summary>True when the recomputed PE image digest matches the Authenticode digest.</summary>
    public bool? FileHashMatches { get; set; }
}
