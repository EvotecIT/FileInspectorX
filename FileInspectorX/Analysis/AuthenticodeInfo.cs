namespace FileInspectorX;

/// <summary>
/// Summary of Authenticode signer and optional timestamp.
/// </summary>
public sealed class AuthenticodeInfo
{
    public bool Present { get; set; }
    public bool? EnvelopeSignatureValid { get; set; }
    public bool? ChainValid { get; set; }

    public string? DigestAlgorithm { get; set; }
    /// <summary>OID of the file content digest algorithm as recorded in the Authenticode content (SpcIndirectDataContent).</summary>
    public string? FileDigestAlgorithmOid { get; set; }
    /// <summary>Friendly name of the file content digest algorithm (e.g., SHA256).</summary>
    public string? FileDigestAlgorithm { get; set; }

    public string? SignerSubject { get; set; }
    public string? SignerIssuer { get; set; }
    public string? SignerSubjectCN { get; set; }
    public string? SignerSubjectO { get; set; }
    public string? IssuerCN { get; set; }
    public string? IssuerO { get; set; }
    public bool? IsSelfSigned { get; set; }
    public string? SignerThumbprint { get; set; }
    public string? SignerSerialHex { get; set; }
    public string? SignatureAlgorithm { get; set; }
    public DateTimeOffset? NotBefore { get; set; }
    public DateTimeOffset? NotAfter { get; set; }

    public bool? TimestampPresent { get; set; }
    public DateTimeOffset? TimestampTime { get; set; }
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
