namespace FileInspectorX;

/// <summary>
/// Flattened Authenticode signature view for display.
/// </summary>
/// <summary>Flattened Authenticode signature view for display.</summary>
public sealed class SignatureView
{
    /// <summary>File path.</summary>
    public string Path { get; set; } = string.Empty;
    /// <summary>True if an Authenticode signature is present.</summary>
    public bool Present { get; set; }
    /// <summary>True if PKCS#7 envelope validates.</summary>
    public bool? EnvelopeSignatureValid { get; set; }
    /// <summary>True if chain builds successfully.</summary>
    public bool? ChainValid { get; set; }
    /// <summary>True if countersignature/time-stamp is present.</summary>
    public bool? TimestampPresent { get; set; }
    /// <summary>Time-stamp time (when present).</summary>
    public DateTimeOffset? TimestampTime { get; set; }

    /// <summary>Signer subject name.</summary>
    public string? SignerSubject { get; set; }
    /// <summary>Signer issuer name.</summary>
    public string? SignerIssuer { get; set; }
    public string? SignerSubjectCN { get; set; }
    public string? SignerSubjectO { get; set; }
    public string? IssuerCN { get; set; }
    public string? IssuerO { get; set; }
    public bool? IsSelfSigned { get; set; }
    /// <summary>Signer certificate thumbprint.</summary>
    public string? SignerThumbprint { get; set; }
    /// <summary>Signer certificate signature algorithm.</summary>
    public string? SignatureAlgorithm { get; set; }
    /// <summary>Signer digest algorithm.</summary>
    public string? DigestAlgorithm { get; set; }
    /// <summary>Signer cert validity start.</summary>
    public DateTimeOffset? NotBefore { get; set; }
    /// <summary>Signer cert validity end.</summary>
    public DateTimeOffset? NotAfter { get; set; }
    /// <summary>The full analysis object for deep inspection.</summary>
    public FileAnalysis? Raw { get; set; }

    public static SignatureView From(string path, AuthenticodeInfo? a) => new SignatureView {
        Path = path,
        Present = a?.Present ?? false,
        EnvelopeSignatureValid = a?.EnvelopeSignatureValid,
        ChainValid = a?.ChainValid,
        TimestampPresent = a?.TimestampPresent,
        TimestampTime = a?.TimestampTime,
        SignerSubject = a?.SignerSubject,
        SignerIssuer = a?.SignerIssuer,
        SignerSubjectCN = a?.SignerSubjectCN,
        SignerSubjectO = a?.SignerSubjectO,
        IssuerCN = a?.IssuerCN,
        IssuerO = a?.IssuerO,
        IsSelfSigned = a?.IsSelfSigned,
        SignerThumbprint = a?.SignerThumbprint,
        SignatureAlgorithm = a?.SignatureAlgorithm,
        DigestAlgorithm = a?.DigestAlgorithm,
        NotBefore = a?.NotBefore,
        NotAfter = a?.NotAfter,
        Raw = null
    };
}
