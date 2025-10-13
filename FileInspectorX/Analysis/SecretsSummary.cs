namespace FileInspectorX;

/// <summary>
/// Counts of generic secret indicators found during lightweight scans (privacy-safe: categories only, never values).
/// </summary>
public sealed class SecretsSummary
{
    /// <summary>Number of private key headers detected (e.g., PEM RSA/DSA/OpenSSH).</summary>
    public int PrivateKeyCount { get; set; }
    /// <summary>Number of JWT-like three-part base64url tokens detected.</summary>
    public int JwtLikeCount { get; set; }
    /// <summary>Number of generic key= / secret= long-token patterns detected.</summary>
    public int KeyPatternCount { get; set; }
}

