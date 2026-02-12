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
    /// <summary>Number of known token-family patterns detected (e.g., GitHub/AWS/Slack key formats).</summary>
    public int TokenFamilyCount { get; set; }
    /// <summary>Number of GitHub token-family matches.</summary>
    public int GitHubTokenCount { get; set; }
    /// <summary>Number of GitLab token-family matches.</summary>
    public int GitLabTokenCount { get; set; }
    /// <summary>Number of AWS access key id token-family matches.</summary>
    public int AwsAccessKeyIdCount { get; set; }
    /// <summary>Number of Slack token-family matches.</summary>
    public int SlackTokenCount { get; set; }
    /// <summary>Number of Stripe live/rk token-family matches.</summary>
    public int StripeLiveKeyCount { get; set; }
}
