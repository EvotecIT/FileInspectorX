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
    /// <summary>Number of GCP API key token-family matches.</summary>
    public int GcpApiKeyCount { get; set; }
    /// <summary>Number of npm token-family matches.</summary>
    public int NpmTokenCount { get; set; }
    /// <summary>Number of Azure SAS token-family matches.</summary>
    public int AzureSasTokenCount { get; set; }
    /// <summary>
    /// Redacted secret finding details with confidence/line context.
    /// Values are privacy-safe and never include full secret values.
    /// </summary>
    public IReadOnlyList<SecretFindingDetail>? Findings { get; set; }
}

/// <summary>
/// Privacy-safe detail for one secret finding.
/// </summary>
public sealed class SecretFindingDetail
{
    /// <summary>Finding code (e.g., secret:token:github).</summary>
    public string Code { get; set; } = string.Empty;
    /// <summary>Confidence level for this finding (High/Medium/Low).</summary>
    public string Confidence { get; set; } = "Medium";
    /// <summary>1-based line number when available.</summary>
    public int? Line { get; set; }
    /// <summary>Redacted evidence snippet (never full raw secret).</summary>
    public string Evidence { get; set; } = string.Empty;
}
