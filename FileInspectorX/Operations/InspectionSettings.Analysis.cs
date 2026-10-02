namespace FileInspectorX;

public sealed partial record InspectionSettings
{
    /// <inheritdoc cref="Settings.JsMinifiedMinLength"/>
    public int JsMinifiedMinLength { get; init; }

    /// <inheritdoc cref="Settings.JsMinifiedAvgLineThreshold"/>
    public int JsMinifiedAvgLineThreshold { get; init; }

    /// <inheritdoc cref="Settings.JsMinifiedDensityThreshold"/>
    public double JsMinifiedDensityThreshold { get; init; }

    /// <inheritdoc cref="Settings.SecurityScanScripts"/>
    public bool SecurityScanScripts { get; init; }

    /// <inheritdoc cref="Settings.SecretsScanEnabled"/>
    public bool SecretsScanEnabled { get; init; }

    /// <inheritdoc cref="Settings.TopTokensEnabled"/>
    public bool TopTokensEnabled { get; init; }

    /// <inheritdoc cref="Settings.TopTokensMaxBytes"/>
    public int TopTokensMaxBytes { get; init; }

    /// <inheritdoc cref="Settings.TopTokensMax"/>
    public int TopTokensMax { get; init; }

    /// <inheritdoc cref="Settings.TopTokensMinLength"/>
    public int TopTokensMinLength { get; init; }

    /// <inheritdoc cref="Settings.TopTokensMinCount"/>
    public int TopTokensMinCount { get; init; }

    /// <inheritdoc cref="Settings.TopTokensMaxUniqueTokens"/>
    public int TopTokensMaxUniqueTokens { get; init; }

    private IReadOnlyList<string> _topTokensRedactPatterns = FrozenSettingsCollections.EmptyStrings;
    /// <inheritdoc cref="Settings.TopTokensRedactPatterns"/>
    public IReadOnlyList<string> TopTokensRedactPatterns { get => _topTokensRedactPatterns; init => _topTokensRedactPatterns = FrozenSettingsCollections.CopyList(value); }

    /// <inheritdoc cref="Settings.ScriptHintMaxLineLength"/>
    public int ScriptHintMaxLineLength { get; init; }

    /// <inheritdoc cref="Settings.ScriptHintMaxLines"/>
    public int ScriptHintMaxLines { get; init; }

    /// <inheritdoc cref="Settings.CheckNetworkPathsInReferences"/>
    public bool CheckNetworkPathsInReferences { get; init; }

    /// <inheritdoc cref="Settings.VerifyAuthenticodeWithWinTrust"/>
    public bool VerifyAuthenticodeWithWinTrust { get; init; }

    /// <inheritdoc cref="Settings.VerifyAuthenticodeRevocation"/>
    public bool VerifyAuthenticodeRevocation { get; init; }

    /// <inheritdoc cref="Settings.WinTrustCacheTtlMinutes"/>
    public int WinTrustCacheTtlMinutes { get; init; }

    /// <inheritdoc cref="Settings.WinTrustCacheMaxEntries"/>
    public int WinTrustCacheMaxEntries { get; init; }

    /// <inheritdoc cref="Settings.IncludeInstaller"/>
    public bool IncludeInstaller { get; init; }

    /// <inheritdoc cref="Settings.EnableMsiCustomActions"/>
    public bool EnableMsiCustomActions { get; init; }

    /// <inheritdoc cref="Settings.EnableMsiSummaryInfo"/>
    public bool EnableMsiSummaryInfo { get; init; }

    /// <inheritdoc cref="Settings.BreadcrumbsEnabled"/>
    public bool BreadcrumbsEnabled { get; init; }

    /// <inheritdoc cref="Settings.BreadcrumbsPath"/>
    public string? BreadcrumbsPath { get; init; }

    /// <inheritdoc cref="Settings.BreadcrumbsMaxBytes"/>
    public int BreadcrumbsMaxBytes { get; init; }

    /// <inheritdoc cref="Settings.ResolveNetworkHostsInHeuristics"/>
    public bool ResolveNetworkHostsInHeuristics { get; init; }

    /// <inheritdoc cref="Settings.NetworkHostResolveMax"/>
    public int NetworkHostResolveMax { get; init; }

    /// <inheritdoc cref="Settings.NetworkHostResolveTimeoutMs"/>
    public int NetworkHostResolveTimeoutMs { get; init; }

    /// <inheritdoc cref="Settings.PingHostsInHeuristics"/>
    public bool PingHostsInHeuristics { get; init; }

    private IReadOnlyList<string> _htmlAllowedDomains = FrozenSettingsCollections.EmptyStrings;
    /// <inheritdoc cref="Settings.HtmlAllowedDomains"/>
    public IReadOnlyList<string> HtmlAllowedDomains { get => _htmlAllowedDomains; init => _htmlAllowedDomains = FrozenSettingsCollections.CopyList(value); }

    /// <inheritdoc cref="Settings.ReferenceFullListsEnabled"/>
    public bool ReferenceFullListsEnabled { get; init; }

    /// <inheritdoc cref="Settings.ReportHostFileMetadataEnabled"/>
    public bool ReportHostFileMetadataEnabled { get; init; }

    /// <inheritdoc cref="Settings.FindingEvidenceSnippetsEnabled"/>
    public bool FindingEvidenceSnippetsEnabled { get; init; }

    /// <inheritdoc cref="Settings.ReferencePathExistenceChecksEnabled"/>
    public bool ReferencePathExistenceChecksEnabled { get; init; }

    /// <inheritdoc cref="Settings.MotwMaxCharacters"/>
    public int MotwMaxCharacters { get; init; }

    /// <inheritdoc cref="Settings.ReferenceExtractionMaxBytes"/>
    public int ReferenceExtractionMaxBytes { get; init; }

    /// <inheritdoc cref="Settings.ReferenceFullListsMaxChars"/>
    public int ReferenceFullListsMaxChars { get; init; }

    /// <inheritdoc cref="Settings.AssessmentWarnThreshold"/>
    public int AssessmentWarnThreshold { get; init; }

    /// <inheritdoc cref="Settings.AssessmentBlockThreshold"/>
    public int AssessmentBlockThreshold { get; init; }

    private IReadOnlyList<string> _allowedVendors = FrozenSettingsCollections.EmptyStrings;
    /// <inheritdoc cref="Settings.AllowedVendors"/>
    public IReadOnlyList<string> AllowedVendors { get => _allowedVendors; init => _allowedVendors = FrozenSettingsCollections.CopyList(value); }

    /// <inheritdoc cref="Settings.VendorMatchMode"/>
    public VendorMatchMode VendorMatchMode { get; init; }

    /// <inheritdoc cref="Settings.EncodedBase64MinBlock"/>
    public int EncodedBase64MinBlock { get; init; }

    /// <inheritdoc cref="Settings.EncodedBase64ProbeChars"/>
    public int EncodedBase64ProbeChars { get; init; }

    /// <inheritdoc cref="Settings.EncodedBase64AllowedRatio"/>
    public double EncodedBase64AllowedRatio { get; init; }

    /// <inheritdoc cref="Settings.EncodedHexMinChars"/>
    public int EncodedHexMinChars { get; init; }

    /// <inheritdoc cref="Settings.EncodedProbeReadBytes"/>
    public int EncodedProbeReadBytes { get; init; }

    /// <inheritdoc cref="Settings.EncodedDecodeMaxBytes"/>
    public int EncodedDecodeMaxBytes { get; init; }

    /// <inheritdoc cref="Settings.EtlValidation"/>
    public Settings.EtlValidationMode EtlValidation { get; init; }

    /// <inheritdoc cref="Settings.EtlProbeTimeoutMs"/>
    public int EtlProbeTimeoutMs { get; init; }

    /// <inheritdoc cref="Settings.EtlLargeFileQuickScanBytes"/>
    public long EtlLargeFileQuickScanBytes { get; init; }
}
