namespace FileInspectorX;

/// <summary>Immutable settings used by one inspection operation or a reusable inspection profile.</summary>
/// <remarks>
/// Create a snapshot with <see cref="CaptureDefaults"/> and customize it with a record <c>with</c> expression.
/// Collections are copied on assignment and exposed through read-only wrappers. Concurrent operations
/// can safely share a snapshot. Capture legacy defaults while their configuration is stable; independent
/// writes to <see cref="Settings"/> are not an atomic configuration transaction.
/// </remarks>
public sealed partial record InspectionSettings
{
    private InspectionSettings() { }

    /// <summary>Captures all current global settings, defensively copying their collections.</summary>
    /// <param name="scoreComparer">Comparer for an opaque score dictionary, or a custom concurrent dictionary on older targets.</param>
    /// <param name="toolHashComparer">Comparer for an opaque known-tool hash dictionary.</param>
    /// <param name="dangerousExtensionComparer">Comparer for an opaque dangerous-extension set.</param>
    /// <remarks>Known dictionary and set implementations retain their exposed comparers. Opaque implementations require an explicit comparer.</remarks>
    public static InspectionSettings CaptureDefaults(IEqualityComparer<string>? scoreComparer = null,
        IEqualityComparer<string>? toolHashComparer = null, IEqualityComparer<string>? dangerousExtensionComparer = null)
    {
#pragma warning disable CS0618 // Preserve obsolete compatibility values without using them for caching.
        return new InspectionSettings
        {
            DetectionReadBudgetBytes = Settings.DetectionReadBudgetBytes,
            HeaderReadBytes = Settings.HeaderReadBytes,
            DetectionLogCandidates = Settings.DetectionLogCandidates,
            DetectionMaxAlternatives = Settings.DetectionMaxAlternatives,
            DetectionPrimaryScoreMargin = Settings.DetectionPrimaryScoreMargin,
            DetectionDeclaredTieBreakerMargin = Settings.DetectionDeclaredTieBreakerMargin,
            DetectionStrongCandidateScoreThreshold = Settings.DetectionStrongCandidateScoreThreshold,
            DetectionScoreAdjustments = FrozenSettingsCollections.CopyDictionary(Settings.DetectionScoreAdjustments, scoreComparer),
            DetectionDeclaredExtensionBoost = Settings.DetectionDeclaredExtensionBoost,
            DetectionJsonValidBoost = Settings.DetectionJsonValidBoost,
            DetectionXmlWellFormedBoost = Settings.DetectionXmlWellFormedBoost,
            DetectionNdjsonLines2Boost = Settings.DetectionNdjsonLines2Boost,
            DetectionNdjsonLines3Boost = Settings.DetectionNdjsonLines3Boost,
            DetectionMarkdownDeclaredPenalty = Settings.DetectionMarkdownDeclaredPenalty,
            DetectionMarkdownStructuralPenalty = Settings.DetectionMarkdownStructuralPenalty,
            DetectionMarkdownPenalty = Settings.DetectionMarkdownPenalty,
            DetectionLogPenaltyFromScript = Settings.DetectionLogPenaltyFromScript,
            DetectionScriptPenaltyFromLog = Settings.DetectionScriptPenaltyFromLog,
            DetectionLogPenaltyFromMarkdown = Settings.DetectionLogPenaltyFromMarkdown,
            DetectionJsonPenaltyFromScript = Settings.DetectionJsonPenaltyFromScript,
            DetectionJsonPenaltyFromLog = Settings.DetectionJsonPenaltyFromLog,
            DetectionYamlPenaltyFromLog = Settings.DetectionYamlPenaltyFromLog,
            DetectionYamlPenaltyFromScript = Settings.DetectionYamlPenaltyFromScript,
            DetectionMarkdownPenaltyFromIni = Settings.DetectionMarkdownPenaltyFromIni,
            DetectionPlainTextPenaltyFromScript = Settings.DetectionPlainTextPenaltyFromScript,
            DetectionPlainTextPenaltyFromLog = Settings.DetectionPlainTextPenaltyFromLog,
            DetectionPlainTextPenaltyFromMarkdown = Settings.DetectionPlainTextPenaltyFromMarkdown,
            PlainTextSampleBytes = Settings.PlainTextSampleBytes,
            PlainTextPrintableMinRatio = Settings.PlainTextPrintableMinRatio,
            PlainTextControlMaxRatio = Settings.PlainTextControlMaxRatio,
            DangerousExtensionsOverride = Settings.DangerousExtensionsOverride == null ? null : new FrozenSettingsCollections.StringSet(Settings.DangerousExtensionsOverride, dangerousExtensionComparer),
            DangerousExtensionsOverrideMode = Settings.DangerousExtensionsOverrideMode,
            ZipSubtypeMaxEntries = Settings.ZipSubtypeMaxEntries,
            AdmxAdmlXmlWellFormednessValidationEnabled = Settings.AdmxAdmlXmlWellFormednessValidationEnabled,
            JsonStructuralValidationEnabled = Settings.JsonStructuralValidationEnabled,
            JsonStructuralValidationMaxBytes = Settings.JsonStructuralValidationMaxBytes,
            JsonStructuralValidationTimeoutMs = Settings.JsonStructuralValidationTimeoutMs,
            JsonStructuralValidationMaxDepth = Settings.JsonStructuralValidationMaxDepth,
            NetCdfNameMaxBytes = Settings.NetCdfNameMaxBytes,
            AdmxAdmlXmlWellFormednessMaxBytes = Settings.AdmxAdmlXmlWellFormednessMaxBytes,
            XmlWellFormednessTimeoutMs = Settings.XmlWellFormednessTimeoutMs,
            JsMinifiedMinLength = Settings.JsMinifiedMinLength,
            JsMinifiedAvgLineThreshold = Settings.JsMinifiedAvgLineThreshold,
            JsMinifiedDensityThreshold = Settings.JsMinifiedDensityThreshold,
            SecurityScanScripts = Settings.SecurityScanScripts,
            SecretsScanEnabled = Settings.SecretsScanEnabled,
            TopTokensEnabled = Settings.TopTokensEnabled,
            TopTokensMaxBytes = Settings.TopTokensMaxBytes,
            TopTokensMax = Settings.TopTokensMax,
            TopTokensMinLength = Settings.TopTokensMinLength,
            TopTokensMinCount = Settings.TopTokensMinCount,
            TopTokensMaxUniqueTokens = Settings.TopTokensMaxUniqueTokens,
            TopTokensRedactPatterns = Settings.TopTokensRedactPatterns ?? Array.Empty<string>(),
            ScriptHintMaxLineLength = Settings.ScriptHintMaxLineLength,
            ScriptHintMaxLines = Settings.ScriptHintMaxLines,
            CheckNetworkPathsInReferences = Settings.CheckNetworkPathsInReferences,
            VerifyAuthenticodeWithWinTrust = Settings.VerifyAuthenticodeWithWinTrust,
            VerifyAuthenticodeRevocation = Settings.VerifyAuthenticodeRevocation,
            WinTrustCacheTtlMinutes = Settings.WinTrustCacheTtlMinutes,
            WinTrustCacheMaxEntries = Settings.WinTrustCacheMaxEntries,
            IncludeInstaller = Settings.IncludeInstaller,
            EnableMsiCustomActions = Settings.EnableMsiCustomActions,
            EnableMsiSummaryInfo = Settings.EnableMsiSummaryInfo,
            BreadcrumbsEnabled = Settings.BreadcrumbsEnabled,
            BreadcrumbsPath = Settings.BreadcrumbsPath,
            BreadcrumbsMaxBytes = Settings.BreadcrumbsMaxBytes,
            ResolveNetworkHostsInHeuristics = Settings.ResolveNetworkHostsInHeuristics,
            NetworkHostResolveMax = Settings.NetworkHostResolveMax,
            NetworkHostResolveTimeoutMs = Settings.NetworkHostResolveTimeoutMs,
            PingHostsInHeuristics = Settings.PingHostsInHeuristics,
            HtmlAllowedDomains = Settings.HtmlAllowedDomains ?? Array.Empty<string>(),
            ReferenceFullListsEnabled = Settings.ReferenceFullListsEnabled,
            ReportHostFileMetadataEnabled = Settings.ReportHostFileMetadataEnabled,
            FindingEvidenceSnippetsEnabled = Settings.FindingEvidenceSnippetsEnabled,
            ReferencePathExistenceChecksEnabled = Settings.ReferencePathExistenceChecksEnabled,
            MotwMaxCharacters = Settings.MotwMaxCharacters,
            ReferenceExtractionMaxBytes = Settings.ReferenceExtractionMaxBytes,
            ReferenceFullListsMaxChars = Settings.ReferenceFullListsMaxChars,
            AssessmentWarnThreshold = Settings.AssessmentWarnThreshold,
            AssessmentBlockThreshold = Settings.AssessmentBlockThreshold,
            AllowedVendors = Settings.AllowedVendors ?? Array.Empty<string>(),
            VendorMatchMode = Settings.VendorMatchMode,
            DeepContainerScanEnabled = Settings.DeepContainerScanEnabled,
            DeepContainerMaxEntries = Settings.DeepContainerMaxEntries,
            DeepContainerMaxEntryBytes = Settings.DeepContainerMaxEntryBytes,
            DeepContainerMaxNestedArchiveBytes = Settings.DeepContainerMaxNestedArchiveBytes,
            DeepContainerMaxDepth = Settings.DeepContainerMaxDepth,
            ArchiveMaxEntries = Settings.ArchiveMaxEntries,
            ArchiveMaxCentralDirectoryBytes = Settings.ArchiveMaxCentralDirectoryBytes,
            ArchiveMaxEntryReadBytes = Settings.ArchiveMaxEntryReadBytes,
            ArchiveMaxTotalReadBytes = Settings.ArchiveMaxTotalReadBytes,
            ArchiveMaxCompressionRatio = Settings.ArchiveMaxCompressionRatio,
            KnownToolNameIndicators = Settings.KnownToolNameIndicators ?? Array.Empty<string>(),
            KnownToolHashes = FrozenSettingsCollections.CopyDictionary(Settings.KnownToolHashes, toolHashComparer),
            EncodedBase64MinBlock = Settings.EncodedBase64MinBlock,
            EncodedBase64ProbeChars = Settings.EncodedBase64ProbeChars,
            EncodedBase64AllowedRatio = Settings.EncodedBase64AllowedRatio,
            EncodedHexMinChars = Settings.EncodedHexMinChars,
            EncodedProbeReadBytes = Settings.EncodedProbeReadBytes,
            EncodedDecodeMaxBytes = Settings.EncodedDecodeMaxBytes,
            EtlValidation = Settings.EtlValidation,
            EtlProbeTimeoutMs = Settings.EtlProbeTimeoutMs,
            EtlLargeFileQuickScanBytes = Settings.EtlLargeFileQuickScanBytes,
        };
#pragma warning restore CS0618
    }
}
