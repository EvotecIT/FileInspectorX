namespace FileInspectorX;

public sealed partial record InspectionSettings
{
    /// <inheritdoc cref="Settings.DetectionReadBudgetBytes"/>
    public int DetectionReadBudgetBytes { get; init; }

    /// <inheritdoc cref="Settings.HeaderReadBytes"/>
    public int HeaderReadBytes { get; init; }

    /// <inheritdoc cref="Settings.DetectionLogCandidates"/>
    public bool DetectionLogCandidates { get; init; }

    /// <inheritdoc cref="Settings.DetectionMaxAlternatives"/>
    public int DetectionMaxAlternatives { get; init; }

    /// <inheritdoc cref="Settings.DetectionPrimaryScoreMargin"/>
    public int DetectionPrimaryScoreMargin { get; init; }

    /// <inheritdoc cref="Settings.DetectionDeclaredTieBreakerMargin"/>
    public int DetectionDeclaredTieBreakerMargin { get; init; }

    /// <inheritdoc cref="Settings.DetectionStrongCandidateScoreThreshold"/>
    public int DetectionStrongCandidateScoreThreshold { get; init; }

    private IReadOnlyDictionary<string, int> _scoreAdjustments = FrozenSettingsCollections.EmptyScores;
    /// <inheritdoc cref="Settings.DetectionScoreAdjustments"/>
    public IReadOnlyDictionary<string, int> DetectionScoreAdjustments { get => _scoreAdjustments; init => _scoreAdjustments = FrozenSettingsCollections.CopyDictionary(value); }

    /// <inheritdoc cref="Settings.DetectionDeclaredExtensionBoost"/>
    public int DetectionDeclaredExtensionBoost { get; init; }

    /// <inheritdoc cref="Settings.DetectionJsonValidBoost"/>
    public int DetectionJsonValidBoost { get; init; }

    /// <inheritdoc cref="Settings.DetectionXmlWellFormedBoost"/>
    public int DetectionXmlWellFormedBoost { get; init; }

    /// <inheritdoc cref="Settings.DetectionNdjsonLines2Boost"/>
    public int DetectionNdjsonLines2Boost { get; init; }

    /// <inheritdoc cref="Settings.DetectionNdjsonLines3Boost"/>
    public int DetectionNdjsonLines3Boost { get; init; }

    /// <inheritdoc cref="Settings.DetectionMarkdownDeclaredPenalty"/>
    public int DetectionMarkdownDeclaredPenalty { get; init; }

    /// <inheritdoc cref="Settings.DetectionMarkdownStructuralPenalty"/>
    public int DetectionMarkdownStructuralPenalty { get; init; }

    /// <inheritdoc cref="Settings.DetectionMarkdownPenalty"/>
    public int DetectionMarkdownPenalty { get; init; }

    /// <inheritdoc cref="Settings.DetectionLogPenaltyFromScript"/>
    public int DetectionLogPenaltyFromScript { get; init; }

    /// <inheritdoc cref="Settings.DetectionScriptPenaltyFromLog"/>
    public int DetectionScriptPenaltyFromLog { get; init; }

    /// <inheritdoc cref="Settings.DetectionLogPenaltyFromMarkdown"/>
    public int DetectionLogPenaltyFromMarkdown { get; init; }

    /// <inheritdoc cref="Settings.DetectionJsonPenaltyFromScript"/>
    public int DetectionJsonPenaltyFromScript { get; init; }

    /// <inheritdoc cref="Settings.DetectionJsonPenaltyFromLog"/>
    public int DetectionJsonPenaltyFromLog { get; init; }

    /// <inheritdoc cref="Settings.DetectionYamlPenaltyFromLog"/>
    public int DetectionYamlPenaltyFromLog { get; init; }

    /// <inheritdoc cref="Settings.DetectionYamlPenaltyFromScript"/>
    public int DetectionYamlPenaltyFromScript { get; init; }

    /// <inheritdoc cref="Settings.DetectionMarkdownPenaltyFromIni"/>
    public int DetectionMarkdownPenaltyFromIni { get; init; }

    /// <inheritdoc cref="Settings.DetectionPlainTextPenaltyFromScript"/>
    public int DetectionPlainTextPenaltyFromScript { get; init; }

    /// <inheritdoc cref="Settings.DetectionPlainTextPenaltyFromLog"/>
    public int DetectionPlainTextPenaltyFromLog { get; init; }

    /// <inheritdoc cref="Settings.DetectionPlainTextPenaltyFromMarkdown"/>
    public int DetectionPlainTextPenaltyFromMarkdown { get; init; }

    /// <inheritdoc cref="Settings.PlainTextSampleBytes"/>
    public int PlainTextSampleBytes { get; init; }

    /// <inheritdoc cref="Settings.PlainTextPrintableMinRatio"/>
    public double PlainTextPrintableMinRatio { get; init; }

    /// <inheritdoc cref="Settings.PlainTextControlMaxRatio"/>
    public double PlainTextControlMaxRatio { get; init; }

    private FrozenSettingsCollections.StringSet? _dangerousExtensions;
    /// <inheritdoc cref="Settings.DangerousExtensionsOverride"/>
    public IReadOnlyCollection<string>? DangerousExtensionsOverride { get => _dangerousExtensions; init => _dangerousExtensions = value == null ? null : new FrozenSettingsCollections.StringSet(value); }
    internal ISet<string>? DangerousExtensionsSet => _dangerousExtensions;

    /// <inheritdoc cref="Settings.DangerousExtensionsOverrideMode"/>
    public DangerousExtensionsOverrideMode DangerousExtensionsOverrideMode { get; init; }

    /// <inheritdoc cref="Settings.AdmxAdmlXmlWellFormednessValidationEnabled"/>
    public bool AdmxAdmlXmlWellFormednessValidationEnabled { get; init; }

    /// <inheritdoc cref="Settings.JsonStructuralValidationEnabled"/>
    public bool JsonStructuralValidationEnabled { get; init; }

    /// <inheritdoc cref="Settings.JsonStructuralValidationMaxBytes"/>
    public int JsonStructuralValidationMaxBytes { get; init; }

    /// <inheritdoc cref="Settings.JsonStructuralValidationTimeoutMs"/>
    public int JsonStructuralValidationTimeoutMs { get; init; }

    /// <inheritdoc cref="Settings.JsonStructuralValidationMaxDepth"/>
    public int JsonStructuralValidationMaxDepth { get; init; }

    /// <inheritdoc cref="Settings.NetCdfNameMaxBytes"/>
    public int NetCdfNameMaxBytes { get; init; }

    /// <inheritdoc cref="Settings.AdmxAdmlXmlWellFormednessMaxBytes"/>
    public long AdmxAdmlXmlWellFormednessMaxBytes { get; init; }

    /// <inheritdoc cref="Settings.XmlWellFormednessTimeoutMs"/>
    public int XmlWellFormednessTimeoutMs { get; init; }
}
