namespace FileInspectorX;

public sealed partial record InspectionSettings
{
    /// <inheritdoc cref="Settings.ZipSubtypeMaxEntries"/>
    public int ZipSubtypeMaxEntries { get; init; }

    /// <inheritdoc cref="Settings.DeepContainerScanEnabled"/>
    public bool DeepContainerScanEnabled { get; init; }

    /// <inheritdoc cref="Settings.DeepContainerMaxEntries"/>
    public int DeepContainerMaxEntries { get; init; }

    /// <inheritdoc cref="Settings.DeepContainerMaxEntryBytes"/>
    public int DeepContainerMaxEntryBytes { get; init; }

    /// <inheritdoc cref="Settings.DeepContainerMaxNestedArchiveBytes"/>
    public int DeepContainerMaxNestedArchiveBytes { get; init; }

    /// <inheritdoc cref="Settings.DeepContainerMaxDepth"/>
    public int DeepContainerMaxDepth { get; init; }

    /// <inheritdoc cref="Settings.ArchiveMaxEntries"/>
    public int ArchiveMaxEntries { get; init; }

    /// <inheritdoc cref="Settings.ArchiveMaxCentralDirectoryBytes"/>
    public long ArchiveMaxCentralDirectoryBytes { get; init; }

    /// <inheritdoc cref="Settings.ArchiveMaxEntryReadBytes"/>
    public long ArchiveMaxEntryReadBytes { get; init; }

    /// <inheritdoc cref="Settings.ArchiveMaxTotalReadBytes"/>
    public long ArchiveMaxTotalReadBytes { get; init; }

    /// <inheritdoc cref="Settings.ArchiveMaxCompressionRatio"/>
    public double ArchiveMaxCompressionRatio { get; init; }

    private IReadOnlyList<string> _knownToolNameIndicators = FrozenSettingsCollections.EmptyStrings;
    /// <inheritdoc cref="Settings.KnownToolNameIndicators"/>
    public IReadOnlyList<string> KnownToolNameIndicators { get => _knownToolNameIndicators; init => _knownToolNameIndicators = FrozenSettingsCollections.CopyList(value); }

    private IReadOnlyDictionary<string, string> _toolHashes = FrozenSettingsCollections.EmptyHashes;
    /// <inheritdoc cref="Settings.KnownToolHashes"/>
    public IReadOnlyDictionary<string, string> KnownToolHashes { get => _toolHashes; init => _toolHashes = FrozenSettingsCollections.CopyDictionary(value); }
}
