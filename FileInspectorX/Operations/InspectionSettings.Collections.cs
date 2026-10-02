namespace FileInspectorX;

public sealed partial record InspectionSettings
{
    /// <summary>Returns a snapshot with copied score adjustments using an explicit key comparer.</summary>
    /// <remarks>Use this for read-only or custom dictionaries whose comparer is not exposed.</remarks>
    public InspectionSettings WithDetectionScoreAdjustments(IEnumerable<KeyValuePair<string, int>> values, IEqualityComparer<string> comparer)
    {
        if (comparer == null) throw new ArgumentNullException(nameof(comparer));
        return this with { DetectionScoreAdjustments = FrozenSettingsCollections.CopyDictionary(values, comparer) };
    }

    /// <summary>Returns a snapshot with copied known-tool hashes using an explicit key comparer.</summary>
    public InspectionSettings WithKnownToolHashes(IEnumerable<KeyValuePair<string, string>> values, IEqualityComparer<string> comparer)
    {
        if (comparer == null) throw new ArgumentNullException(nameof(comparer));
        return this with { KnownToolHashes = FrozenSettingsCollections.CopyDictionary(values, comparer) };
    }

    /// <summary>Returns a snapshot with a copied dangerous-extension set using an explicit comparer.</summary>
    public InspectionSettings WithDangerousExtensionsOverride(IEnumerable<string> values, IEqualityComparer<string> comparer)
    {
        if (comparer == null) throw new ArgumentNullException(nameof(comparer));
        return this with { DangerousExtensionsOverride = new FrozenSettingsCollections.StringSet(values, comparer) };
    }
}
