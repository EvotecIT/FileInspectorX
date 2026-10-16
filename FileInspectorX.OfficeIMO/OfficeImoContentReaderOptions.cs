namespace FileInspectorX.OfficeIMO;

/// <summary>Finite native inspection profile. The reader snapshots these settings at construction.</summary>
public sealed class OfficeImoContentReaderOptions
{
    /// <summary>Maximum source bytes admitted to one native owner. Default: 32 MiB.</summary>
    public long MaxInputBytes { get; set; } = 32L * 1024 * 1024;
    /// <summary>Maximum native expanded bytes reserved per input. Default: 64 MiB.</summary>
    public long MaxNativeExpandedBytes { get; set; } = 64L * 1024 * 1024;
    /// <summary>Maximum package parts, archive entries or source records. Default: 4096.</summary>
    public int MaxSourceRecords { get; set; } = 4096;
    /// <summary>Maximum native XML depth. Default: 128.</summary>
    public int MaxXmlDepth { get; set; } = 128;
    /// <summary>Maximum source expansion ratio. Default: 300.</summary>
    public double MaxCompressionRatio { get; set; } = 300;
    /// <summary>Includes speaker notes and RTF notes in canonical text.</summary>
    public bool IncludeNotes { get; set; } = true;
    /// <summary>Includes authored hidden PowerPoint shapes in canonical text.</summary>
    public bool IncludeHiddenShapes { get; set; } = true;
    /// <summary>Uses saved Excel formula values without calculating formulas.</summary>
    public bool UseCachedFormulaResults { get; set; } = true;
    /// <summary>Requests complete bounded inert payloads for the core's descendant dispatcher.</summary>
    public bool ReadEmbeddedMembers { get; set; } = true;

    internal OfficeImoContentReaderOptions Snapshot()
    {
        if (MaxInputBytes < 1 || MaxNativeExpandedBytes < 1 || MaxSourceRecords < 1 || MaxXmlDepth < 1 ||
            double.IsNaN(MaxCompressionRatio) || double.IsInfinity(MaxCompressionRatio) || MaxCompressionRatio < 1)
            throw new ArgumentOutOfRangeException(nameof(OfficeImoContentReaderOptions), "Native limits must be finite and positive.");
        return (OfficeImoContentReaderOptions)MemberwiseClone();
    }
}
