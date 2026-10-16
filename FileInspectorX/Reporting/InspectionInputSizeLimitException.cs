namespace FileInspectorX;

/// <summary>Whole-snapshot input-size rejection, intentionally distinct from native reader and parser I/O failures.</summary>
public sealed class InspectionInputSizeLimitException : IOException
{
    /// <summary>Create an input-size failure with the configured maximum and observed source length.</summary>
    public InspectionInputSizeLimitException(long maximumBytes, long observedBytes)
        : base("Input exceeds the configured snapshot byte limit.")
    {
        if (maximumBytes < 0) throw new ArgumentOutOfRangeException(nameof(maximumBytes));
        if (observedBytes < 0) throw new ArgumentOutOfRangeException(nameof(observedBytes));
        MaximumBytes = maximumBytes;
        ObservedBytes = observedBytes;
    }

    /// <summary>Configured complete-input maximum.</summary>
    public long MaximumBytes { get; }
    /// <summary>Source bytes observed before rejection; may be a lower bound for an unseekable input.</summary>
    public long ObservedBytes { get; }
}
