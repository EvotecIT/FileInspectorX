namespace FileInspectorX;

/// <summary>
/// Raised when learned classification is required but cannot complete.
/// </summary>
public sealed class LearnedClassificationException : Exception
{
    /// <summary>Creates an exception for a required learned-classification failure.</summary>
    public LearnedClassificationException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
