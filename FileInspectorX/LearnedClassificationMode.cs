namespace FileInspectorX;

/// <summary>
/// Controls whether an optional learned content classifier participates in detection.
/// </summary>
public enum LearnedClassificationMode
{
    /// <summary>Do not invoke a learned classifier. This is the default.</summary>
    Off = 0,

    /// <summary>
    /// Use learned classification as supplemental evidence. Provider failures are recorded
    /// on the result and deterministic detection continues.
    /// </summary>
    Assist = 1,

    /// <summary>
    /// Require the configured learned classifier to run successfully. Provider failures throw
    /// <see cref="LearnedClassificationException"/>.
    /// </summary>
    Required = 2
}
