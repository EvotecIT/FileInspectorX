namespace FileInspectorX.Magika;

/// <summary>
/// Selects how model probability thresholds affect Magika output.
/// </summary>
public enum MagikaPredictionMode
{
    /// <summary>Use each label's high-confidence threshold.</summary>
    HighConfidence = 0,

    /// <summary>Use the model's shared medium-confidence threshold.</summary>
    MediumConfidence = 1,

    /// <summary>Return the highest-probability label regardless of its probability.</summary>
    BestGuess = 2
}
