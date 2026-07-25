namespace FileInspectorX.Magika;

/// <summary>
/// Options for the bundled Magika model.
/// </summary>
public sealed class MagikaClassifierOptions
{
    /// <summary>Controls threshold handling. The default is <see cref="MagikaPredictionMode.HighConfidence"/>.</summary>
    public MagikaPredictionMode PredictionMode { get; set; } = MagikaPredictionMode.HighConfidence;
}
