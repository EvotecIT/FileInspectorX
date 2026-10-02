namespace FileInspectorX.Magika;

/// <summary>
/// Options for the bundled Magika model.
/// </summary>
public sealed class MagikaClassifierOptions
{
    /// <summary>Controls threshold handling. The default is <see cref="MagikaPredictionMode.HighConfidence"/>.</summary>
    public MagikaPredictionMode PredictionMode { get; set; } = MagikaPredictionMode.HighConfidence;

    /// <summary>Native intra-operation threads. Zero preserves ONNX Runtime's default physical-core policy; positive values set an explicit count.</summary>
    /// <remarks>Captured at construction. Benchmark explicit counts for your concurrency and batch sizes before selecting one.</remarks>
    public int IntraOpThreadCount { get; set; }
}
