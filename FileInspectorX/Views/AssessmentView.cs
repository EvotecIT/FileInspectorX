namespace FileInspectorX;

/// <summary>
/// Flattened projection of <see cref="AssessmentResult"/>.
/// </summary>
public sealed class AssessmentView
{
    /// <summary>File path.</summary>
    public string Path { get; set; } = string.Empty;
    /// <summary>Computed risk score (0-100).</summary>
    public int Score { get; set; }
    /// <summary>Decision derived from the score and signals.</summary>
    public AssessmentDecision Decision { get; set; }
    /// <summary>Comma-separated list of stable finding codes that contributed to the score.</summary>
    public string Codes { get; set; } = string.Empty; // comma-separated for table friendliness
    /// <summary>The full analysis object for deep inspection.</summary>
    public FileAnalysis? Raw { get; set; }

    internal static AssessmentView From(string path, AssessmentResult a)
    {
        return new AssessmentView
        {
            Path = path,
            Score = a.Score,
            Decision = a.Decision,
            Codes = string.Join(",", a.Codes ?? System.Array.Empty<string>()),
            Raw = null
        };
    }
}
