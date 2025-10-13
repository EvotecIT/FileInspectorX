namespace FileInspectorX;

/// <summary>
/// Flattened projection of <see cref="AssessmentResult"/>.
/// </summary>
public sealed class AssessmentView
{
    public string Path { get; set; } = string.Empty;
    public int Score { get; set; }
    public AssessmentDecision Decision { get; set; }
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
