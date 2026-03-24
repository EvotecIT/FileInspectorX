namespace FileInspectorX;

/// <summary>
/// Policy-oriented projection of a file analysis for operator workflows and automation.
/// </summary>
public sealed class PolicySummaryView
{
    /// <summary>File path.</summary>
    public string Path { get; set; } = string.Empty;
    /// <summary>Computed risk score (0-100).</summary>
    public int? Score { get; set; }
    /// <summary>Primary balanced-profile decision.</summary>
    public string? Decision { get; set; }
    /// <summary>Decision under strict thresholds.</summary>
    public string? DecisionStrict { get; set; }
    /// <summary>Decision under balanced thresholds.</summary>
    public string? DecisionBalanced { get; set; }
    /// <summary>Decision under lenient thresholds.</summary>
    public string? DecisionLenient { get; set; }
    /// <summary>Compact assessment summary for logs or notification headers.</summary>
    public string? Summary { get; set; }
    /// <summary>Top scoring assessment drivers in short form.</summary>
    public string? TopDrivers { get; set; }
    /// <summary>Top scoring assessment drivers with longer explanations.</summary>
    public string? TopDriversLong { get; set; }
    /// <summary>High-level risk categories represented by the assessment drivers.</summary>
    public string? Categories { get; set; }
    /// <summary>Recommended operator action for the current decision.</summary>
    public string? RecommendedAction { get; set; }
    /// <summary>Conservative signal for whether the current decision is safe to automate.</summary>
    public bool? SafeForAutomation { get; set; }
    /// <summary>Detected type display used alongside the policy summary.</summary>
    public string? DetectedTypeDisplay { get; set; }
    /// <summary>The full analysis object for deep inspection.</summary>
    public FileAnalysis? Raw { get; set; }

    internal static PolicySummaryView From(string path, FileAnalysis analysis)
    {
        var report = ReportView.From(analysis);
        return new PolicySummaryView
        {
            Path = path,
            Score = report.AssessmentScore,
            Decision = report.AssessmentDecision,
            DecisionStrict = report.AssessmentDecisionStrict,
            DecisionBalanced = report.AssessmentDecisionBalanced,
            DecisionLenient = report.AssessmentDecisionLenient,
            Summary = report.AssessmentSummary,
            TopDrivers = report.AssessmentTopDrivers,
            TopDriversLong = report.AssessmentTopDriversLong,
            Categories = report.AssessmentCategories,
            RecommendedAction = report.AssessmentRecommendedAction,
            SafeForAutomation = report.AssessmentSafeForAutomation,
            DetectedTypeDisplay = report.DetectedTypeDisplay,
            Raw = null
        };
    }
}
