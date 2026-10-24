namespace FileInspectorX;

/// <summary>Acceptance under the selected policy and the available inspection evidence.</summary>
public enum FileAcceptanceDecision
{
    /// <summary>The observed evidence satisfies the policy. This is not a malware-free guarantee.</summary>
    Accepted,
    /// <summary>An observed property violates the policy.</summary>
    Rejected,
    /// <summary>The evidence is insufficient to accept the input automatically.</summary>
    Incomplete
}

/// <summary>A policy verdict with stable reason codes that contain no input paths or exception messages.</summary>
public sealed class FileAcceptanceResult
{
    internal FileAcceptanceResult(FileAcceptanceDecision decision, IEnumerable<string> reasons)
    {
        Decision = decision;
        Reasons = Array.AsReadOnly(reasons.Distinct(StringComparer.Ordinal).OrderBy(x => x, StringComparer.Ordinal).ToArray());
    }

    /// <summary>The decision for the supplied evidence, not for any later changed file.</summary>
    public FileAcceptanceDecision Decision { get; }

    /// <summary>Stable reasons explaining rejection or incomplete evidence.</summary>
    public IReadOnlyList<string> Reasons { get; }
}
