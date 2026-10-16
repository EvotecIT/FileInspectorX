namespace FileInspectorX;

/// <summary>The native or Core boundary that rejected content work.</summary>
public enum InspectionContentLimitDomain
{
    /// <summary>A native resource/work allowance was exhausted.</summary>
    Resource,
    /// <summary>A source or output admission rule rejected the operation.</summary>
    Admission
}

/// <summary>Terminal optional-reader resource or admission failure, distinct from parser and filesystem I/O failures.</summary>
public sealed class InspectionContentLimitException : Exception
{
    /// <summary>Create a terminal marker preserving native numeric measurements and the original exception.</summary>
    /// <remarks>Fractional and infinite measurements are retained without rounding into byte quotas.</remarks>
    public InspectionContentLimitException(InspectionContentLimitDomain domain, string code, string limitName,
        double? maximum, double? actual, Exception? innerException = null)
        : base(FormatMessage(code, limitName), innerException)
    {
        if (!Enum.IsDefined(typeof(InspectionContentLimitDomain), domain)) throw new ArgumentOutOfRangeException(nameof(domain));
        Domain = domain;
        Code = code;
        LimitName = limitName;
        Maximum = maximum;
        Actual = actual;
    }

    /// <summary>Resource exhaustion or admission rejection.</summary>
    public InspectionContentLimitDomain Domain { get; }
    /// <summary>Stable native or mapped failure code.</summary>
    public string Code { get; }
    /// <summary>Native limit or admission-rule name.</summary>
    public string LimitName { get; }
    /// <summary>Native maximum when measured, without numeric coercion.</summary>
    public double? Maximum { get; }
    /// <summary>Native observed measurement when known.</summary>
    public double? Actual { get; }

    private static string FormatMessage(string code, string limitName)
    {
        if (string.IsNullOrWhiteSpace(code)) throw new ArgumentException("A stable failure code is required.", nameof(code));
        if (string.IsNullOrWhiteSpace(limitName)) throw new ArgumentException("A limit name is required.", nameof(limitName));
        return "Content limit exceeded: " + code + " (" + limitName + ").";
    }
}
