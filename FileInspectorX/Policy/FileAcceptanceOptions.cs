namespace FileInspectorX;

/// <summary>Content restrictions applied to an inspection result without executing or reopening the input.</summary>
public sealed class FileAcceptanceOptions
{
    /// <summary>Require the client filename extension to match content detection, including supported aliases.</summary>
    public bool RequireDeclaredTypeMatch { get; init; } = true;

    /// <summary>Reject encrypted PDF, Office and archive content that cannot be inspected transparently.</summary>
    public bool RejectEncryptedContent { get; init; } = true;

    /// <summary>Reject observed document macros, active controls, automatic actions and external actions.</summary>
    public bool RejectActiveDocuments { get; init; } = true;

    /// <summary>Reject observed embedded document payloads. Ordinary archive members are not covered by this option.</summary>
    public bool RejectEmbeddedPayloads { get; init; } = true;

    /// <summary>Reject archive traversal, absolute member paths and symbolic links.</summary>
    public bool RejectUnsafeArchivePaths { get; init; } = true;

    /// <summary>Reject inputs whose analysis reached a declared resource limit instead of treating them as ordinary partial evidence.</summary>
    public bool RejectResourceLimits { get; init; } = true;
}
