namespace FileInspectorX;

/// <summary>
/// Describes how deterministic and learned content evidence were combined.
/// </summary>
public enum LearnedClassificationDisposition
{
    /// <summary>The learned classifier was not enabled.</summary>
    Disabled = 0,

    /// <summary>The learned prediction was retained as supplemental evidence.</summary>
    Supplemental = 1,

    /// <summary>The learned prediction agreed with deterministic detection.</summary>
    Agreed = 2,

    /// <summary>The learned prediction filled an unknown or generic low-confidence detection.</summary>
    Promoted = 3,

    /// <summary>Strong deterministic evidence and learned evidence disagreed.</summary>
    Conflict = 4,

    /// <summary>The learned provider failed while running in assist mode.</summary>
    Failed = 5
}
