namespace FileInspectorX;

/// <summary>Portable archive-name checks, independent of the host's path rules.</summary>
internal static class ArchivePathSafety
{
    internal static bool HasTraversal(string name)
        => name.Replace('\\', '/').Split('/').Any(segment => segment == "..");

    internal static bool IsAbsolute(string name)
        => name.StartsWith("/", StringComparison.Ordinal) || name.StartsWith("\\", StringComparison.Ordinal) ||
           (name.Length >= 2 && char.IsLetter(name[0]) && name[1] == ':');
}
