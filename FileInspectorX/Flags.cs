namespace FileInspectorX;

/// <summary>
/// Bitmask of analysis signals derived from headers, containers and heuristics.
/// </summary>
[System.Flags]
public enum ContentFlags {
    None = 0,
    // OOXML
    /// <summary>Office Open XML document contains a vbaProject.bin stream.</summary>
    HasOoxmlMacros = 1 << 0,
    // Scripts / Text
    /// <summary>Text file contains a shebang indicating a script interpreter.</summary>
    IsScript = 1 << 1,
    // Containers
    /// <summary>Archive contains one or more executable modules (e.g., .exe, .dll, .msi).</summary>
    ContainerContainsExecutables = 1 << 2,
    /// <summary>Archive contains one or more script files (e.g., .ps1, .sh, .bat, .js).</summary>
    ContainerContainsScripts = 1 << 3,
    // PDF heuristics
    /// <summary>PDF contains JavaScript (/JS or /JavaScript markers).</summary>
    PdfHasJavaScript = 1 << 4,
    /// <summary>PDF defines an /OpenAction entry.</summary>
    PdfHasOpenAction = 1 << 5,
    /// <summary>PDF declares /AA (AdditionalActions).</summary>
    PdfHasAA = 1 << 6,
    // PE triage
    /// <summary>PE file has a non-empty IMAGE_DIRECTORY_ENTRY_SECURITY (WIN_CERTIFICATE).</summary>
    PeHasAuthenticodeDirectory = 1 << 7,
    /// <summary>PE file contains a COM descriptor (managed .NET assembly).</summary>
    PeIsDotNet = 1 << 8,
}