namespace FileInspectorX;

/// <summary>
/// Bitmask of analysis signals derived from headers, containers and heuristics.
/// </summary>
[System.Flags]
public enum ContentFlags : long {
    /// <summary>No additional signals detected.</summary>
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
    /// <summary>PDF indicates embedded files via /EmbeddedFiles name tree or related markers.</summary>
    PdfHasEmbeddedFiles = 1 << 7,
    /// <summary>PDF includes /Launch action.</summary>
    PdfHasLaunch = 1 << 8,
    /// <summary>PDF contains a /Names tree.</summary>
    PdfHasNamesTree = 1 << 12,
    /// <summary>PDF indicates many embedded files (heuristic count threshold).</summary>
    PdfHasManyEmbeddedFiles = 1 << 15,
    // PE triage
    /// <summary>PE file has a non-empty IMAGE_DIRECTORY_ENTRY_SECURITY (WIN_CERTIFICATE).</summary>
    PeHasAuthenticodeDirectory = 1 << 9,
    /// <summary>PE file contains a COM descriptor (managed .NET assembly).</summary>
    PeIsDotNet = 1 << 10,

    /// <summary>Archive contains nested archive(s) (e.g., zip within zip).</summary>
    ContainerContainsArchives = 1 << 11,
    /// <summary>JavaScript file appears minified based on simple heuristics.</summary>
    JsLooksMinified = 1 << 13,
    /// <summary>Script file (by extension or shebang) that is potentially dangerous to execute.</summary>
    ScriptsPotentiallyDangerous = 1 << 14,
    /// <summary>PE file looks packed with UPX based on section names.</summary>
    PeLooksPackedUpx = 1 << 16,
    /// <summary>PE file contains an Authenticode signature blob (WIN_CERTIFICATE).</summary>
    PeHasAuthenticode = 1 << 17,
    /// <summary>Authenticode chain builds successfully to a trusted root (best-effort).</summary>
    PeAuthenticodeChainValid = 1 << 18,
    /// <summary>Authenticode signature includes a timestamp countersignature.</summary>
    PeAuthenticodeHasTimestamp = 1 << 19,

    /// <summary>Archive contains entries with path traversal patterns (e.g., ..\ or ../).</summary>
    ArchiveHasPathTraversal = 1 << 20,
    /// <summary>Archive contains entries that are symbolic links.</summary>
    ArchiveHasSymlinks = 1 << 21,
    /// <summary>Archive contains entries with absolute paths.</summary>
    ArchiveHasAbsolutePaths = 1 << 22,
    /// <summary>Archive contains installer packages (e.g., .msi, .msix/.appx, msu) or setup stubs.</summary>
    ContainerContainsInstallers = 1 << 23,
    /// <summary>PE optional header lacks ASLR (no DYNAMIC_BASE).</summary>
    PeNoAslr = 1 << 24,
    /// <summary>PE optional header lacks NX/DEP (no NX_COMPAT).</summary>
    PeNoNx = 1 << 25,
    /// <summary>PE optional header lacks Control Flow Guard (no GUARD_CF).</summary>
    PeNoCfg = 1 << 26,
    /// <summary>PE optional header lacks HighEntropyVA (x64 ASLR hardening).</summary>
    PeNoHighEntropyVa = 1 << 27,
    /// <summary>PDF contains XFA forms (/XFA).</summary>
    PdfHasXfa = 1 << 28,
    /// <summary>PDF is encrypted (/Encrypt dictionary present).</summary>
    PdfEncrypted = 1 << 29,
    /// <summary>PDF appears to have many incremental updates (multiple startxref markers).</summary>
    PdfManyIncrementalUpdates = 1 << 30,
    /// <summary>OOXML document references a remote template (attachedTemplate external).</summary>
    OfficeRemoteTemplate = 1L << 31,
    /// <summary>OOXML document contains possible DDE/DDEAUTO field instructions.</summary>
    OfficePossibleDde = 1L << 32,
    /// <summary>OOXML document (Excel) references external links (xl/externalLinks or related relationships).</summary>
    OfficeExternalLinks = 1L << 33
}
