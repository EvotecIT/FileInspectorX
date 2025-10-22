using System;
using System.Collections.Generic;
using System.Linq;

namespace FileInspectorX;

/// <summary>
/// Humanization for risk assessment codes emitted by FileInspectorX.Assess().
/// Provides typed legend and helpers to render short/long text.
/// </summary>
public static class AssessmentLegend
{
    private static readonly Dictionary<string, LegendEntry> s_codes = new(StringComparer.OrdinalIgnoreCase)
    {
        // Archives
        ["Archive.PathTraversal"]       = new("Archive.PathTraversal", "Archive path traversal", "Archive contains entries with path traversal patterns (e.g., ../ or ..\\).", "Archive", 90),
        ["Archive.Symlink"]             = new("Archive.Symlink",       "Archive symlinks",     "Archive contains symbolic links.", "Archive", 60),
        ["Archive.AbsolutePath"]        = new("Archive.AbsolutePath",  "Archive absolute paths","Archive contains entries with absolute paths.", "Archive", 55),
        ["Archive.ContainsExecutables"] = new("Archive.ContainsExecutables", "Executables inside archive", "Archive includes .exe/.dll/.msi items.", "Archive", 70),
        ["Archive.ContainsScripts"]     = new("Archive.ContainsScripts",     "Scripts inside archive",     "Archive includes scripts (.ps1/.sh/.bat/.js).", "Archive", 60),
        ["Archive.ContainsArchives"]    = new("Archive.ContainsArchives",    "Nested archives",            "Archive contains nested archive files.", "Archive", 45),
        ["Archive.DisguisedExecutables"] = new("Archive.DisguisedExecutables","Disguised executables",     "Container holds executables disguised by extension.", "Archive", 75),
        ["Archive.EncryptedEntries"]    = new("Archive.EncryptedEntries",    "Encrypted entries",          "Archive has password-protected items.", "Archive", 50),

        // Office/PDF
        ["Office.Macros"]        = new("Office.Macros",        "Office macros",           "OOXML document contains macros (vbaProject.bin).", "OOXML", 80),
        ["Office.Encrypted"]     = new("Office.Encrypted",     "Office encrypted",        "Office document is encrypted (requires password).", "OOXML", 75),
        ["Office.ExternalLinks"] = new("Office.ExternalLinks",  "Excel external links",    "Workbook references external links.", "OOXML", 35),
        ["Office.RemoteTemplate"] = new("Office.RemoteTemplate","Remote template",         "Document references a remote template.", "OOXML", 70),
        ["Office.PossibleDde"]   = new("Office.PossibleDde",    "Possible DDE",             "Possible DDE/DDEAUTO field instructions present.", "OOXML", 60),

        ["Pdf.JavaScript"]       = new("Pdf.JavaScript",       "PDF JavaScript",          "PDF contains JavaScript.", "PDF", 65),
        ["Pdf.OpenAction"]       = new("Pdf.OpenAction",       "PDF OpenAction",          "PDF defines OpenAction (auto-run on open).", "PDF", 55),
        ["Pdf.Launch"]           = new("Pdf.Launch",           "PDF Launch",              "PDF includes a Launch action.", "PDF", 60),
        ["Pdf.NamesTree"]        = new("Pdf.NamesTree",        "PDF Names tree",          "PDF includes a Names tree.", "PDF", 25),
        ["Pdf.Xfa"]              = new("Pdf.Xfa",              "PDF XFA",                 "PDF contains XFA forms.", "PDF", 30),
        ["Pdf.Encrypted"]        = new("Pdf.Encrypted",        "PDF encrypted",           "PDF is encrypted.", "PDF", 35),
        ["Pdf.ManyUpdates"]      = new("Pdf.ManyUpdates",      "PDF many updates",        "PDF appears to have many incremental updates.", "PDF", 20),

        // PE
        ["PE.PackerSuspect"]     = new("PE.PackerSuspect",     "PE possibly packed",      "PE appears packed (e.g., UPX section names).", "PE", 60),
        ["PE.NoASLR"]            = new("PE.NoASLR",            "PE: no ASLR",            "PE optional header lacks ASLR (DYNAMIC_BASE).", "PE", 40),
        ["PE.NoNX"]              = new("PE.NoNX",              "PE: no NX/DEP",          "PE optional header lacks NX/DEP (NX_COMPAT).", "PE", 50),
        ["PE.NoCFG"]             = new("PE.NoCFG",             "PE: no CFG",             "PE optional header lacks Control Flow Guard.", "PE", 40),
        ["PE.NoHighEntropyVA"]   = new("PE.NoHighEntropyVA",   "PE: no HighEntropyVA",   "64-bit PE lacks HighEntropyVA hardening.", "PE", 20),

        // Signature/vendor signals
        ["Sig.SelfSigned"]       = new("Sig.SelfSigned",       "Self-signed signature",   "Signature is self-signed.", "Signature", 60),
        ["Sig.ChainInvalid"]     = new("Sig.ChainInvalid",     "Invalid signature chain", "Certificate chain did not build to a trusted root.", "Signature", 70),
        ["Sig.VendorAllowed"]    = new("Sig.VendorAllowed",    "Allowed vendor",         "Signer/vendor is in the allowed list (reduces score).", "Signature", 0),
        ["Sig.VendorUnknown"]    = new("Sig.VendorUnknown",    "Unknown vendor",         "Signed but vendor could not be determined.", "Signature", 10),

        // Packages
        ["Package.VendorPresent"]  = new("Package.VendorPresent",  "Package vendor present",  "Installer/package declares a vendor name.", "Package", 0),
        ["Package.VendorAllowed"]  = new("Package.VendorAllowed",  "Allowed vendor (package)", "Package vendor is allowed (reduces score).", "Package", 0),
        ["Package.VendorUnknown"]  = new("Package.VendorUnknown",  "Unknown package vendor",  "Installer detected but vendor fields are missing.", "Package", 10),
        ["Msi.CustomActionExe"]    = new("Msi.CustomActionExe",    "MSI custom action (EXE)", "MSI contains EXE custom actions.", "Package", 50),
        ["Msi.CustomActionScript"] = new("Msi.CustomActionScript", "MSI custom action (script)", "MSI contains scripted custom actions.", "Package", 50),
        ["Msi.CustomActionDll"]    = new("Msi.CustomActionDll",    "MSI custom action (DLL)", "MSI contains DLL custom actions.", "Package", 25),

        // Appx/MSIX
        ["Appx.Capability.RunFullTrust"]      = new("Appx.Capability.RunFullTrust", "MSIX RunFullTrust", "Appx/MSIX requests runFullTrust capability.", "Package", 50),
        ["Appx.Capability.BroadFileSystemAccess"] = new("Appx.Capability.BroadFileSystemAccess", "MSIX BroadFileSystemAccess", "Appx/MSIX requests broadFileSystemAccess.", "Package", 45),
        ["Appx.Extension.Protocol"]           = new("Appx.Extension.Protocol", "MSIX protocol handler", "Appx/MSIX registers a custom URL protocol.", "Package", 10),
        ["Appx.Extension.FTA"]                = new("Appx.Extension.FTA",      "MSIX file associations", "Appx/MSIX declares file type associations.", "Package", 10),
    };

    /// <summary>Returns a stable, typed legend for assessment codes.</summary>
    public static IReadOnlyList<LegendEntry> GetLegend() => s_codes.Values
        .OrderByDescending(e => e.Severity ?? 0)
        .ThenBy(e => e.Short, StringComparer.OrdinalIgnoreCase)
        .ToList();

    /// <summary>Humanizes a list of assessment codes.</summary>
    public static string HumanizeCodes(IEnumerable<string>? codes, HumanizeStyle style = HumanizeStyle.Short, string separator = ", ")
    {
        if (codes == null) return string.Empty;
        var labels = new List<string>();
        foreach (var c in codes)
        {
            if (string.IsNullOrWhiteSpace(c)) continue;
            if (s_codes.TryGetValue(c, out var entry)) labels.Add(style == HumanizeStyle.Long ? entry.Long : entry.Short);
            else labels.Add(c);
        }
        return string.Join(separator, labels);
    }
}

