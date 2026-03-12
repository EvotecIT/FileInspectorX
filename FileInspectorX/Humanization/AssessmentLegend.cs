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
        ["Archive.ContainsInstallers"]  = new("Archive.ContainsInstallers",  "Installers inside archive",  "Archive includes installer or package files.", "Archive", 65),
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
        ["PE.RegSvrExport"]      = new("PE.RegSvrExport",      "PE registration export", "PE exports self-registration entry points often used by COM registration flows.", "PE", 30),

        // Signature/vendor signals
        ["Sig.SelfSigned"]       = new("Sig.SelfSigned",       "Self-signed signature",   "Signature is self-signed.", "Signature", 60),
        ["Sig.ChainInvalid"]     = new("Sig.ChainInvalid",     "Invalid signature chain", "Certificate chain did not build to a trusted root.", "Signature", 70),
        ["Sig.BadEnvelope"]      = new("Sig.BadEnvelope",      "Invalid signature envelope", "Signature envelope or digest validation failed.", "Signature", 55),
        ["Sig.WinTrustInvalid"]  = new("Sig.WinTrustInvalid",  "Windows trust policy failed", "Signature did not validate under Windows trust policy.", "Signature", 70),
        ["Sig.NoTimestamp"]      = new("Sig.NoTimestamp",      "Missing timestamp",       "Signature is present but no trusted timestamp was found.", "Signature", 20),
        ["Sig.Absent"]           = new("Sig.Absent",           "Unsigned executable or package", "Executable or installer-like content has no signature.", "Signature", 45),
        ["Sig.VendorAllowed"]    = new("Sig.VendorAllowed",    "Allowed vendor",         "Signer/vendor is in the allowed list (reduces score).", "Signature", 0),
        ["Sig.VendorUnknown"]    = new("Sig.VendorUnknown",    "Unknown vendor",         "Signed but vendor could not be determined.", "Signature", 10),

        // Packages
        ["Package.VendorPresent"]  = new("Package.VendorPresent",  "Package vendor present",  "Installer/package declares a vendor name.", "Package", 0),
        ["Package.VendorAllowed"]  = new("Package.VendorAllowed",  "Allowed vendor (package)", "Package vendor is allowed (reduces score).", "Package", 0),
        ["Package.VendorUnknown"]  = new("Package.VendorUnknown",  "Unknown package vendor",  "Installer detected but vendor fields are missing.", "Package", 10),
        ["Msi.CustomActionExe"]    = new("Msi.CustomActionExe",    "MSI custom action (EXE)", "MSI contains EXE custom actions.", "Package", 50),
        ["Msi.CustomActionScript"] = new("Msi.CustomActionScript", "MSI custom action (script)", "MSI contains scripted custom actions.", "Package", 50),
        ["Msi.CustomActionDll"]    = new("Msi.CustomActionDll",    "MSI custom action (DLL)", "MSI contains DLL custom actions.", "Package", 25),
        ["Msi.PerUser"]            = new("Msi.PerUser",            "Per-user installer", "Installer is scoped per-user instead of machine-wide.", "Package", 10),
        ["Msi.UrlsPresent"]        = new("Msi.UrlsPresent",        "Installer URLs present", "Installer metadata includes support, update, or contact URLs.", "Package", 5),

        // Appx/MSIX
        ["Appx.Capability.RunFullTrust"]      = new("Appx.Capability.RunFullTrust", "MSIX RunFullTrust", "Appx/MSIX requests runFullTrust capability.", "Package", 50),
        ["Appx.Capability.BroadFileSystemAccess"] = new("Appx.Capability.BroadFileSystemAccess", "MSIX BroadFileSystemAccess", "Appx/MSIX requests broadFileSystemAccess.", "Package", 45),
        ["Appx.Extension.Protocol"]           = new("Appx.Extension.Protocol", "MSIX protocol handler", "Appx/MSIX registers a custom URL protocol.", "Package", 10),
        ["Appx.Extension.FTA"]                = new("Appx.Extension.FTA",      "MSIX file associations", "Appx/MSIX declares file type associations.", "Package", 10),

        // Encoded content
        ["Encoded.Present"]        = new("Encoded.Present",        "Encoded content present",   "Text or file appears to contain encoded payload (base64/hex/base85/uu).", "Content", 40),
        ["Encoded.InnerExecutable"] = new("Encoded.InnerExecutable", "Encoded inner executable",  "Decoded payload contains an executable module.", "Content", 60),
        ["Encoded.InnerScript"]     = new("Encoded.InnerScript",     "Encoded inner script",      "Decoded payload contains a script.", "Content", 50),
        ["Encoded.Embedded"]        = new("Encoded.Embedded",        "Embedded data URIs",        "HTML/script contains embedded base64 data URIs.", "Content", 35),
        ["Encoded.EmbeddedExecutable"] = new("Encoded.EmbeddedExecutable", "Embedded executable payload", "Embedded HTML/script data URIs decode to executable or package content.", "Content", 60),
        ["Encoded.EmbeddedScript"]     = new("Encoded.EmbeddedScript",     "Embedded script payload",     "Embedded HTML/script data URIs decode to script content.", "Content", 50),
        ["Script.Encoded"]            = new("Script.Encoded", "Encoded script invocation", "Script includes encoded-command or base64 decode patterns associated with payload staging.", "Content", 55),
        ["Script.IEX"]                = new("Script.IEX", "Dynamic expression execution", "Script invokes expression-style runtime execution.", "Content", 50),
        ["Script.WebDownload"]        = new("Script.WebDownload", "Web download behavior", "Script downloads content from web endpoints at runtime.", "Content", 45),
        ["Script.Reflection"]         = new("Script.Reflection", "Reflection-based loading", "Script uses reflection or runtime type loading patterns.", "Content", 40),
        ["Script.CertutilDecode"]     = new("Script.CertutilDecode", "certutil decode", "Script uses certutil decode behavior associated with payload reconstruction.", "Content", 45),
        ["Script.Mshta"]              = new("Script.Mshta", "mshta execution", "Script references mshta-style HTML application execution.", "Content", 55),
        ["Script.ActiveX"]            = new("Script.ActiveX", "ActiveX/COM script", "Script uses ActiveX or COM automation patterns associated with payload delivery.", "Content", 50),
        ["Script.FromCharCode"]       = new("Script.FromCharCode", "String assembly obfuscation", "Script builds long strings through repeated character-code assembly.", "Content", 40),
        ["Script.PyExecB64"]          = new("Script.PyExecB64", "Python base64 execution", "Python script combines runtime execution with base64 decoding.", "Content", 50),
        ["Script.PyExec"]             = new("Script.PyExec", "Python process execution", "Python script launches commands or subprocesses.", "Content", 40),
        ["Script.RbEval"]             = new("Script.RbEval", "Ruby eval or exec", "Ruby script uses eval, exec, or remote open patterns.", "Content", 40),
        ["Script.LuaExec"]            = new("Script.LuaExec", "Lua runtime execution", "Lua script uses loadstring or operating-system command execution.", "Content", 40),
        ["Script.UncShares"]          = new("Script.UncShares", "UNC share references", "Script references one or more UNC shares or remote administrative paths.", "Content", 30),
        ["Script.NetworkDriveMapping"] = new("Script.NetworkDriveMapping", "Network drive mapping", "Script maps or mounts remote network shares.", "Content", 35),
        ["Script.ExternalHosts"]      = new("Script.ExternalHosts", "External host references", "Script references one or more external network hosts.", "Content", 45),

        // Naming and file identity
        ["Html.ExternalLinks"]        = new("Html.ExternalLinks", "HTML external links", "HTML content references external links.", "Markup", 15),
        ["Name.DoubleExtension"]      = new("Name.DoubleExtension", "Double extension", "Filename uses multiple extensions that can disguise the true content type.", "Identity", 35),
        ["Name.BiDiOverride"]         = new("Name.BiDiOverride", "BiDi override in name", "Filename contains bidirectional override characters that can disguise the visible extension.", "Identity", 50),
        ["Name.ExtensionMismatch"]    = new("Name.ExtensionMismatch", "Extension mismatch", "Filename extension does not align with detected content type.", "Identity", 25),

        // Operational/tooling cues
        ["DotNet.StrongName"]         = new("DotNet.StrongName", ".NET strong name present", ".NET assembly carries a strong-name signature, which slightly lowers risk.", "DotNet", 0),
        ["DotNet.NoStrongName"]       = new("DotNet.NoStrongName", ".NET without strong name", ".NET assembly lacks a strong-name signature.", "DotNet", 15),
        ["Tool.Indicator"]            = new("Tool.Indicator", "Administrative tool indicator", "Content references a built-in administrative or dual-use tool name.", "Content", 25),

        // Secrets
        ["Secret.PrivateKey"]       = new("Secret.PrivateKey",       "Private key material",      "File appears to contain private key material.", "Secrets", 90),
        ["Secret.PrivateKey.Volume"] = new("Secret.PrivateKey.Volume","Multiple private keys",     "Multiple private key indicators increased risk weight.", "Secrets", 95),
        ["Secret.JWT"]              = new("Secret.JWT",              "JWT-like token",            "File contains tokens resembling JSON Web Tokens.", "Secrets", 60),
        ["Secret.JWT.Volume"]       = new("Secret.JWT.Volume",       "Multiple JWT-like tokens",  "Multiple JWT-like tokens increased risk weight.", "Secrets", 70),
        ["Secret.KeyPattern"]       = new("Secret.KeyPattern",       "Key/secret pattern",        "File contains long key=/secret=/password= token patterns.", "Secrets", 50),
        ["Secret.KeyPattern.Volume"] = new("Secret.KeyPattern.Volume","Multiple key patterns",     "Multiple key/secret patterns increased risk weight.", "Secrets", 60),
        ["Secret.TokenFamily"]      = new("Secret.TokenFamily",      "Token-family secret",       "File contains known API token-family formats (e.g., GitHub/AWS/Slack-like).", "Secrets", 70),
        ["Secret.TokenFamily.Volume"] = new("Secret.TokenFamily.Volume","Multiple token-family secrets","Multiple token-family secret indicators increased risk weight.", "Secrets", 80),
        ["Secret.TokenFamily.GitHub"] = new("Secret.TokenFamily.GitHub", "GitHub token-family", "File contains token patterns matching GitHub token families.", "Secrets", 75),
        ["Secret.TokenFamily.GitHub.Volume"] = new("Secret.TokenFamily.GitHub.Volume", "Multiple GitHub token-family indicators", "Multiple GitHub token-family indicators increased risk weight.", "Secrets", 80),
        ["Secret.TokenFamily.GitLab"] = new("Secret.TokenFamily.GitLab", "GitLab token-family", "File contains token patterns matching GitLab token families.", "Secrets", 70),
        ["Secret.TokenFamily.GitLab.Volume"] = new("Secret.TokenFamily.GitLab.Volume", "Multiple GitLab token-family indicators", "Multiple GitLab token-family indicators increased risk weight.", "Secrets", 75),
        ["Secret.TokenFamily.AwsAccessKeyId"] = new("Secret.TokenFamily.AwsAccessKeyId", "AWS access key id", "File contains AWS access key id token-family patterns.", "Secrets", 50),
        ["Secret.TokenFamily.AwsAccessKeyId.Volume"] = new("Secret.TokenFamily.AwsAccessKeyId.Volume", "Multiple AWS access key ids", "Multiple AWS access key id indicators increased risk weight.", "Secrets", 55),
        ["Secret.TokenFamily.Slack"] = new("Secret.TokenFamily.Slack", "Slack token-family", "File contains token patterns matching Slack token families.", "Secrets", 75),
        ["Secret.TokenFamily.Slack.Volume"] = new("Secret.TokenFamily.Slack.Volume", "Multiple Slack token-family indicators", "Multiple Slack token-family indicators increased risk weight.", "Secrets", 80),
        ["Secret.TokenFamily.Stripe"] = new("Secret.TokenFamily.Stripe", "Stripe live key", "File contains token patterns matching Stripe live key families.", "Secrets", 75),
        ["Secret.TokenFamily.Stripe.Volume"] = new("Secret.TokenFamily.Stripe.Volume", "Multiple Stripe live key indicators", "Multiple Stripe live key indicators increased risk weight.", "Secrets", 80),
        ["Secret.TokenFamily.GcpApiKey"] = new("Secret.TokenFamily.GcpApiKey", "GCP API key", "File contains token patterns matching GCP API key families.", "Secrets", 55),
        ["Secret.TokenFamily.GcpApiKey.Volume"] = new("Secret.TokenFamily.GcpApiKey.Volume", "Multiple GCP API key indicators", "Multiple GCP API key indicators increased risk weight.", "Secrets", 60),
        ["Secret.TokenFamily.Npm"] = new("Secret.TokenFamily.Npm", "npm token-family", "File contains token patterns matching npm token families.", "Secrets", 70),
        ["Secret.TokenFamily.Npm.Volume"] = new("Secret.TokenFamily.Npm.Volume", "Multiple npm token-family indicators", "Multiple npm token-family indicators increased risk weight.", "Secrets", 75),
        ["Secret.TokenFamily.AzureSas"] = new("Secret.TokenFamily.AzureSas", "Azure SAS token", "File contains token patterns matching Azure SAS token families.", "Secrets", 75),
        ["Secret.TokenFamily.AzureSas.Volume"] = new("Secret.TokenFamily.AzureSas.Volume", "Multiple Azure SAS token indicators", "Multiple Azure SAS token indicators increased risk weight.", "Secrets", 80),
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

