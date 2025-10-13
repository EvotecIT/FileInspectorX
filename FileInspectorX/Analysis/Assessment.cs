namespace FileInspectorX;

/// <summary>
/// Coarse decision for consumers that want a simple gate. Generic: no environment/tier semantics.
/// </summary>
public enum AssessmentDecision
{
    Allow = 0,
    Warn = 1,
    Block = 2,
    Defer = 3
}

/// <summary>
/// Compact risk assessment for a single file. Carry a score (0-100), a decision, and stable finding codes.
/// </summary>
public sealed class AssessmentResult
{
    /// <summary>0 (no risk) to 100 (maximum risk).</summary>
    public int Score { get; set; }
    /// <summary>Allow/Warn/Block/Defer decision, computed from Score and signals.</summary>
    public AssessmentDecision Decision { get; set; } = AssessmentDecision.Allow;
    /// <summary>Short, stable codes describing the drivers behind the decision (e.g., "Archive.PathTraversal").</summary>
    public IReadOnlyList<string> Codes { get; set; } = Array.Empty<string>();
}

public static partial class FileInspector
{
    /// <summary>
    /// Computes a coarse risk score (0-100) and decision from <see cref="FileAnalysis"/>.
    /// The mapping is intentionally generic; consumers can layer their own policy thresholds.
    /// </summary>
    public static AssessmentResult Assess(FileAnalysis a)
    {
        int score = 0; var codes = new List<string>(16);

        // Containers and archives
        if ((a.Flags & ContentFlags.ArchiveHasPathTraversal) != 0) { score += 40; codes.Add("Archive.PathTraversal"); }
        if ((a.Flags & ContentFlags.ArchiveHasSymlinks) != 0) { score += 20; codes.Add("Archive.Symlink"); }
        if ((a.Flags & ContentFlags.ArchiveHasAbsolutePaths) != 0) { score += 15; codes.Add("Archive.AbsolutePath"); }
        if ((a.Flags & ContentFlags.ContainerContainsExecutables) != 0) { score += 25; codes.Add("Archive.ContainsExecutables"); }
        if ((a.Flags & ContentFlags.ContainerContainsScripts) != 0) { score += 20; codes.Add("Archive.ContainsScripts"); }
        if ((a.Flags & ContentFlags.ContainerContainsArchives) != 0) { score += 15; codes.Add("Archive.ContainsArchives"); }

        // Documents with active content
        if ((a.Flags & ContentFlags.HasOoxmlMacros) != 0) { score += 30; codes.Add("Office.Macros"); }
        if ((a.Flags & ContentFlags.PdfHasJavaScript) != 0) { score += 20; codes.Add("Pdf.JavaScript"); }
        if ((a.Flags & ContentFlags.PdfHasOpenAction) != 0) { score += 15; codes.Add("Pdf.OpenAction"); }
        if ((a.Flags & ContentFlags.PdfHasLaunch) != 0) { score += 20; codes.Add("Pdf.Launch"); }
        if ((a.Flags & ContentFlags.PdfHasNamesTree) != 0) { score += 10; codes.Add("Pdf.NamesTree"); }
        if ((a.Flags & ContentFlags.PdfHasXfa) != 0) { score += 10; codes.Add("Pdf.Xfa"); }
        if ((a.Flags & ContentFlags.PdfEncrypted) != 0) { score += 10; codes.Add("Pdf.Encrypted"); }
        if ((a.Flags & ContentFlags.PdfManyIncrementalUpdates) != 0) { score += 5; codes.Add("Pdf.ManyUpdates"); }
        if ((a.Flags & ContentFlags.OfficeExternalLinks) != 0) { score += 5; codes.Add("Office.ExternalLinks"); }

        // Executables
        if ((a.Flags & ContentFlags.PeLooksPackedUpx) != 0) { score += 20; codes.Add("PE.PackerSuspect"); }
        if ((a.Flags & ContentFlags.PeHasAuthenticode) != 0 && (a.Signature?.IsSigned == true)) { /* neutral */ }

        // Signature quality (if present on PE or package)
        var sig = a.Authenticode;
        if (sig != null)
        {
            if (sig.IsSelfSigned == true) { score += 20; codes.Add("Sig.SelfSigned"); }
            if (sig.ChainValid == false) { score += 25; codes.Add("Sig.ChainInvalid"); }
            if (sig.EnvelopeSignatureValid == false) { score += 15; codes.Add("Sig.BadEnvelope"); }
        }

        // Scripts/text cues (neutral codes from SecurityFindings)
        foreach (var f in a.SecurityFindings ?? Array.Empty<string>())
        {
            switch (f)
            {
                case "ps:encoded": score += 25; codes.Add("Script.Encoded"); break;
                case "ps:iex": score += 20; codes.Add("Script.IEX"); break;
                case "ps:web-dl": score += 15; codes.Add("Script.WebDownload"); break;
                case "ps:reflection": score += 10; codes.Add("Script.Reflection"); break;
                case "py:exec-b64": score += 20; codes.Add("Script.PyExecB64"); break;
                case "py:exec": score += 10; codes.Add("Script.PyExec"); break;
                case "rb:eval": score += 10; codes.Add("Script.RbEval"); break;
                case "lua:exec": score += 10; codes.Add("Script.LuaExec"); break;
                case "sig:mkatz": score += 30; codes.Add("Sig.MimikatzEncodedHint"); break;
                case "sig:sekurlsa": score += 30; codes.Add("Sig.SekurlsaEncodedHint"); break;
                case "secret:privkey": score += 40; codes.Add("Secret.PrivateKey"); break;
                case "secret:jwt": score += 25; codes.Add("Secret.JWT"); break;
                case "secret:keypattern": score += 15; codes.Add("Secret.KeyPattern"); break;
            }
        }

        // Name/path issues
        if ((a.NameIssues & NameIssues.DoubleExtension) != 0) { score += 15; codes.Add("Name.DoubleExtension"); }
        if ((a.NameIssues & NameIssues.BiDiOverride) != 0) { score += 25; codes.Add("Name.BiDiOverride"); }
        if ((a.NameIssues & NameIssues.ExtensionMismatch) != 0) { score += 10; codes.Add("Name.ExtensionMismatch"); }

        // Package vendor presence / allow-list hints
        string? pkgVendor = a.Installer?.PublisherDisplayName ?? a.Installer?.Publisher ?? a.Installer?.Manufacturer;
        if (!string.IsNullOrWhiteSpace(pkgVendor))
        {
            codes.Add("Package.VendorPresent");
            if (IsAllowedVendor(pkgVendor)) { codes.Add("Package.VendorAllowed"); score = Math.Max(0, score - 15); }
        }
        else if (a.Installer != null)
        {
            // Installer detected but vendor fields missing
            codes.Add("Package.VendorUnknown");
        }
        // Signature vendor allow
        var sigCn = a.Authenticode?.SignerSubjectCN; var sigOrg = a.Authenticode?.SignerSubjectO;
        if (!string.IsNullOrWhiteSpace(sigCn) && IsAllowedVendor(sigCn)) { codes.Add("Sig.VendorAllowed"); score = Math.Max(0, score - 10); }
        else if (!string.IsNullOrWhiteSpace(sigOrg) && IsAllowedVendor(sigOrg)) { codes.Add("Sig.VendorAllowed"); score = Math.Max(0, score - 10); }
        else if (a.Authenticode?.Present == true)
        {
            // Signed object but no recognizable vendor name components
            if (string.IsNullOrWhiteSpace(sigCn) && string.IsNullOrWhiteSpace(sigOrg)) codes.Add("Sig.VendorUnknown");
        }

        // MSI CustomActions (Windows-only data)
        var ca = a.Installer?.MsiCustomActions;
        if (ca != null)
        {
            if (ca.CountExe > 0) { codes.Add("Msi.CustomActionExe"); score += 20; }
            if (ca.CountScript > 0) { codes.Add("Msi.CustomActionScript"); score += 20; }
            if (ca.CountDll > 0) { codes.Add("Msi.CustomActionDll"); score += 10; }
        }

        // Appx/MSIX capabilities and extensions
        var caps = a.Installer?.Capabilities;
        if (caps != null)
        {
            foreach (var c in caps)
            {
                if (c.IndexOf("runFullTrust", StringComparison.OrdinalIgnoreCase) >= 0) { codes.Add("Appx.Capability.RunFullTrust"); score += 20; }
                if (c.IndexOf("broadFileSystemAccess", StringComparison.OrdinalIgnoreCase) >= 0) { codes.Add("Appx.Capability.BroadFileSystemAccess"); score += 15; }
            }
        }
        var exts = a.Installer?.Extensions;
        if (exts != null)
        {
            foreach (var e in exts)
            {
                if (e.IndexOf("windows.protocol", StringComparison.OrdinalIgnoreCase) >= 0) { codes.Add("Appx.Extension.Protocol"); score += 5; }
                if (e.IndexOf("filetypeassociation", StringComparison.OrdinalIgnoreCase) >= 0) { codes.Add("Appx.Extension.FTA"); score += 5; }
            }
        }

        // Guardrails and clamp
        if (score < 0) score = 0; if (score > 100) score = 100;
        var decision = score >= Settings.AssessmentBlockThreshold ? AssessmentDecision.Block : (score >= Settings.AssessmentWarnThreshold ? AssessmentDecision.Warn : AssessmentDecision.Allow);

        return new AssessmentResult { Score = score, Decision = decision, Codes = codes };
    }

    private static bool IsAllowedVendor(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return false;
        try {
            var list = Settings.AllowedVendors ?? Array.Empty<string>();
            foreach (var v in list)
            {
                if (string.IsNullOrWhiteSpace(v)) continue;
                if (Settings.VendorMatchMode == VendorMatchMode.Exact)
                {
                    if (string.Equals(name, v, StringComparison.OrdinalIgnoreCase)) return true;
                }
                else
                {
                    var nn = name!;
                    if (nn.IndexOf(v, StringComparison.OrdinalIgnoreCase) >= 0) return true;
                }
            }
        } catch { }
        return false;
    }
}
