namespace FileInspectorX;

/// <summary>
/// Coarse decision for consumers that want a simple gate. Generic: no environment/tier semantics.
/// </summary>
public enum AssessmentDecision
{
    /// <summary>
    /// The file appears acceptable based on current signals and thresholds.
    /// </summary>
    Allow = 0,
    /// <summary>
    /// The file contains noteworthy signals; proceed with caution or additional review.
    /// </summary>
    Warn = 1,
    /// <summary>
    /// The file exhibits high‑risk traits; recommended to block by default.
    /// </summary>
    Block = 2,
    /// <summary>
    /// Decision is deferred to a higher‑level policy or human review.
    /// </summary>
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
    /// <summary>
    /// Breakdown of score contributions by code. Keys mirror entries in <see cref="Codes"/> and values are the weights added to the total score.
    /// </summary>
    public IReadOnlyDictionary<string,int> Factors { get; set; } = new Dictionary<string,int>();
}

public static partial class FileInspector
{
    /// <summary>
    /// Computes a coarse risk score (0-100) and decision from <see cref="FileAnalysis"/>.
    /// The mapping is intentionally generic; consumers can layer their own policy thresholds.
    /// </summary>
    public static AssessmentResult Assess(FileAnalysis a)
    {
        int score = 0; var codes = new List<string>(32); var factors = new Dictionary<string,int>(32);

        void Add(string code, int weight)
        {
            score += weight; codes.Add(code); factors[code] = weight;
        }

        // Containers and archives
        if ((a.Flags & ContentFlags.ArchiveHasPathTraversal) != 0) Add("Archive.PathTraversal", 40);
        if ((a.Flags & ContentFlags.ArchiveHasSymlinks) != 0) Add("Archive.Symlink", 20);
        if ((a.Flags & ContentFlags.ArchiveHasAbsolutePaths) != 0) Add("Archive.AbsolutePath", 15);
        if ((a.Flags & ContentFlags.ContainerContainsExecutables) != 0) Add("Archive.ContainsExecutables", 25);
        if ((a.Flags & ContentFlags.ContainerContainsScripts) != 0) Add("Archive.ContainsScripts", 20);
        if ((a.Flags & ContentFlags.ContainerContainsArchives) != 0) Add("Archive.ContainsArchives", 15);
        if ((a.Flags & ContentFlags.ContainerHasDisguisedExecutables) != 0) Add("Archive.DisguisedExecutables", 25);

        // Documents with active content
        if ((a.Flags & ContentFlags.HasOoxmlMacros) != 0) Add("Office.Macros", 30);
        if ((a.Flags & ContentFlags.PdfHasJavaScript) != 0) Add("Pdf.JavaScript", 20);
        if ((a.Flags & ContentFlags.PdfHasOpenAction) != 0) Add("Pdf.OpenAction", 15);
        if ((a.Flags & ContentFlags.PdfHasLaunch) != 0) Add("Pdf.Launch", 20);
        if ((a.Flags & ContentFlags.PdfHasNamesTree) != 0) Add("Pdf.NamesTree", 10);
        if ((a.Flags & ContentFlags.PdfHasXfa) != 0) Add("Pdf.Xfa", 10);
        if ((a.Flags & ContentFlags.PdfEncrypted) != 0) Add("Pdf.Encrypted", 10);
        if ((a.Flags & ContentFlags.ArchiveHasEncryptedEntries) != 0) Add("Archive.EncryptedEntries", 10);
        if ((a.Flags & ContentFlags.OoxmlEncrypted) != 0) Add("Office.Encrypted", 15);
        if ((a.Flags & ContentFlags.PdfManyIncrementalUpdates) != 0) Add("Pdf.ManyUpdates", 5);
        if ((a.Flags & ContentFlags.OfficeExternalLinks) != 0) Add("Office.ExternalLinks", 5);
        if ((a.Flags & ContentFlags.HtmlHasExternalLinks) != 0) Add("Html.ExternalLinks", 5);
        if ((a.Flags & ContentFlags.OfficeRemoteTemplate) != 0) Add("Office.RemoteTemplate", 25);
        if ((a.Flags & ContentFlags.OfficePossibleDde) != 0) Add("Office.PossibleDde", 15);

        // Executables
        if ((a.Flags & ContentFlags.PeLooksPackedUpx) != 0) Add("PE.PackerSuspect", 20);
        if ((a.Flags & ContentFlags.PeHasAuthenticode) != 0 && (a.Signature?.IsSigned == true)) { /* neutral */ }
        if ((a.Flags & ContentFlags.PeNoAslr) != 0) Add("PE.NoASLR", 15);
        if ((a.Flags & ContentFlags.PeNoNx) != 0) Add("PE.NoNX", 20);
        if ((a.Flags & ContentFlags.PeNoCfg) != 0) Add("PE.NoCFG", 15);
        if ((a.Flags & ContentFlags.PeNoHighEntropyVa) != 0 && (a.PeMachine != null && a.PeMachine.IndexOf("64", StringComparison.OrdinalIgnoreCase) >= 0)) Add("PE.NoHighEntropyVA", 5);

        // Signature quality (if present on PE or package)
        var sig = a.Authenticode;
        if (sig != null)
        {
            if (sig.IsSelfSigned == true) Add("Sig.SelfSigned", 20);
            if (sig.ChainValid == false) Add("Sig.ChainInvalid", 25);
            if (sig.EnvelopeSignatureValid == false) Add("Sig.BadEnvelope", 15);
            if (sig.IsTrustedWindowsPolicy == false) Add("Sig.WinTrustInvalid", 25);
            if (sig.TimestampPresent == false) Add("Sig.NoTimestamp", 5);
        }
        else
        {
            var ext = a.Detection?.Extension?.ToLowerInvariant();
            if (ext is "exe" or "dll") Add("Sig.Absent", 10);
        }

        // Scripts/text cues (neutral codes from SecurityFindings)
        foreach (var f in a.SecurityFindings ?? Array.Empty<string>())
        {
            switch (f)
            {
                case var t when t != null && t.StartsWith("tool:"): Add("Tool.Indicator", 10); break;
                case "ps:encoded": Add("Script.Encoded", 25); break;
                case "ps:iex": Add("Script.IEX", 20); break;
                case "ps:web-dl": Add("Script.WebDownload", 15); break;
                case "ps:reflection": Add("Script.Reflection", 10); break;
                case "py:exec-b64": Add("Script.PyExecB64", 20); break;
                case "py:exec": Add("Script.PyExec", 10); break;
                case "rb:eval": Add("Script.RbEval", 10); break;
                case "lua:exec": Add("Script.LuaExec", 10); break;
                case "sig:mkatz": Add("Sig.MimikatzEncodedHint", 30); break;
                case "sig:sekurlsa": Add("Sig.SekurlsaEncodedHint", 30); break;
                case "secret:privkey": Add("Secret.PrivateKey", 40); break;
                case "secret:jwt": Add("Secret.JWT", 25); break;
                case "secret:keypattern": Add("Secret.KeyPattern", 15); break;
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
            if (IsAllowedVendor(pkgVendor)) { codes.Add("Package.VendorAllowed"); factors["Package.VendorAllowed"] = -15; score = Math.Max(0, score - 15); }
        }
        else if (a.Installer != null)
        {
            // Installer detected but vendor fields missing
            codes.Add("Package.VendorUnknown");
        }
        // Signature vendor allow
        var sigCn = a.Authenticode?.SignerSubjectCN; var sigOrg = a.Authenticode?.SignerSubjectO;
        if (!string.IsNullOrWhiteSpace(sigCn) && IsAllowedVendor(sigCn)) { codes.Add("Sig.VendorAllowed"); factors["Sig.VendorAllowed"] = -10; score = Math.Max(0, score - 10); }
        else if (!string.IsNullOrWhiteSpace(sigOrg) && IsAllowedVendor(sigOrg)) { codes.Add("Sig.VendorAllowed"); factors["Sig.VendorAllowed"] = -10; score = Math.Max(0, score - 10); }
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
        if (string.Equals(a.Installer?.Scope, "PerUser", StringComparison.OrdinalIgnoreCase)) { codes.Add("Msi.PerUser"); score += 5; }
        if (!string.IsNullOrWhiteSpace(a.Installer?.UrlInfoAbout) || !string.IsNullOrWhiteSpace(a.Installer?.UrlUpdateInfo) || !string.IsNullOrWhiteSpace(a.Installer?.SupportUrl))
        { codes.Add("Msi.UrlsPresent"); score += 2; }
        if (a.SecurityFindings != null && a.SecurityFindings.Any(s => string.Equals(s, "pe:regsvr", StringComparison.OrdinalIgnoreCase)))
        { codes.Add("PE.RegSvrExport"); score += 10; }

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

        return new AssessmentResult { Score = score, Decision = decision, Codes = codes, Factors = factors };
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
