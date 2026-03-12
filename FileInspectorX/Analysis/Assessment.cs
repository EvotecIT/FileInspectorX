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
/// Assessment profile used for parallel risk decisions over the same scoring factors.
/// </summary>
public enum AssessmentProfile
{
    /// <summary>More aggressive thresholds (earlier Warn/Block).</summary>
    Strict = 0,
    /// <summary>Default thresholds from settings.</summary>
    Balanced = 1,
    /// <summary>More permissive thresholds (later Warn/Block).</summary>
    Lenient = 2
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

/// <summary>
/// Multi-profile assessment view over one analyzed file.
/// Keeps the same score/factors and only varies the decision thresholds by profile.
/// </summary>
public sealed class MultiAssessmentResult
{
    /// <summary>Strict profile result.</summary>
    public AssessmentResult Strict { get; set; } = new AssessmentResult();
    /// <summary>Balanced profile result.</summary>
    public AssessmentResult Balanced { get; set; } = new AssessmentResult();
    /// <summary>Lenient profile result.</summary>
    public AssessmentResult Lenient { get; set; } = new AssessmentResult();
}

public static partial class FileInspector
{
    /// <summary>
    /// Computes assessment results for strict/balanced/lenient profiles using one shared score/factors baseline.
    /// </summary>
    public static MultiAssessmentResult AssessMulti(FileAnalysis a)
    {
        var balanced = Assess(a);
        return AssessMulti(balanced);
    }

    internal static MultiAssessmentResult AssessMulti(AssessmentResult balanced)
    {
        if (balanced == null) throw new ArgumentNullException(nameof(balanced));

        var strictDecision = DecideForProfile(balanced.Score, AssessmentProfile.Strict);
        var lenientDecision = DecideForProfile(balanced.Score, AssessmentProfile.Lenient);
        return new MultiAssessmentResult
        {
            Strict = CloneWithDecision(balanced, strictDecision),
            Balanced = CloneWithDecision(balanced, balanced.Decision),
            Lenient = CloneWithDecision(balanced, lenientDecision)
        };
    }

    /// <summary>
    /// Computes a coarse risk score (0-100) and decision from <see cref="FileAnalysis"/>.
    /// The mapping is intentionally generic; consumers can layer their own policy thresholds.
    /// </summary>
    public static AssessmentResult Assess(FileAnalysis a)
    {
        int score = 0; var codes = new List<string>(32); var factors = new Dictionary<string,int>(32);
        var securityFindings = a.SecurityFindings ?? Array.Empty<string>();

        void Add(string code, int weight)
        {
            if (string.IsNullOrWhiteSpace(code)) return;
            if (weight < 0) score = Math.Max(0, score + weight);
            else score += weight;
            if (factors.TryGetValue(code, out var existing))
            {
                factors[code] = existing + weight;
            }
            else
            {
                codes.Add(code);
                factors[code] = weight;
            }
        }

        var securityFindingCodes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void AddSecurityFindingCode(string code, int weight)
        {
            if (securityFindingCodes.Add(code)) Add(code, weight);
        }

        // Containers and archives
        bool hasDisguisedExecutables = (a.Flags & ContentFlags.ContainerHasDisguisedExecutables) != 0;
        bool isAppPackageContainer =
            a.Installer?.Kind is InstallerKind.Appx or InstallerKind.Msix ||
            string.Equals(a.ContainerSubtype, "appx", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(a.ContainerSubtype, "msix", StringComparison.OrdinalIgnoreCase);

        if ((a.Flags & ContentFlags.ArchiveHasPathTraversal) != 0) Add("Archive.PathTraversal", 40);
        if ((a.Flags & ContentFlags.ArchiveHasSymlinks) != 0) Add("Archive.Symlink", 20);
        if ((a.Flags & ContentFlags.ArchiveHasAbsolutePaths) != 0) Add("Archive.AbsolutePath", 15);
        if ((a.Flags & ContentFlags.ContainerContainsExecutables) != 0 && !hasDisguisedExecutables && !isAppPackageContainer) Add("Archive.ContainsExecutables", 25);
        if ((a.Flags & ContentFlags.ContainerContainsScripts) != 0 && !isAppPackageContainer) Add("Archive.ContainsScripts", 20);
        if ((a.Flags & ContentFlags.ContainerContainsArchives) != 0) Add("Archive.ContainsArchives", 15);
        if (hasDisguisedExecutables) Add("Archive.DisguisedExecutables", 25);

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

        // Encoded content signals
        if (!string.IsNullOrWhiteSpace(a.EncodedKind))
        {
            Add("Encoded.Present", 10);
            var innerExt = a.EncodedInnerDetection?.Extension?.ToLowerInvariant();
            if (!string.IsNullOrWhiteSpace(innerExt))
            {
                switch (innerExt)
                {
                    case "exe": case "dll": case "sys": case "ocx": case "cpl": case "scr": case "com": case "pif": case "msi": case "msp": case "msix": case "appx":
                        Add("Encoded.InnerExecutable", 20); break;
                    case "ps1": case "psm1": case "psd1": case "bat": case "cmd": case "sh": case "bash": case "zsh": case "js": case "vbs": case "vbe": case "wsf": case "wsh": case "py": case "rb":
                        Add("Encoded.InnerScript", 15); break;
                }
            }
        }
        // Embedded base64 data URIs in HTML/scripts
        if (securityFindings.Any(s => s.StartsWith("html:data-b64=", StringComparison.OrdinalIgnoreCase) || s.StartsWith("script:data-b64=", StringComparison.OrdinalIgnoreCase)))
        {
            Add("Encoded.Embedded", 10);
        }

        // Executables
        if ((a.Flags & ContentFlags.PeLooksPackedUpx) != 0) Add("PE.PackerSuspect", 20);
        if ((a.Flags & ContentFlags.PeHasAuthenticode) != 0 && (a.Signature?.IsSigned == true)) { /* neutral */ }
        if ((a.Flags & ContentFlags.PeNoAslr) != 0) Add("PE.NoASLR", 15);
        if ((a.Flags & ContentFlags.PeNoNx) != 0) Add("PE.NoNX", 20);
        if ((a.Flags & ContentFlags.PeNoCfg) != 0) Add("PE.NoCFG", 15);
        if ((a.Flags & ContentFlags.PeNoHighEntropyVa) != 0 && (a.PeMachine != null && a.PeMachine.IndexOf("64", StringComparison.OrdinalIgnoreCase) >= 0)) Add("PE.NoHighEntropyVA", 5);
        // .NET strong-name signal (mild weight)
        if ((a.Flags & ContentFlags.PeIsDotNet) != 0)
        {
            if (a.DotNetStrongNameSigned == true) { Add("DotNet.StrongName", -5); }
            else if (a.DotNetStrongNameSigned == false) { Add("DotNet.NoStrongName", 5); }
        }

        // Signature quality (if present on PE or package)
        var sig = a.Authenticode;
        if (sig?.Present == true)
        {
            bool hasPrimaryTrustFailure = false;
            bool hasSignatureFailure = false;
            if (sig.IsSelfSigned == true)
            {
                Add("Sig.SelfSigned", 20);
                hasPrimaryTrustFailure = true;
                hasSignatureFailure = true;
            }
            else if (sig.ChainValid == false)
            {
                Add("Sig.ChainInvalid", 25);
                hasPrimaryTrustFailure = true;
                hasSignatureFailure = true;
            }
            if (sig.EnvelopeSignatureValid == false)
            {
                Add("Sig.BadEnvelope", 15);
                hasSignatureFailure = true;
            }
            if (!hasPrimaryTrustFailure && sig.IsTrustedWindowsPolicy == false)
            {
                Add("Sig.WinTrustInvalid", 25);
                hasSignatureFailure = true;
            }
            if (!hasSignatureFailure && sig.TimestampPresent == false) Add("Sig.NoTimestamp", 5);
        }
        else
        {
            var ext = a.Detection?.Extension?.ToLowerInvariant();
            if (ext is "exe" or "dll" or "sys" or "ocx" or "cpl" or "scr" or "com" or "pif" or "msi" or "msp" or "msix" or "appx") Add("Sig.Absent", 10);
        }

        bool hasSpecificTokenFamilyFinding = securityFindings.Any(f =>
            f.StartsWith("secret:token:", StringComparison.OrdinalIgnoreCase));

        // Scripts/text cues (neutral codes from SecurityFindings)
        foreach (var f in securityFindings)
        {
            switch (f)
            {
                case var t when t != null && t.StartsWith("tool:"): AddSecurityFindingCode("Tool.Indicator", 10); break;
                case "ps:encoded": AddSecurityFindingCode("Script.Encoded", 25); break;
                case "ps:iex": AddSecurityFindingCode("Script.IEX", 20); break;
                case "ps:web-dl": AddSecurityFindingCode("Script.WebDownload", 15); break;
                case "ps:reflection": AddSecurityFindingCode("Script.Reflection", 10); break;
                case "py:exec-b64": AddSecurityFindingCode("Script.PyExecB64", 20); break;
                case "py:exec": AddSecurityFindingCode("Script.PyExec", 10); break;
                case "rb:eval": AddSecurityFindingCode("Script.RbEval", 10); break;
                case "lua:exec": AddSecurityFindingCode("Script.LuaExec", 10); break;
                case "sig:mkatz": AddSecurityFindingCode("Sig.MimikatzEncodedHint", 30); break;
                case "sig:sekurlsa": AddSecurityFindingCode("Sig.SekurlsaEncodedHint", 30); break;
                case "secret:privkey": AddSecurityFindingCode("Secret.PrivateKey", 40); break;
                case "secret:jwt": AddSecurityFindingCode("Secret.JWT", 25); break;
                case "secret:keypattern": AddSecurityFindingCode("Secret.KeyPattern", 15); break;
                case "secret:token":
                    if (!hasSpecificTokenFamilyFinding) AddSecurityFindingCode("Secret.TokenFamily", 30);
                    break;
                case "secret:token:github": AddSecurityFindingCode("Secret.TokenFamily.GitHub", 32); break;
                case "secret:token:gitlab": AddSecurityFindingCode("Secret.TokenFamily.GitLab", 28); break;
                case "secret:token:aws-akid": AddSecurityFindingCode("Secret.TokenFamily.AwsAccessKeyId", 14); break;
                case "secret:token:slack": AddSecurityFindingCode("Secret.TokenFamily.Slack", 32); break;
                case "secret:token:stripe": AddSecurityFindingCode("Secret.TokenFamily.Stripe", 32); break;
                case "secret:token:gcp-apikey": AddSecurityFindingCode("Secret.TokenFamily.GcpApiKey", 16); break;
                case "secret:token:npm": AddSecurityFindingCode("Secret.TokenFamily.Npm", 28); break;
                case "secret:token:azure-sas": AddSecurityFindingCode("Secret.TokenFamily.AzureSas", 30); break;
            }
        }

        // Secret counts add volume-aware weighting. This also covers callers that set Secrets directly.
        var secrets = a.Secrets;
        if (secrets != null)
        {
            ApplySecretCount("Secret.PrivateKey", secrets.PrivateKeyCount, baseWeight: 40, perExtraWeight: 8, maxExtraWeight: 24);
            ApplySecretCount("Secret.JWT", secrets.JwtLikeCount, baseWeight: 25, perExtraWeight: 4, maxExtraWeight: 16);
            ApplySecretCount("Secret.KeyPattern", secrets.KeyPatternCount, baseWeight: 15, perExtraWeight: 2, maxExtraWeight: 12);

            bool hasFamilyBreakdown = secrets.GitHubTokenCount > 0 || secrets.GitLabTokenCount > 0 ||
                                      secrets.AwsAccessKeyIdCount > 0 || secrets.SlackTokenCount > 0 ||
                                      secrets.StripeLiveKeyCount > 0 || secrets.GcpApiKeyCount > 0 ||
                                      secrets.NpmTokenCount > 0 || secrets.AzureSasTokenCount > 0;

            if (hasFamilyBreakdown)
            {
                ApplySecretCount("Secret.TokenFamily.GitHub", secrets.GitHubTokenCount, baseWeight: 32, perExtraWeight: 4, maxExtraWeight: 16);
                ApplySecretCount("Secret.TokenFamily.GitLab", secrets.GitLabTokenCount, baseWeight: 28, perExtraWeight: 3, maxExtraWeight: 14);
                ApplySecretCount("Secret.TokenFamily.AwsAccessKeyId", secrets.AwsAccessKeyIdCount, baseWeight: 14, perExtraWeight: 2, maxExtraWeight: 10);
                ApplySecretCount("Secret.TokenFamily.Slack", secrets.SlackTokenCount, baseWeight: 32, perExtraWeight: 4, maxExtraWeight: 16);
                ApplySecretCount("Secret.TokenFamily.Stripe", secrets.StripeLiveKeyCount, baseWeight: 32, perExtraWeight: 4, maxExtraWeight: 16);
                ApplySecretCount("Secret.TokenFamily.GcpApiKey", secrets.GcpApiKeyCount, baseWeight: 16, perExtraWeight: 2, maxExtraWeight: 10);
                ApplySecretCount("Secret.TokenFamily.Npm", secrets.NpmTokenCount, baseWeight: 28, perExtraWeight: 3, maxExtraWeight: 14);
                ApplySecretCount("Secret.TokenFamily.AzureSas", secrets.AzureSasTokenCount, baseWeight: 30, perExtraWeight: 4, maxExtraWeight: 16);
            }
            else if (!hasSpecificTokenFamilyFinding)
            {
                ApplySecretCount("Secret.TokenFamily", secrets.TokenFamilyCount, baseWeight: 30, perExtraWeight: 4, maxExtraWeight: 20);
            }
        }

        // Name/path issues
        if ((a.NameIssues & NameIssues.DoubleExtension) != 0) Add("Name.DoubleExtension", 15);
        if ((a.NameIssues & NameIssues.BiDiOverride) != 0) Add("Name.BiDiOverride", 25);
        if ((a.NameIssues & NameIssues.ExtensionMismatch) != 0) Add("Name.ExtensionMismatch", 10);

        // Package vendor presence / allow-list hints
        string? pkgVendor = a.Installer?.PublisherDisplayName ?? a.Installer?.Publisher ?? a.Installer?.Manufacturer;
        bool packageVendorAllowed = false;
        if (!string.IsNullOrWhiteSpace(pkgVendor))
        {
            Add("Package.VendorPresent", 0);
            packageVendorAllowed = IsAllowedVendor(pkgVendor);
            if (packageVendorAllowed) Add("Package.VendorAllowed", -15);
        }
        else if (a.Installer != null)
        {
            // Installer detected but vendor fields missing
            Add("Package.VendorUnknown", 0);
        }
        // Signature vendor allow
        var sigCn = a.Authenticode?.SignerSubjectCN; var sigOrg = a.Authenticode?.SignerSubjectO;
        bool signatureVendorAllowed =
            (!string.IsNullOrWhiteSpace(sigCn) && IsAllowedVendor(sigCn)) ||
            (!string.IsNullOrWhiteSpace(sigOrg) && IsAllowedVendor(sigOrg));

        if (!packageVendorAllowed && signatureVendorAllowed) Add("Sig.VendorAllowed", -10);
        else if (a.Authenticode?.Present == true)
        {
            // Signed object but no recognizable vendor name components
            if (!signatureVendorAllowed && string.IsNullOrWhiteSpace(sigCn) && string.IsNullOrWhiteSpace(sigOrg)) Add("Sig.VendorUnknown", 0);
        }

        // MSI CustomActions (Windows-only data)
        var ca = a.Installer?.MsiCustomActions;
        if (ca != null)
        {
            if (ca.CountExe > 0) Add("Msi.CustomActionExe", 20);
            if (ca.CountScript > 0) Add("Msi.CustomActionScript", 20);
            if (ca.CountDll > 0) Add("Msi.CustomActionDll", 10);
        }
        if (string.Equals(a.Installer?.Scope, "PerUser", StringComparison.OrdinalIgnoreCase)) Add("Msi.PerUser", 5);
        if (!string.IsNullOrWhiteSpace(a.Installer?.UrlInfoAbout) || !string.IsNullOrWhiteSpace(a.Installer?.UrlUpdateInfo) || !string.IsNullOrWhiteSpace(a.Installer?.SupportUrl))
            Add("Msi.UrlsPresent", 2);
        if (securityFindings.Any(s => string.Equals(s, "pe:regsvr", StringComparison.OrdinalIgnoreCase)))
            Add("PE.RegSvrExport", 10);

        // Appx/MSIX capabilities and extensions
        var caps = a.Installer?.Capabilities;
        if (caps != null)
        {
            if (caps.Any(c => !string.IsNullOrWhiteSpace(c) && c.IndexOf("runFullTrust", StringComparison.OrdinalIgnoreCase) >= 0))
                Add("Appx.Capability.RunFullTrust", 20);
            if (caps.Any(c => !string.IsNullOrWhiteSpace(c) && c.IndexOf("broadFileSystemAccess", StringComparison.OrdinalIgnoreCase) >= 0))
                Add("Appx.Capability.BroadFileSystemAccess", 15);
        }
        var exts = a.Installer?.Extensions;
        if (exts != null)
        {
            if (exts.Any(e => !string.IsNullOrWhiteSpace(e) && e.IndexOf("windows.protocol", StringComparison.OrdinalIgnoreCase) >= 0))
                Add("Appx.Extension.Protocol", 5);
            if (exts.Any(e => !string.IsNullOrWhiteSpace(e) && e.IndexOf("filetypeassociation", StringComparison.OrdinalIgnoreCase) >= 0))
                Add("Appx.Extension.FTA", 5);
        }

        // Guardrails and clamp
        if (score < 0) score = 0; if (score > 100) score = 100;
        var decision = score >= Settings.AssessmentBlockThreshold ? AssessmentDecision.Block : (score >= Settings.AssessmentWarnThreshold ? AssessmentDecision.Warn : AssessmentDecision.Allow);

        return new AssessmentResult { Score = score, Decision = decision, Codes = codes, Factors = factors };

        void ApplySecretCount(string baseCode, int count, int baseWeight, int perExtraWeight, int maxExtraWeight)
        {
            if (count <= 0) return;
            if (!factors.ContainsKey(baseCode)) Add(baseCode, baseWeight);
            var extra = Math.Max(0, count - 1);
            if (extra <= 0 || perExtraWeight <= 0 || maxExtraWeight <= 0) return;
            int volume = Math.Min(maxExtraWeight, extra * perExtraWeight);
            if (volume > 0) Add(baseCode + ".Volume", volume);
        }
    }

    private static AssessmentResult CloneWithDecision(AssessmentResult source, AssessmentDecision decision)
    {
        var factorsCopy = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var kvp in source.Factors ?? new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase))
        {
            factorsCopy[kvp.Key] = kvp.Value;
        }

        return new AssessmentResult
        {
            Score = source.Score,
            Decision = decision,
            Codes = (source.Codes ?? Array.Empty<string>()).ToArray(),
            Factors = factorsCopy
        };
    }

    private static AssessmentDecision DecideForProfile(int score, AssessmentProfile profile)
    {
        var (warn, block) = GetThresholds(profile);
        return score >= block ? AssessmentDecision.Block :
               (score >= warn ? AssessmentDecision.Warn : AssessmentDecision.Allow);
    }

    private static (int warn, int block) GetThresholds(AssessmentProfile profile)
    {
        int warn = Settings.AssessmentWarnThreshold;
        int block = Settings.AssessmentBlockThreshold;
        switch (profile)
        {
            case AssessmentProfile.Strict:
                warn -= 10;
                block -= 10;
                break;
            case AssessmentProfile.Lenient:
                warn += 10;
                block += 10;
                break;
        }
        return NormalizeThresholds(warn, block);
    }

    private static (int warn, int block) NormalizeThresholds(int warn, int block)
    {
        warn = ClampInt(warn, 1, 99);
        block = ClampInt(block, 2, 100);
        if (block <= warn) block = Math.Min(100, warn + 1);
        return (warn, block);
    }

    private static int ClampInt(int value, int min, int max)
    {
        if (value < min) return min;
        if (value > max) return max;
        return value;
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
