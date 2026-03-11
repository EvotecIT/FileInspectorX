using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace FileInspectorX;

/// <summary>
/// Lightweight Markdown renderer for FileInspectorX results.
/// Keeps dependency-free formatting suitable for emails, CLI, or docs.
/// </summary>
public static class MarkdownRenderer
{
    /// <summary>
    /// Renders a concise Markdown report for a <see cref="FileAnalysis"/>.
    /// </summary>
    public static string From(FileAnalysis a)
    {
        var r = ReportView.From(a);
        return From(r);
    }

    /// <summary>
    /// Renders a concise Markdown report for a <see cref="ReportView"/>.
    /// </summary>
    public static string From(ReportView r)
    {
        var sb = new StringBuilder();
        // Header
        if (HasTypeAnalysis(r))
        {
            sb.AppendLine($"### File Type");
            var type = (r.DetectedTypeName ?? r.DetectedTypeFriendly ?? "").Trim();
            if (!string.IsNullOrEmpty(r.DetectedTypeExtension)) type += $" ({r.DetectedTypeExtension})";
            if (!string.IsNullOrEmpty(r.DetectionConfidence)) type += $" — {r.DetectionConfidence}";
            if (!string.IsNullOrEmpty(r.DetectionReason)) type += $" — {r.DetectionReason}";
            if (!string.IsNullOrEmpty(r.DetectionReasonDetails)) type += $" ({r.DetectionReasonDetails})";
            if (!string.IsNullOrWhiteSpace(type))
                sb.AppendLine(type);
            if (!string.IsNullOrEmpty(r.DetectionValidationStatus))
                sb.AppendLine($"- Validation: {r.DetectionValidationStatus}");
            if (r.DetectionScore.HasValue)
                sb.AppendLine($"- Score: {r.DetectionScore.Value}");
            if (r.DetectionIsDangerous.HasValue)
                sb.AppendLine($"- Dangerous type: {(r.DetectionIsDangerous.Value ? "yes" : "no")}");
            if (!string.IsNullOrEmpty(r.GuessedExtension))
                sb.AppendLine($"- Guessed extension: {r.GuessedExtension}");
            if (!string.IsNullOrEmpty(r.ContainerSubtype))
                sb.AppendLine($"- Container subtype: {r.ContainerSubtype}");
            if (!string.IsNullOrEmpty(r.TextSubtype))
                sb.AppendLine($"- Text subtype: {r.TextSubtype}");
            if (r.EstimatedLineCount.HasValue)
                sb.AppendLine($"- Estimated lines: {r.EstimatedLineCount.Value}");
            if (!string.IsNullOrEmpty(r.PeMachine))
                sb.AppendLine($"- PE machine: {r.PeMachine}");
            if (!string.IsNullOrEmpty(r.PeSubsystem))
                sb.AppendLine($"- PE subsystem: {r.PeSubsystem}");
            if (!string.IsNullOrEmpty(r.PeKind))
                sb.AppendLine($"- PE kind: {r.PeKind}");
            if (!string.IsNullOrEmpty(r.EncodedKind))
            {
                var encoded = $"- Encoded payload: {r.EncodedKind}";
                if (!string.IsNullOrEmpty(r.EncodedInnerDetectedFriendly))
                    encoded += $" -> {r.EncodedInnerDetectedFriendly}";
                else if (!string.IsNullOrEmpty(r.EncodedInnerDetectedName) || !string.IsNullOrEmpty(r.EncodedInnerDetectedExtension))
                    encoded += $" -> {(r.EncodedInnerDetectedName ?? "").Trim()}".TrimEnd();
                if (!string.IsNullOrEmpty(r.EncodedInnerDetectedExtension))
                    encoded += $" ({r.EncodedInnerDetectedExtension})";
                sb.AppendLine(encoded);
            }
            if (r.DetectionCandidates is { Count: > 0 })
                sb.AppendLine($"- Candidates: {string.Join(", ", r.DetectionCandidates.Take(4).Select(FormatCandidate))}");
            if (r.DetectionAlternatives is { Count: > 0 })
                sb.AppendLine($"- Alternatives: {string.Join(", ", r.DetectionAlternatives.Take(4).Select(FormatCandidate))}");
            sb.AppendLine();
        }

        // Publisher/signature
        if (HasSignatureData(r))
        {
            sb.AppendLine("### Signature");
            if (r.SignatureIsSigned.HasValue)
                sb.AppendLine($"- Signature blob present: {(r.SignatureIsSigned.Value ? "yes" : "no")}");
            if (r.AuthenticodePresent.HasValue)
                sb.AppendLine($"- Authenticode present: {(r.AuthenticodePresent.Value ? "yes" : "no")}");
            if (r.AuthenticodeChainValid.HasValue)
                sb.AppendLine($"- Authenticode chain valid: {(r.AuthenticodeChainValid.Value ? "yes" : "no")}");
            if (r.AuthenticodeTimestampPresent.HasValue)
                sb.AppendLine($"- Authenticode timestamp present: {(r.AuthenticodeTimestampPresent.Value ? "yes" : "no")}");
            if (r.WinTrustStatusCode.HasValue)
            {
                var ok = r.IsTrustedWindowsPolicy == true ? "Trusted" : "Untrusted";
                sb.AppendLine($"- WinTrust: {ok} (Status={r.WinTrustStatusCode})");
            }
            else if (r.IsTrustedWindowsPolicy.HasValue)
            {
                sb.AppendLine($"- WinTrust policy trusted: {(r.IsTrustedWindowsPolicy.Value ? "yes" : "no")}");
            }
            if (r.CertificateTableSize.HasValue)
                sb.AppendLine($"- Certificate Table: {r.CertificateTableSize} bytes");
            if (!string.IsNullOrEmpty(r.CertificateBlobSha256))
                sb.AppendLine($"- PKCS#7 SHA-256: `{r.CertificateBlobSha256}`");
            if (r.DotNetStrongNameSigned.HasValue)
                sb.AppendLine($"- .NET strong-name signed: {(r.DotNetStrongNameSigned.Value ? "yes" : "no")}");
            if (r.EnhancedKeyUsages != null && r.EnhancedKeyUsages.Count > 0)
                sb.AppendLine($"- EKUs: {string.Join(", ", r.EnhancedKeyUsages)}");
            if (!string.IsNullOrEmpty(r.TimestampAuthorityCN))
                sb.AppendLine($"- Timestamp Authority: {r.TimestampAuthorityCN}");
            if (!string.IsNullOrEmpty(r.SignerIssuerCN))
                sb.AppendLine($"- Signer issuer CN: {r.SignerIssuerCN}");
            if (!string.IsNullOrEmpty(r.SignerIssuerO))
                sb.AppendLine($"- Signer issuer O: {r.SignerIssuerO}");
            if (!string.IsNullOrEmpty(r.CertSubject))
                sb.AppendLine($"- Certificate subject: {r.CertSubject}");
            if (!string.IsNullOrEmpty(r.CertIssuer))
                sb.AppendLine($"- Certificate issuer: {r.CertIssuer}");
            if (r.CertNotBefore.HasValue)
                sb.AppendLine($"- Certificate not before: {r.CertNotBefore.Value:u}");
            if (r.CertNotAfter.HasValue)
                sb.AppendLine($"- Certificate not after: {r.CertNotAfter.Value:u}");
            if (!string.IsNullOrEmpty(r.CertThumbprint))
                sb.AppendLine($"- Certificate thumbprint: {r.CertThumbprint}");
            if (!string.IsNullOrEmpty(r.CertKeyAlgorithm))
                sb.AppendLine($"- Certificate key algorithm: {r.CertKeyAlgorithm}");
            if (r.CertSelfSigned.HasValue)
                sb.AppendLine($"- Certificate self-signed: {(r.CertSelfSigned.Value ? "yes" : "no")}");
            if (r.CertChainTrusted.HasValue)
                sb.AppendLine($"- Certificate chain trusted: {(r.CertChainTrusted.Value ? "yes" : "no")}");
            if (!string.IsNullOrEmpty(r.CertRootSubject))
                sb.AppendLine($"- Certificate root subject: {r.CertRootSubject}");
            if (r.CertSanPresent.HasValue)
                sb.AppendLine($"- Certificate SAN present: {(r.CertSanPresent.Value ? "yes" : "no")}");
            if (r.CertBundleCount.HasValue)
                sb.AppendLine($"- Certificate bundle count: {r.CertBundleCount.Value}");
            if (r.CertBundleSubjects != null && r.CertBundleSubjects.Count > 0)
                sb.AppendLine($"- Certificate bundle subjects: {string.Join(", ", r.CertBundleSubjects)}");
            sb.AppendLine();
        }

        // Version info
        if (HasPropertiesData(r))
        {
            sb.AppendLine("### Properties");
            if (!string.IsNullOrEmpty(r.CompanyName)) sb.AppendLine($"- Company: {r.CompanyName}");
            if (!string.IsNullOrEmpty(r.ProductName)) sb.AppendLine($"- Product: {r.ProductName}");
            if (!string.IsNullOrEmpty(r.FileDescription)) sb.AppendLine($"- Description: {r.FileDescription}");
            if (!string.IsNullOrEmpty(r.FileVersion)) sb.AppendLine($"- FileVersion: {r.FileVersion}");
            if (!string.IsNullOrEmpty(r.ProductVersion)) sb.AppendLine($"- ProductVersion: {r.ProductVersion}");
            if (!string.IsNullOrEmpty(r.OriginalFilename)) sb.AppendLine($"- OriginalFilename: {r.OriginalFilename}");
            if (r.VersionInfo != null && r.VersionInfo.Count > 0)
            {
                var emitted = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                {
                    "CompanyName",
                    "ProductName",
                    "FileDescription",
                    "FileVersion",
                    "ProductVersion",
                    "OriginalFilename"
                };
                foreach (var entry in r.VersionInfo
                    .Where(kv => !string.IsNullOrWhiteSpace(kv.Key) && !string.IsNullOrWhiteSpace(kv.Value) && !emitted.Contains(kv.Key))
                    .OrderBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                    .Take(12))
                {
                    sb.AppendLine($"- {entry.Key}: {entry.Value}");
                }
            }
            sb.AppendLine();
        }

        if (HasSecurityData(r))
        {
            sb.AppendLine("### Security");
            if (r.IsSymlink.HasValue) sb.AppendLine($"- Symlink: {(r.IsSymlink.Value ? "yes" : "no")}");
            if (r.IsHidden.HasValue) sb.AppendLine($"- Hidden: {(r.IsHidden.Value ? "yes" : "no")}");
            if (r.IsReadOnly.HasValue) sb.AppendLine($"- Read-only: {(r.IsReadOnly.Value ? "yes" : "no")}");
            if (!string.IsNullOrEmpty(r.Owner)) sb.AppendLine($"- Owner: {r.Owner}");
            if (!string.IsNullOrEmpty(r.OwnerId)) sb.AppendLine($"- Owner ID: {r.OwnerId}");
            if (!string.IsNullOrEmpty(r.Group)) sb.AppendLine($"- Group: {r.Group}");
            if (!string.IsNullOrEmpty(r.GroupId)) sb.AppendLine($"- Group ID: {r.GroupId}");
            if (!string.IsNullOrEmpty(r.ModeOctal)) sb.AppendLine($"- Mode (octal): {r.ModeOctal}");
            if (!string.IsNullOrEmpty(r.ModeSymbolic)) sb.AppendLine($"- Mode (symbolic): {r.ModeSymbolic}");
            if (r.IsExecutable.HasValue) sb.AppendLine($"- Executable: {(r.IsExecutable.Value ? "yes" : "no")}");
            if (r.IsWorldWritable.HasValue) sb.AppendLine($"- World-writable: {(r.IsWorldWritable.Value ? "yes" : "no")}");
            if (r.EveryoneWriteAllowed.HasValue) sb.AppendLine($"- Everyone write allowed: {(r.EveryoneWriteAllowed.Value ? "yes" : "no")}");
            if (r.AuthenticatedUsersWriteAllowed.HasValue) sb.AppendLine($"- Authenticated Users write allowed: {(r.AuthenticatedUsersWriteAllowed.Value ? "yes" : "no")}");
            if (r.EveryoneReadAllowed.HasValue) sb.AppendLine($"- Everyone read allowed: {(r.EveryoneReadAllowed.Value ? "yes" : "no")}");
            if (r.BuiltinUsersWriteAllowed.HasValue) sb.AppendLine($"- BUILTIN\\Users write allowed: {(r.BuiltinUsersWriteAllowed.Value ? "yes" : "no")}");
            if (r.BuiltinUsersReadAllowed.HasValue) sb.AppendLine($"- BUILTIN\\Users read allowed: {(r.BuiltinUsersReadAllowed.Value ? "yes" : "no")}");
            if (r.AdministratorsWriteAllowed.HasValue) sb.AppendLine($"- BUILTIN\\Administrators write allowed: {(r.AdministratorsWriteAllowed.Value ? "yes" : "no")}");
            if (r.AdministratorsReadAllowed.HasValue) sb.AppendLine($"- BUILTIN\\Administrators read allowed: {(r.AdministratorsReadAllowed.Value ? "yes" : "no")}");
            if (r.HasDenyEntries.HasValue) sb.AppendLine($"- Has deny ACEs: {(r.HasDenyEntries.Value ? "yes" : "no")}");
            if (r.TotalAllowCount.HasValue) sb.AppendLine($"- Total allow ACEs: {r.TotalAllowCount.Value}");
            if (r.TotalDenyCount.HasValue) sb.AppendLine($"- Total deny ACEs: {r.TotalDenyCount.Value}");
            if (r.ExplicitAllowCount.HasValue) sb.AppendLine($"- Explicit allow ACEs: {r.ExplicitAllowCount.Value}");
            if (r.ExplicitDenyCount.HasValue) sb.AppendLine($"- Explicit deny ACEs: {r.ExplicitDenyCount.Value}");
            if (r.MotwZoneId.HasValue) sb.AppendLine($"- MOTW ZoneId: {r.MotwZoneId.Value}");
            if (!string.IsNullOrEmpty(r.MotwReferrerUrl)) sb.AppendLine($"- MOTW Referrer URL: {r.MotwReferrerUrl}");
            if (!string.IsNullOrEmpty(r.MotwHostUrl)) sb.AppendLine($"- MOTW Host URL: {r.MotwHostUrl}");
            if (r.AlternateStreamCount.HasValue) sb.AppendLine($"- Alternate stream count: {r.AlternateStreamCount.Value}");
            if (!string.IsNullOrEmpty(r.NameIssuesCsv)) sb.AppendLine($"- Name issues: {r.NameIssuesCsv}");
            sb.AppendLine();
        }

        if (HasScriptData(r))
        {
            sb.AppendLine("### Script");
            if (!string.IsNullOrEmpty(r.ScriptLanguageHuman)) sb.AppendLine($"- Language: {r.ScriptLanguageHuman}");
            else if (!string.IsNullOrEmpty(r.ScriptLanguage)) sb.AppendLine($"- Language: {r.ScriptLanguage}");
            if (!string.IsNullOrEmpty(r.ScriptCmdlets)) sb.AppendLine($"- Cmdlets: {r.ScriptCmdlets}");
            sb.AppendLine();
        }

        if (HasReferenceData(r))
        {
            sb.AppendLine("### References");
            if (!string.IsNullOrEmpty(r.HtmlExternalLinksSample)) sb.AppendLine($"- HTML external links: {r.HtmlExternalLinksSample}");
            if (!string.IsNullOrEmpty(r.HtmlUncSample)) sb.AppendLine($"- HTML UNC paths: {r.HtmlUncSample}");
            if (!string.IsNullOrEmpty(r.ScriptUrlsSample)) sb.AppendLine($"- Script URLs: {r.ScriptUrlsSample}");
            if (!string.IsNullOrEmpty(r.ScriptUncSample)) sb.AppendLine($"- Script UNC paths: {r.ScriptUncSample}");
            if (r.OfficeExternalLinksCount.HasValue) sb.AppendLine($"- Office external links: {r.OfficeExternalLinksCount.Value}");
            if (!string.IsNullOrEmpty(r.HtmlExternalLinksFull)) sb.AppendLine($"- HTML external links (full): {r.HtmlExternalLinksFull}");
            if (!string.IsNullOrEmpty(r.HtmlUncFull)) sb.AppendLine($"- HTML UNC paths (full): {r.HtmlUncFull}");
            if (!string.IsNullOrEmpty(r.ScriptUrlsFull)) sb.AppendLine($"- Script URLs (full): {r.ScriptUrlsFull}");
            if (!string.IsNullOrEmpty(r.ScriptUncFull)) sb.AppendLine($"- Script UNC paths (full): {r.ScriptUncFull}");
            sb.AppendLine();
        }

        if (HasInstallerData(r))
        {
            sb.AppendLine("### Installer");
            if (!string.IsNullOrEmpty(r.InstallerKind)) sb.AppendLine($"- Kind: {r.InstallerKind}");
            if (!string.IsNullOrEmpty(r.InstallerName)) sb.AppendLine($"- Name: {r.InstallerName}");
            if (!string.IsNullOrEmpty(r.InstallerManufacturer)) sb.AppendLine($"- Manufacturer: {r.InstallerManufacturer}");
            if (!string.IsNullOrEmpty(r.InstallerVersion)) sb.AppendLine($"- Version: {r.InstallerVersion}");
            if (!string.IsNullOrEmpty(r.InstallerProductCode)) sb.AppendLine($"- ProductCode: {r.InstallerProductCode}");
            if (!string.IsNullOrEmpty(r.InstallerUpgradeCode)) sb.AppendLine($"- UpgradeCode: {r.InstallerUpgradeCode}");
            if (!string.IsNullOrEmpty(r.InstallerScope)) sb.AppendLine($"- Scope: {r.InstallerScope}");
            if (!string.IsNullOrEmpty(r.InstallerUrlInfoAbout)) sb.AppendLine($"- Info URL: {r.InstallerUrlInfoAbout}");
            if (!string.IsNullOrEmpty(r.InstallerUrlUpdateInfo)) sb.AppendLine($"- Update URL: {r.InstallerUrlUpdateInfo}");
            if (!string.IsNullOrEmpty(r.InstallerHelpLink)) sb.AppendLine($"- Help link: {r.InstallerHelpLink}");
            if (!string.IsNullOrEmpty(r.InstallerSupportUrl)) sb.AppendLine($"- Support URL: {r.InstallerSupportUrl}");
            if (!string.IsNullOrEmpty(r.InstallerContact)) sb.AppendLine($"- Contact: {r.InstallerContact}");
            if (!string.IsNullOrEmpty(r.InstallerCreated)) sb.AppendLine($"- Created: {r.InstallerCreated}");
            if (!string.IsNullOrEmpty(r.InstallerLastSaved)) sb.AppendLine($"- Last saved: {r.InstallerLastSaved}");
            if (r._MsiCAExe.HasValue) sb.AppendLine($"- MSI custom actions (EXE): {r._MsiCAExe.Value}");
            if (r._MsiCADll.HasValue) sb.AppendLine($"- MSI custom actions (DLL): {r._MsiCADll.Value}");
            if (r._MsiCAScript.HasValue) sb.AppendLine($"- MSI custom actions (script): {r._MsiCAScript.Value}");
            if (!string.IsNullOrEmpty(r._MsiCASamples)) sb.AppendLine($"- MSI custom action samples: {r._MsiCASamples}");
            sb.AppendLine();
        }

        if (HasArchiveData(r))
        {
            sb.AppendLine("### Archive");
            if (r.EncryptedEntryCount.HasValue) sb.AppendLine($"- Encrypted entries: {r.EncryptedEntryCount.Value}");
            if (r.ArchiveEntryCount.HasValue) sb.AppendLine($"- Entry count: {r.ArchiveEntryCount.Value}");
            if (r.ArchiveTopExtensions != null && r.ArchiveTopExtensions.Count > 0)
                sb.AppendLine($"- Top extensions: {string.Join(", ", r.ArchiveTopExtensions)}");
            if (r.InnerExecutablesSampled.HasValue) sb.AppendLine($"- Inner binaries sampled: {r.InnerExecutablesSampled.Value}");
            if (r.InnerSignedExecutables.HasValue) sb.AppendLine($"- Inner signed binaries: {r.InnerSignedExecutables.Value}");
            if (r.InnerValidSignedExecutables.HasValue) sb.AppendLine($"- Inner validly signed binaries: {r.InnerValidSignedExecutables.Value}");
            if (!string.IsNullOrEmpty(r.InnerPublishersHuman))
                sb.AppendLine($"- Inner publishers: {r.InnerPublishersHuman}");
            else if (r.InnerPublisherCounts != null && r.InnerPublisherCounts.Count > 0)
                sb.AppendLine($"- Inner publishers: {string.Join(", ", FormatInnerPublishers(r).Take(5))}");
            if (r.InnerExecutableExtCounts != null && r.InnerExecutableExtCounts.Count > 0)
            {
                var topExts = r.InnerExecutableExtCounts
                    .OrderByDescending(kv => kv.Value)
                    .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                    .Take(6)
                    .Select(kv => $"{kv.Key}={kv.Value}");
                sb.AppendLine($"- Inner executable types: {string.Join(", ", topExts)}");
            }
            if (!string.IsNullOrEmpty(r.InnerBinariesSummary))
                sb.AppendLine($"- {r.InnerBinariesSummary}");
            if (r.ArchivePreview != null && r.ArchivePreview.Count > 0)
                sb.AppendLine($"- Preview: {string.Join(", ", r.ArchivePreview.Take(6))}");
            sb.AppendLine();
        }

        // Flags and findings
        if (!string.IsNullOrEmpty(r.FlagsHumanShort) || !string.IsNullOrEmpty(r.FlagsHumanLong) || !string.IsNullOrEmpty(r.FlagsCsv))
        {
            sb.AppendLine("### Analysis Flags");
            if (!string.IsNullOrEmpty(r.FlagsHumanShort))
                sb.AppendLine(r.FlagsHumanShort);
            else if (!string.IsNullOrEmpty(r.FlagsCsv))
                sb.AppendLine($"Flags: {r.FlagsCsv}");
            if (!string.IsNullOrEmpty(r.FlagsHumanLong) &&
                !string.Equals(r.FlagsHumanLong, r.FlagsHumanShort, StringComparison.Ordinal))
            {
                sb.AppendLine($"Details: {r.FlagsHumanLong}");
            }
            sb.AppendLine();
        }
        if (!string.IsNullOrEmpty(r.SecurityFindingsHumanShort) ||
            (r.SecurityFindings != null && r.SecurityFindings.Count > 0) ||
            (r.TopTokens != null && r.TopTokens.Count > 0))
        {
            sb.AppendLine("### Heuristics");
            if (!string.IsNullOrEmpty(r.SecurityFindingsHumanShort))
                sb.AppendLine(r.SecurityFindingsHumanShort);
            else if (r.SecurityFindings is { Count: > 0 })
                sb.AppendLine($"Findings: {string.Join(", ", r.SecurityFindings.Take(8))}");
            if (!string.IsNullOrEmpty(r.SecurityFindingsHumanLong) &&
                !string.Equals(r.SecurityFindingsHumanLong, r.SecurityFindingsHumanShort, StringComparison.Ordinal))
            {
                sb.AppendLine($"Details: {r.SecurityFindingsHumanLong}");
            }
            if (r.TopTokens is { Count: > 0 })
                sb.AppendLine($"Top tokens: {string.Join(", ", r.TopTokens.Take(8))}");
            sb.AppendLine();
        }
        if (!string.IsNullOrEmpty(r.InnerFindingsHumanShort) ||
            !string.IsNullOrEmpty(r.InnerFindingsHumanLong) ||
            (r.InnerFindings != null && r.InnerFindings.Count > 0))
        {
            sb.AppendLine("### Inner Findings");
            if (!string.IsNullOrEmpty(r.InnerFindingsHumanShort))
                sb.AppendLine(r.InnerFindingsHumanShort);
            else if (r.InnerFindings is { Count: > 0 })
                sb.AppendLine($"Findings: {string.Join(", ", r.InnerFindings.Take(8))}");
            if (!string.IsNullOrEmpty(r.InnerFindingsHumanLong) &&
                !string.Equals(r.InnerFindingsHumanLong, r.InnerFindingsHumanShort, StringComparison.Ordinal))
            {
                sb.AppendLine($"Details: {r.InnerFindingsHumanLong}");
            }
            sb.AppendLine();
        }
        if (HasAnySecretCounts(r))
        {
            sb.AppendLine("### Secrets");
            AppendSecretCount(sb, "Private key indicators", r.SecretsPrivateKeyCount);
            AppendSecretCount(sb, "JWT-like tokens", r.SecretsJwtLikeCount);
            AppendSecretCount(sb, "Key/secret patterns", r.SecretsKeyPatternCount);
            AppendSecretCount(sb, "Token-family secrets", r.SecretsTokenFamilyCount);
            AppendSecretCount(sb, "GitHub token-family", r.SecretsGitHubTokenCount);
            AppendSecretCount(sb, "GitLab token-family", r.SecretsGitLabTokenCount);
            AppendSecretCount(sb, "AWS access key id", r.SecretsAwsAccessKeyIdCount);
            AppendSecretCount(sb, "Slack token-family", r.SecretsSlackTokenCount);
            AppendSecretCount(sb, "Stripe live key", r.SecretsStripeLiveKeyCount);
            AppendSecretCount(sb, "GCP API key", r.SecretsGcpApiKeyCount);
            AppendSecretCount(sb, "npm token-family", r.SecretsNpmTokenCount);
            AppendSecretCount(sb, "Azure SAS token-family", r.SecretsAzureSasTokenCount);
            if (r.SecretsFindings is { Count: > 0 })
            {
                sb.AppendLine("- Findings:");
                foreach (var f in r.SecretsFindings.Take(6))
                {
                    if (f == null) continue;
                    var linePart = f.Line.HasValue ? $" line {f.Line.Value}" : string.Empty;
                    var evidence = string.IsNullOrWhiteSpace(f.Evidence) ? string.Empty : $" -> `{f.Evidence}`";
                    sb.AppendLine($"  - [{f.Confidence}] {f.Code}{linePart}{evidence}");
                }
            }
            sb.AppendLine();
        }

        // Risk assessment
        if (r.AssessmentScore.HasValue ||
            !string.IsNullOrEmpty(r.AssessmentDecision) ||
            !string.IsNullOrEmpty(r.AssessmentDecisionStrict) ||
            !string.IsNullOrEmpty(r.AssessmentDecisionBalanced) ||
            !string.IsNullOrEmpty(r.AssessmentDecisionLenient) ||
            (r.AssessmentCodes != null && r.AssessmentCodes.Count > 0) ||
            !string.IsNullOrEmpty(r.AssessmentCodesHuman) ||
            !string.IsNullOrEmpty(r.AssessmentCodesHumanLong) ||
            (r.AssessmentFactors != null && r.AssessmentFactors.Count > 0))
        {
            sb.AppendLine("### Risk Assessment");
            if (r.AssessmentScore.HasValue)
                sb.AppendLine($"- Score: {r.AssessmentScore.Value}");
            if (!string.IsNullOrEmpty(r.AssessmentDecision)) sb.AppendLine($"- Decision: {r.AssessmentDecision}");
            if (!string.IsNullOrEmpty(r.AssessmentDecisionStrict) ||
                !string.IsNullOrEmpty(r.AssessmentDecisionBalanced) ||
                !string.IsNullOrEmpty(r.AssessmentDecisionLenient))
            {
                sb.AppendLine($"- Profile decisions: Strict={r.AssessmentDecisionStrict ?? "n/a"}, Balanced={r.AssessmentDecisionBalanced ?? r.AssessmentDecision ?? "n/a"}, Lenient={r.AssessmentDecisionLenient ?? "n/a"}");
            }
            if (!string.IsNullOrEmpty(r.AssessmentCodesHuman)) sb.AppendLine($"- Drivers: {r.AssessmentCodesHuman}");
            else if (r.AssessmentCodes is { Count: > 0 }) sb.AppendLine($"- Codes: {string.Join(", ", r.AssessmentCodes)}");
            if (!string.IsNullOrEmpty(r.AssessmentCodesHumanLong)) sb.AppendLine($"- Drivers (long): {r.AssessmentCodesHumanLong}");
            if (r.AssessmentFactors != null && r.AssessmentFactors.Count > 0)
            {
                var topFactors = r.AssessmentFactors
                    .OrderByDescending(kv => Math.Abs(kv.Value))
                    .ThenBy(kv => kv.Key, StringComparer.Ordinal)
                    .Take(6)
                    .Select(kv => $"{kv.Key}={kv.Value}");
                sb.AppendLine($"- Factors: {string.Join(", ", topFactors)}");
            }
            sb.AppendLine();
        }
        return sb.ToString();

        static bool HasAnySecretCounts(ReportView view)
            => (view.SecretsPrivateKeyCount ?? 0) > 0 ||
               (view.SecretsJwtLikeCount ?? 0) > 0 ||
               (view.SecretsKeyPatternCount ?? 0) > 0 ||
               (view.SecretsTokenFamilyCount ?? 0) > 0 ||
               (view.SecretsGitHubTokenCount ?? 0) > 0 ||
               (view.SecretsGitLabTokenCount ?? 0) > 0 ||
               (view.SecretsAwsAccessKeyIdCount ?? 0) > 0 ||
               (view.SecretsSlackTokenCount ?? 0) > 0 ||
               (view.SecretsStripeLiveKeyCount ?? 0) > 0 ||
               (view.SecretsGcpApiKeyCount ?? 0) > 0 ||
               (view.SecretsNpmTokenCount ?? 0) > 0 ||
               (view.SecretsAzureSasTokenCount ?? 0) > 0 ||
               (view.SecretsFindings != null && view.SecretsFindings.Count > 0);

        static void AppendSecretCount(StringBuilder builder, string label, int? value)
        {
            if (!value.HasValue || value.Value <= 0) return;
            builder.AppendLine($"- {label}: {value.Value}");
        }

        static bool HasTypeAnalysis(ReportView view)
            => !string.IsNullOrEmpty(view.DetectedTypeName) ||
               !string.IsNullOrEmpty(view.DetectedTypeFriendly) ||
               !string.IsNullOrEmpty(view.DetectedTypeExtension) ||
               !string.IsNullOrEmpty(view.DetectionConfidence) ||
               !string.IsNullOrEmpty(view.DetectionReason) ||
               !string.IsNullOrEmpty(view.DetectionReasonDetails) ||
               !string.IsNullOrEmpty(view.DetectionValidationStatus) ||
               view.DetectionScore.HasValue ||
               view.DetectionIsDangerous.HasValue ||
               !string.IsNullOrEmpty(view.GuessedExtension) ||
               !string.IsNullOrEmpty(view.ContainerSubtype) ||
               !string.IsNullOrEmpty(view.TextSubtype) ||
               view.EstimatedLineCount.HasValue ||
               !string.IsNullOrEmpty(view.PeMachine) ||
               !string.IsNullOrEmpty(view.PeSubsystem) ||
               !string.IsNullOrEmpty(view.PeKind) ||
               (view.DetectionAlternatives != null && view.DetectionAlternatives.Count > 0) ||
               (view.DetectionCandidates != null && view.DetectionCandidates.Count > 0) ||
               !string.IsNullOrEmpty(view.EncodedKind) ||
               !string.IsNullOrEmpty(view.EncodedInnerDetectedExtension) ||
               !string.IsNullOrEmpty(view.EncodedInnerDetectedName) ||
               !string.IsNullOrEmpty(view.EncodedInnerDetectedFriendly);

        static bool HasInstallerData(ReportView view)
            => !string.IsNullOrEmpty(view.InstallerKind) ||
               !string.IsNullOrEmpty(view.InstallerName) ||
               !string.IsNullOrEmpty(view.InstallerManufacturer) ||
               !string.IsNullOrEmpty(view.InstallerVersion) ||
               !string.IsNullOrEmpty(view.InstallerProductCode) ||
               !string.IsNullOrEmpty(view.InstallerUpgradeCode) ||
               !string.IsNullOrEmpty(view.InstallerScope) ||
               !string.IsNullOrEmpty(view.InstallerUrlInfoAbout) ||
               !string.IsNullOrEmpty(view.InstallerUrlUpdateInfo) ||
               !string.IsNullOrEmpty(view.InstallerHelpLink) ||
               !string.IsNullOrEmpty(view.InstallerSupportUrl) ||
               !string.IsNullOrEmpty(view.InstallerContact) ||
               !string.IsNullOrEmpty(view.InstallerCreated) ||
               !string.IsNullOrEmpty(view.InstallerLastSaved) ||
               view._MsiCAExe.HasValue ||
               view._MsiCADll.HasValue ||
               view._MsiCAScript.HasValue ||
               !string.IsNullOrEmpty(view._MsiCASamples);

        static bool HasPropertiesData(ReportView view)
            => (view.VersionInfo != null && view.VersionInfo.Count > 0) ||
               !string.IsNullOrEmpty(view.CompanyName) ||
               !string.IsNullOrEmpty(view.ProductName) ||
               !string.IsNullOrEmpty(view.FileDescription) ||
               !string.IsNullOrEmpty(view.FileVersion) ||
               !string.IsNullOrEmpty(view.ProductVersion) ||
               !string.IsNullOrEmpty(view.OriginalFilename);

        static bool HasSecurityData(ReportView view)
            => view.IsSymlink.HasValue ||
               view.IsHidden.HasValue ||
               view.IsReadOnly.HasValue ||
               !string.IsNullOrEmpty(view.Owner) ||
               !string.IsNullOrEmpty(view.OwnerId) ||
               !string.IsNullOrEmpty(view.Group) ||
               !string.IsNullOrEmpty(view.GroupId) ||
               !string.IsNullOrEmpty(view.ModeOctal) ||
               !string.IsNullOrEmpty(view.ModeSymbolic) ||
               view.IsExecutable.HasValue ||
               view.IsWorldWritable.HasValue ||
               view.EveryoneWriteAllowed.HasValue ||
               view.AuthenticatedUsersWriteAllowed.HasValue ||
               view.EveryoneReadAllowed.HasValue ||
               view.BuiltinUsersWriteAllowed.HasValue ||
               view.BuiltinUsersReadAllowed.HasValue ||
               view.AdministratorsWriteAllowed.HasValue ||
               view.AdministratorsReadAllowed.HasValue ||
               view.HasDenyEntries.HasValue ||
               view.TotalAllowCount.HasValue ||
               view.TotalDenyCount.HasValue ||
               view.ExplicitAllowCount.HasValue ||
               view.ExplicitDenyCount.HasValue ||
               view.MotwZoneId.HasValue ||
               !string.IsNullOrEmpty(view.MotwReferrerUrl) ||
               !string.IsNullOrEmpty(view.MotwHostUrl) ||
               view.AlternateStreamCount.HasValue ||
               !string.IsNullOrEmpty(view.NameIssuesCsv);

        static bool HasScriptData(ReportView view)
            => !string.IsNullOrEmpty(view.ScriptLanguage) ||
               !string.IsNullOrEmpty(view.ScriptLanguageHuman) ||
               !string.IsNullOrEmpty(view.ScriptCmdlets);

        static bool HasReferenceData(ReportView view)
            => !string.IsNullOrEmpty(view.HtmlExternalLinksSample) ||
               !string.IsNullOrEmpty(view.HtmlUncSample) ||
               !string.IsNullOrEmpty(view.ScriptUrlsSample) ||
               !string.IsNullOrEmpty(view.ScriptUncSample) ||
               view.OfficeExternalLinksCount.HasValue ||
               !string.IsNullOrEmpty(view.HtmlExternalLinksFull) ||
               !string.IsNullOrEmpty(view.HtmlUncFull) ||
               !string.IsNullOrEmpty(view.ScriptUrlsFull) ||
               !string.IsNullOrEmpty(view.ScriptUncFull);

        static bool HasArchiveData(ReportView view)
            => view.EncryptedEntryCount.HasValue ||
               view.ArchiveEntryCount.HasValue ||
               (view.ArchiveTopExtensions != null && view.ArchiveTopExtensions.Count > 0) ||
               view.InnerExecutablesSampled.HasValue ||
               view.InnerSignedExecutables.HasValue ||
               view.InnerValidSignedExecutables.HasValue ||
               !string.IsNullOrEmpty(view.InnerPublishersHuman) ||
               (view.InnerPublisherCounts != null && view.InnerPublisherCounts.Count > 0) ||
               (view.InnerPublisherValidCounts != null && view.InnerPublisherValidCounts.Count > 0) ||
               (view.InnerPublisherSelfSignedCounts != null && view.InnerPublisherSelfSignedCounts.Count > 0) ||
               (view.InnerExecutableExtCounts != null && view.InnerExecutableExtCounts.Count > 0) ||
               !string.IsNullOrEmpty(view.InnerBinariesSummary) ||
               (view.ArchivePreview != null && view.ArchivePreview.Count > 0);

        static bool HasSignatureData(ReportView view)
            => view.SignatureIsSigned.HasValue ||
               view.CertificateTableSize.HasValue ||
               !string.IsNullOrEmpty(view.CertificateBlobSha256) ||
               view.DotNetStrongNameSigned.HasValue ||
               view.AuthenticodePresent.HasValue ||
               view.AuthenticodeChainValid.HasValue ||
               view.AuthenticodeTimestampPresent.HasValue ||
               view.IsTrustedWindowsPolicy.HasValue ||
               view.WinTrustStatusCode.HasValue ||
               (view.EnhancedKeyUsages != null && view.EnhancedKeyUsages.Count > 0) ||
               !string.IsNullOrEmpty(view.TimestampAuthorityCN) ||
               !string.IsNullOrEmpty(view.SignerIssuerCN) ||
               !string.IsNullOrEmpty(view.SignerIssuerO) ||
               !string.IsNullOrEmpty(view.CertSubject) ||
               !string.IsNullOrEmpty(view.CertIssuer) ||
               view.CertNotBefore.HasValue ||
               view.CertNotAfter.HasValue ||
               !string.IsNullOrEmpty(view.CertThumbprint) ||
               !string.IsNullOrEmpty(view.CertKeyAlgorithm) ||
               view.CertSelfSigned.HasValue ||
               view.CertChainTrusted.HasValue ||
               !string.IsNullOrEmpty(view.CertRootSubject) ||
               view.CertSanPresent.HasValue ||
               view.CertBundleCount.HasValue ||
               (view.CertBundleSubjects != null && view.CertBundleSubjects.Count > 0);

        static string FormatCandidate(ContentTypeDetectionCandidate candidate)
        {
            var parts = new List<string>();
            if (!string.IsNullOrEmpty(candidate.Extension)) parts.Add(candidate.Extension);
            else if (!string.IsNullOrEmpty(candidate.MimeType)) parts.Add(candidate.MimeType);
            if (!string.IsNullOrEmpty(candidate.Confidence)) parts.Add(candidate.Confidence);
            if (candidate.Score > 0) parts.Add(candidate.Score.ToString());
            if (candidate.IsDangerous) parts.Add("dangerous");
            var head = string.Join(" ", parts);
            return string.IsNullOrEmpty(head) ? candidate.Reason : $"{head} ({candidate.Reason})";
        }

        static IEnumerable<string> FormatInnerPublishers(ReportView view)
            => view.InnerPublisherCounts!
                .OrderByDescending(kv => kv.Value)
                .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                .Select(kv =>
                {
                    int valid = 0;
                    int self = 0;
                    if (view.InnerPublisherValidCounts != null) view.InnerPublisherValidCounts.TryGetValue(kv.Key, out valid);
                    if (view.InnerPublisherSelfSignedCounts != null) view.InnerPublisherSelfSignedCounts.TryGetValue(kv.Key, out self);
                    var files = kv.Value == 1 ? "1 file" : $"{kv.Value} files";
                    var qualifier = self > 0 ? "self-signed" : (valid >= kv.Value && kv.Value > 0 ? "valid" : "signed");
                    return $"{kv.Key} ({files}, {qualifier})";
                });
    }
}
