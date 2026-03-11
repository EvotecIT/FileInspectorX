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
            var type = (r.DetectedTypeName ?? "").Trim();
            if (!string.IsNullOrEmpty(r.DetectedTypeExtension)) type += $" ({r.DetectedTypeExtension})";
            if (!string.IsNullOrEmpty(r.DetectionConfidence)) type += $" — {r.DetectionConfidence}";
            if (!string.IsNullOrEmpty(r.DetectionReason)) type += $" — {r.DetectionReason}";
            if (!string.IsNullOrEmpty(r.DetectionReasonDetails)) type += $" ({r.DetectionReasonDetails})";
            if (!string.IsNullOrWhiteSpace(type))
                sb.AppendLine(type);
            if (!string.IsNullOrEmpty(r.DetectionValidationStatus))
                sb.AppendLine($"- Validation: {r.DetectionValidationStatus}");
            if (!string.IsNullOrEmpty(r.GuessedExtension))
                sb.AppendLine($"- Guessed extension: {r.GuessedExtension}");
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
            if (r.WinTrustStatusCode.HasValue)
            {
                var ok = r.IsTrustedWindowsPolicy == true ? "Trusted" : "Untrusted";
                sb.AppendLine($"- WinTrust: {ok} (Status={r.WinTrustStatusCode})");
            }
            if (r.CertificateTableSize.HasValue)
                sb.AppendLine($"- Certificate Table: {r.CertificateTableSize} bytes");
            if (!string.IsNullOrEmpty(r.CertificateBlobSha256))
                sb.AppendLine($"- PKCS#7 SHA-256: `{r.CertificateBlobSha256}`");
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
            if (!string.IsNullOrEmpty(r.CertThumbprint))
                sb.AppendLine($"- Certificate thumbprint: {r.CertThumbprint}");
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
            if (!string.IsNullOrEmpty(r.InnerBinariesSummary))
                sb.AppendLine($"- {r.InnerBinariesSummary}");
            if (r.ArchivePreview != null && r.ArchivePreview.Count > 0)
                sb.AppendLine($"- Preview: {string.Join(", ", r.ArchivePreview.Take(6))}");
            sb.AppendLine();
        }

        // Flags and findings
        if (!string.IsNullOrEmpty(r.FlagsHumanShort)) sb.AppendLine($"### Analysis Flags\n{r.FlagsHumanShort}\n");
        if (!string.IsNullOrEmpty(r.SecurityFindingsHumanShort) || (r.TopTokens != null && r.TopTokens.Count > 0))
        {
            sb.AppendLine("### Heuristics");
            if (!string.IsNullOrEmpty(r.SecurityFindingsHumanShort))
                sb.AppendLine(r.SecurityFindingsHumanShort);
            if (r.TopTokens is { Count: > 0 })
                sb.AppendLine($"Top tokens: {string.Join(", ", r.TopTokens.Take(8))}");
            sb.AppendLine();
        }
        if (!string.IsNullOrEmpty(r.InnerFindingsHumanShort)) sb.AppendLine($"### Inner Findings\n{r.InnerFindingsHumanShort}\n");
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
            !string.IsNullOrEmpty(r.AssessmentDecisionLenient))
        {
            sb.AppendLine("### Risk Assessment");
            sb.AppendLine($"- Score: {r.AssessmentScore ?? 0}");
            if (!string.IsNullOrEmpty(r.AssessmentDecision)) sb.AppendLine($"- Decision: {r.AssessmentDecision}");
            if (!string.IsNullOrEmpty(r.AssessmentDecisionStrict) ||
                !string.IsNullOrEmpty(r.AssessmentDecisionBalanced) ||
                !string.IsNullOrEmpty(r.AssessmentDecisionLenient))
            {
                sb.AppendLine($"- Profile decisions: Strict={r.AssessmentDecisionStrict ?? "n/a"}, Balanced={r.AssessmentDecisionBalanced ?? r.AssessmentDecision ?? "n/a"}, Lenient={r.AssessmentDecisionLenient ?? "n/a"}");
            }
            if (!string.IsNullOrEmpty(r.AssessmentCodesHuman)) sb.AppendLine($"- Drivers: {r.AssessmentCodesHuman}");
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
               !string.IsNullOrEmpty(view.DetectedTypeExtension) ||
               !string.IsNullOrEmpty(view.DetectionConfidence) ||
               !string.IsNullOrEmpty(view.DetectionReason) ||
               !string.IsNullOrEmpty(view.DetectionReasonDetails) ||
               !string.IsNullOrEmpty(view.DetectionValidationStatus) ||
               !string.IsNullOrEmpty(view.GuessedExtension) ||
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

        static bool HasArchiveData(ReportView view)
            => view.EncryptedEntryCount.HasValue ||
               view.ArchiveEntryCount.HasValue ||
               (view.ArchiveTopExtensions != null && view.ArchiveTopExtensions.Count > 0) ||
               !string.IsNullOrEmpty(view.InnerBinariesSummary) ||
               (view.ArchivePreview != null && view.ArchivePreview.Count > 0);

        static bool HasSignatureData(ReportView view)
            => view.WinTrustStatusCode.HasValue ||
               view.CertificateTableSize.HasValue ||
               !string.IsNullOrEmpty(view.CertificateBlobSha256) ||
               (view.EnhancedKeyUsages != null && view.EnhancedKeyUsages.Count > 0) ||
               !string.IsNullOrEmpty(view.TimestampAuthorityCN) ||
               !string.IsNullOrEmpty(view.SignerIssuerCN) ||
               !string.IsNullOrEmpty(view.SignerIssuerO) ||
               !string.IsNullOrEmpty(view.CertSubject) ||
               !string.IsNullOrEmpty(view.CertIssuer) ||
               !string.IsNullOrEmpty(view.CertThumbprint) ||
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
    }
}
