using System;
using System.Collections.Generic;
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
        if (!string.IsNullOrEmpty(r.DetectedTypeName) || !string.IsNullOrEmpty(r.DetectedTypeExtension))
        {
            sb.AppendLine($"### File Type");
            var type = (r.DetectedTypeName ?? "").Trim();
            if (!string.IsNullOrEmpty(r.DetectedTypeExtension)) type += $" ({r.DetectedTypeExtension})";
            if (!string.IsNullOrEmpty(r.DetectionConfidence)) type += $" — {r.DetectionConfidence}";
            if (!string.IsNullOrEmpty(r.DetectionReason)) type += $" — {r.DetectionReason}";
            if (!string.IsNullOrEmpty(r.DetectionReasonDetails)) type += $" ({r.DetectionReasonDetails})";
            sb.AppendLine(type);
            sb.AppendLine();
        }

        // Publisher/signature
        if (r.WinTrustStatusCode.HasValue || r.CertificateTableSize.HasValue)
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
            sb.AppendLine();
        }

        // Version info
        if (r.VersionInfo != null && r.VersionInfo.Count > 0)
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

        // Flags and findings
        if (!string.IsNullOrEmpty(r.FlagsHumanShort)) sb.AppendLine($"### Analysis Flags\n{r.FlagsHumanShort}\n");
        if (!string.IsNullOrEmpty(r.SecurityFindingsHumanShort)) sb.AppendLine($"### Heuristics\n{r.SecurityFindingsHumanShort}\n");
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
               (view.SecretsStripeLiveKeyCount ?? 0) > 0;

        static void AppendSecretCount(StringBuilder builder, string label, int? value)
        {
            if (!value.HasValue || value.Value <= 0) return;
            builder.AppendLine($"- {label}: {value.Value}");
        }
    }
}
