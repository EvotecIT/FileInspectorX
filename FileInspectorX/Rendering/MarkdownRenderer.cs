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

        // Risk assessment
        if (r.AssessmentScore.HasValue || !string.IsNullOrEmpty(r.AssessmentDecision))
        {
            sb.AppendLine("### Risk Assessment");
            sb.AppendLine($"- Score: {r.AssessmentScore ?? 0}");
            if (!string.IsNullOrEmpty(r.AssessmentDecision)) sb.AppendLine($"- Decision: {r.AssessmentDecision}");
            if (!string.IsNullOrEmpty(r.AssessmentCodesHuman)) sb.AppendLine($"- Drivers: {r.AssessmentCodesHuman}");
            sb.AppendLine();
        }
        return sb.ToString();
    }
}
