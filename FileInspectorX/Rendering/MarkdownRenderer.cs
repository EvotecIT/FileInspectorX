using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace FileInspectorX;

/// <summary>
/// Lightweight Markdown renderer for FileInspectorX results.
/// Keeps dependency-free formatting suitable for emails, CLI, or docs.
/// </summary>
public static partial class MarkdownRenderer
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
        if (!r.AnalysisComplete || r.Outcome != InspectionOutcome.Complete)
        {
            sb.AppendLine("### Analysis incomplete");
            sb.AppendLine("Some requested inspection stages did not complete. Review the recorded stage outcomes before relying on this report.");
            if (r.AnalysisIssues is { Count: > 0 })
                sb.AppendSafeLine($"- Issues: {string.Join(", ", r.AnalysisIssues)}");
            foreach (var stage in r.StageOutcomes.Where(stage => stage.Status is InspectionStageStatus.Partial or InspectionStageStatus.Unavailable or InspectionStageStatus.Failed))
                sb.AppendSafeLine($"- {stage.Stage}: {stage.Status} ({string.Join(", ", stage.Issues)})");
            sb.AppendLine();
        }
        if (!string.IsNullOrEmpty(r.Sha256Hex) || !string.IsNullOrEmpty(r.MagicHeaderHex))
        {
            sb.AppendLine("### Content identity");
            if (!string.IsNullOrEmpty(r.Sha256Hex)) sb.AppendSafeLine($"- SHA-256: {Code(r.Sha256Hex!)}");
            if (!string.IsNullOrEmpty(r.MagicHeaderHex)) sb.AppendSafeLine($"- Header (hex): {Code(r.MagicHeaderHex!)}");
            sb.AppendLine();
        }
        if (r.LearnedClassification is { } learned)
        {
            sb.AppendLine("### Learned classification");
            sb.AppendSafeLine($"- Disposition: {learned.Disposition}");
            if (!string.IsNullOrEmpty(learned.DeterministicExtension)) sb.AppendSafeLine($"- Deterministic type: {learned.DeterministicExtension}");
            if (learned.Prediction is { } prediction)
            {
                sb.AppendSafeLine($"- Provider: {prediction.Provider}");
                sb.AppendSafeLine($"- Prediction: {prediction.Extension} ({prediction.MimeType})");
                sb.AppendSafeLine($"- Probability: {prediction.Probability:0.####}");
                sb.AppendSafeLine($"- Threshold met: {prediction.ThresholdMet}");
            }
            if (!string.IsNullOrEmpty(learned.Message)) sb.AppendSafeLine($"- Detail: {learned.Message}");
            sb.AppendLine();
        }
        // Header
        if (HasTypeAnalysis(r))
        {
            sb.AppendLine("### File Type");
            var type = (r.DetectedTypeName ?? r.DetectedTypeFriendly ?? "").Trim();
            if (!string.IsNullOrEmpty(r.DetectedTypeExtension)) type += $" ({r.DetectedTypeExtension})";
            if (!string.IsNullOrEmpty(r.DetectionConfidence)) type += $" — {r.DetectionConfidence}";
            if (!string.IsNullOrEmpty(r.DetectionReason)) type += $" — {r.DetectionReason}";
            if (!string.IsNullOrEmpty(r.DetectionReasonDetails)) type += $" ({r.DetectionReasonDetails})";
            if (!string.IsNullOrWhiteSpace(type))
                sb.AppendTextLine(type);
            if (!string.IsNullOrEmpty(r.DetectionValidationStatus))
                sb.AppendSafeLine($"- Validation: {r.DetectionValidationStatus}");
            if (r.DetectionScore.HasValue)
                sb.AppendSafeLine($"- Score: {r.DetectionScore.Value}");
            if (r.DetectionIsDangerous.HasValue)
                sb.AppendSafeLine($"- Dangerous type: {(r.DetectionIsDangerous.Value ? "yes" : "no")}");
            if (!string.IsNullOrEmpty(r.GuessedExtension))
                sb.AppendSafeLine($"- Guessed extension: {r.GuessedExtension}");
            if (!string.IsNullOrEmpty(r.ContainerSubtype))
                sb.AppendSafeLine($"- Container subtype: {r.ContainerSubtype}");
            if (!string.IsNullOrEmpty(r.TextSubtype))
                sb.AppendSafeLine($"- Text subtype: {r.TextSubtype}");
            if (r.EstimatedLineCount.HasValue)
                sb.AppendSafeLine($"- Estimated lines: {r.EstimatedLineCount.Value}");
            if (!string.IsNullOrEmpty(r.PeMachine))
                sb.AppendSafeLine($"- PE machine: {r.PeMachine}");
            if (!string.IsNullOrEmpty(r.PeSubsystem))
                sb.AppendSafeLine($"- PE subsystem: {r.PeSubsystem}");
            if (!string.IsNullOrEmpty(r.PeKind))
                sb.AppendSafeLine($"- PE kind: {r.PeKind}");
            if (!string.IsNullOrEmpty(r.EncodedKind))
            {
                var encoded = r.EncodedKind;
                if (!string.IsNullOrEmpty(r.EncodedInnerDetectedFriendly))
                    encoded += $" -> {r.EncodedInnerDetectedFriendly}";
                else if (!string.IsNullOrEmpty(r.EncodedInnerDetectedName) || !string.IsNullOrEmpty(r.EncodedInnerDetectedExtension))
                    encoded += $" -> {(r.EncodedInnerDetectedName ?? "").Trim()}".TrimEnd();
                if (!string.IsNullOrEmpty(r.EncodedInnerDetectedExtension))
                    encoded += $" ({r.EncodedInnerDetectedExtension})";
                sb.AppendSafeLine($"- Encoded payload: {encoded}");
            }
            if (r.DetectionCandidates is { Count: > 0 })
                sb.AppendSafeLine($"- Candidates: {string.Join(", ", r.DetectionCandidates.Take(4).Select(FormatCandidate))}");
            if (r.DetectionAlternatives is { Count: > 0 })
                sb.AppendSafeLine($"- Alternatives: {string.Join(", ", r.DetectionAlternatives.Take(4).Select(FormatCandidate))}");
            sb.AppendLine();
        }

        // Publisher/signature
        if (HasSignatureData(r))
        {
            sb.AppendLine("### Signature");
            if (r.SignatureIsSigned.HasValue)
                sb.AppendSafeLine($"- Signature blob present: {(r.SignatureIsSigned.Value ? "yes" : "no")}");
            if (r.AuthenticodePresent.HasValue)
                sb.AppendSafeLine($"- Authenticode present: {(r.AuthenticodePresent.Value ? "yes" : "no")}");
            if (r.AuthenticodeEnvelopeValid.HasValue)
                sb.AppendSafeLine($"- Authenticode envelope valid: {(r.AuthenticodeEnvelopeValid.Value ? "yes" : "no")}");
            if (r.AuthenticodeChainValid.HasValue)
                sb.AppendSafeLine($"- Authenticode chain valid: {(r.AuthenticodeChainValid.Value ? "yes" : "no")}");
            if (r.AuthenticodeTimestampPresent.HasValue)
                sb.AppendSafeLine($"- Authenticode timestamp present: {(r.AuthenticodeTimestampPresent.Value ? "yes" : "no")}");
            if (!string.IsNullOrEmpty(r.AuthenticodeDigestAlgorithm))
                sb.AppendSafeLine($"- Authenticode digest algorithm: {r.AuthenticodeDigestAlgorithm}");
            if (!string.IsNullOrEmpty(r.AuthenticodeFileDigestAlgorithm))
                sb.AppendSafeLine($"- File digest algorithm: {r.AuthenticodeFileDigestAlgorithm}");
            if (!string.IsNullOrEmpty(r.AuthenticodeFileDigestAlgorithmOid))
                sb.AppendSafeLine($"- File digest algorithm OID: {r.AuthenticodeFileDigestAlgorithmOid}");
            if (!string.IsNullOrEmpty(r.SignerSubject))
                sb.AppendSafeLine($"- Signer subject: {r.SignerSubject}");
            if (!string.IsNullOrEmpty(r.SignerIssuer))
                sb.AppendSafeLine($"- Signer issuer: {r.SignerIssuer}");
            if (r.WinTrustStatusCode.HasValue)
            {
                var ok = r.IsTrustedWindowsPolicy == true ? "Trusted" : "Untrusted";
                sb.AppendSafeLine($"- WinTrust: {ok} (Status={r.WinTrustStatusCode})");
            }
            else if (r.IsTrustedWindowsPolicy.HasValue)
            {
                sb.AppendSafeLine($"- WinTrust policy trusted: {(r.IsTrustedWindowsPolicy.Value ? "yes" : "no")}");
            }
            if (r.CertificateTableSize.HasValue)
                sb.AppendSafeLine($"- Certificate Table: {r.CertificateTableSize} bytes");
            if (!string.IsNullOrEmpty(r.CertificateBlobSha256))
                sb.AppendSafeLine($"- PKCS#7 SHA-256: {Code(r.CertificateBlobSha256!)}");
            if (r.DotNetStrongNameSigned.HasValue)
                sb.AppendSafeLine($"- .NET strong-name signed: {(r.DotNetStrongNameSigned.Value ? "yes" : "no")}");
            if (r.EnhancedKeyUsages != null && r.EnhancedKeyUsages.Count > 0)
                sb.AppendSafeLine($"- EKUs: {string.Join(", ", r.EnhancedKeyUsages)}");
            if (!string.IsNullOrEmpty(r.SignerSubjectCN))
                sb.AppendSafeLine($"- Signer subject CN: {r.SignerSubjectCN}");
            if (!string.IsNullOrEmpty(r.SignerSubjectO))
                sb.AppendSafeLine($"- Signer subject O: {r.SignerSubjectO}");
            if (!string.IsNullOrEmpty(r.TimestampAuthorityCN))
                sb.AppendSafeLine($"- Timestamp Authority: {r.TimestampAuthorityCN}");
            else if (!string.IsNullOrEmpty(r.TimestampAuthority))
                sb.AppendSafeLine($"- Timestamp Authority: {r.TimestampAuthority}");
            if (r.TimestampTime.HasValue)
                sb.AppendSafeLine($"- Timestamp time: {r.TimestampTime.Value:u}");
            if (!string.IsNullOrEmpty(r.SignerIssuerCN))
                sb.AppendSafeLine($"- Signer issuer CN: {r.SignerIssuerCN}");
            if (!string.IsNullOrEmpty(r.SignerIssuerO))
                sb.AppendSafeLine($"- Signer issuer O: {r.SignerIssuerO}");
            if (r.SignerSelfSigned.HasValue)
                sb.AppendSafeLine($"- Signer self-signed: {(r.SignerSelfSigned.Value ? "yes" : "no")}");
            if (!string.IsNullOrEmpty(r.SignerThumbprint))
                sb.AppendSafeLine($"- Signer thumbprint: {r.SignerThumbprint}");
            if (!string.IsNullOrEmpty(r.SignerSerialHex))
                sb.AppendSafeLine($"- Signer serial: {r.SignerSerialHex}");
            if (!string.IsNullOrEmpty(r.SignerSignatureAlgorithm))
                sb.AppendSafeLine($"- Signer signature algorithm: {r.SignerSignatureAlgorithm}");
            if (r.SignerNotBefore.HasValue)
                sb.AppendSafeLine($"- Signer not before: {r.SignerNotBefore.Value:u}");
            if (r.SignerNotAfter.HasValue)
                sb.AppendSafeLine($"- Signer not after: {r.SignerNotAfter.Value:u}");
            if (r.AuthenticodeFileHashMatches.HasValue)
                sb.AppendSafeLine($"- Authenticode file hash matches: {(r.AuthenticodeFileHashMatches.Value ? "yes" : "no")}");
            if (!string.IsNullOrEmpty(r.AuthenticodeVerificationNote))
                sb.AppendSafeLine($"- Verification note: {r.AuthenticodeVerificationNote}");
            if (!string.IsNullOrEmpty(r.CertSubject))
                sb.AppendSafeLine($"- Certificate subject: {r.CertSubject}");
            if (!string.IsNullOrEmpty(r.CertIssuer))
                sb.AppendSafeLine($"- Certificate issuer: {r.CertIssuer}");
            if (r.CertNotBefore.HasValue)
                sb.AppendSafeLine($"- Certificate not before: {r.CertNotBefore.Value:u}");
            if (r.CertNotAfter.HasValue)
                sb.AppendSafeLine($"- Certificate not after: {r.CertNotAfter.Value:u}");
            if (!string.IsNullOrEmpty(r.CertThumbprint))
                sb.AppendSafeLine($"- Certificate thumbprint: {r.CertThumbprint}");
            if (!string.IsNullOrEmpty(r.CertKeyAlgorithm))
                sb.AppendSafeLine($"- Certificate key algorithm: {r.CertKeyAlgorithm}");
            if (r.CertSelfSigned.HasValue)
                sb.AppendSafeLine($"- Certificate self-signed: {(r.CertSelfSigned.Value ? "yes" : "no")}");
            if (r.CertChainTrusted.HasValue)
                sb.AppendSafeLine($"- Certificate chain trusted: {(r.CertChainTrusted.Value ? "yes" : "no")}");
            if (!string.IsNullOrEmpty(r.CertRootSubject))
                sb.AppendSafeLine($"- Certificate root subject: {r.CertRootSubject}");
            if (r.CertSanPresent.HasValue)
                sb.AppendSafeLine($"- Certificate SAN present: {(r.CertSanPresent.Value ? "yes" : "no")}");
            if (r.CertBundleCount.HasValue)
                sb.AppendSafeLine($"- Certificate bundle count: {r.CertBundleCount.Value}");
            if (r.CertBundleSubjects != null && r.CertBundleSubjects.Count > 0)
                sb.AppendSafeLine($"- Certificate bundle subjects: {string.Join(", ", r.CertBundleSubjects)}");
            sb.AppendLine();
        }

        // Version info
        if (HasPropertiesData(r))
        {
            sb.AppendLine("### Properties");
            if (r.ShellPropertyCount.HasValue) sb.AppendSafeLine($"- Shell properties: {r.ShellPropertyCount.Value}");
            if (r.ShellPropertyPreview != null && r.ShellPropertyPreview.Count > 0)
                sb.AppendSafeLine($"- Shell property preview: {string.Join("; ", r.ShellPropertyPreview.Take(4))}");
            if (!string.IsNullOrEmpty(r.CompanyName)) sb.AppendSafeLine($"- Company: {r.CompanyName}");
            if (!string.IsNullOrEmpty(r.ProductName)) sb.AppendSafeLine($"- Product: {r.ProductName}");
            if (!string.IsNullOrEmpty(r.FileDescription)) sb.AppendSafeLine($"- Description: {r.FileDescription}");
            if (!string.IsNullOrEmpty(r.FileVersion)) sb.AppendSafeLine($"- FileVersion: {r.FileVersion}");
            if (!string.IsNullOrEmpty(r.ProductVersion)) sb.AppendSafeLine($"- ProductVersion: {r.ProductVersion}");
            if (!string.IsNullOrEmpty(r.OriginalFilename)) sb.AppendSafeLine($"- OriginalFilename: {r.OriginalFilename}");
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
                    sb.AppendSafeLine($"- {entry.Key}: {entry.Value}");
                }
            }
            sb.AppendLine();
        }

        if (HasSecurityData(r))
        {
            sb.AppendLine("### Security");
            if (r.IsSymlink.HasValue) sb.AppendSafeLine($"- Symlink: {(r.IsSymlink.Value ? "yes" : "no")}");
            if (r.IsHidden.HasValue) sb.AppendSafeLine($"- Hidden: {(r.IsHidden.Value ? "yes" : "no")}");
            if (r.IsReadOnly.HasValue) sb.AppendSafeLine($"- Read-only: {(r.IsReadOnly.Value ? "yes" : "no")}");
            if (!string.IsNullOrEmpty(r.Owner)) sb.AppendSafeLine($"- Owner: {r.Owner}");
            if (!string.IsNullOrEmpty(r.OwnerId)) sb.AppendSafeLine($"- Owner ID: {r.OwnerId}");
            if (!string.IsNullOrEmpty(r.Group)) sb.AppendSafeLine($"- Group: {r.Group}");
            if (!string.IsNullOrEmpty(r.GroupId)) sb.AppendSafeLine($"- Group ID: {r.GroupId}");
            if (!string.IsNullOrEmpty(r.ModeOctal)) sb.AppendSafeLine($"- Mode (octal): {r.ModeOctal}");
            if (!string.IsNullOrEmpty(r.ModeSymbolic)) sb.AppendSafeLine($"- Mode (symbolic): {r.ModeSymbolic}");
            if (r.IsExecutable.HasValue) sb.AppendSafeLine($"- Executable: {(r.IsExecutable.Value ? "yes" : "no")}");
            if (r.IsWorldWritable.HasValue) sb.AppendSafeLine($"- World-writable: {(r.IsWorldWritable.Value ? "yes" : "no")}");
            if (r.EveryoneWriteAllowed.HasValue) sb.AppendSafeLine($"- Everyone write allowed: {(r.EveryoneWriteAllowed.Value ? "yes" : "no")}");
            if (r.AuthenticatedUsersWriteAllowed.HasValue) sb.AppendSafeLine($"- Authenticated Users write allowed: {(r.AuthenticatedUsersWriteAllowed.Value ? "yes" : "no")}");
            if (r.EveryoneReadAllowed.HasValue) sb.AppendSafeLine($"- Everyone read allowed: {(r.EveryoneReadAllowed.Value ? "yes" : "no")}");
            if (r.BuiltinUsersWriteAllowed.HasValue) sb.AppendSafeLine($"- BUILTIN\\Users write allowed: {(r.BuiltinUsersWriteAllowed.Value ? "yes" : "no")}");
            if (r.BuiltinUsersReadAllowed.HasValue) sb.AppendSafeLine($"- BUILTIN\\Users read allowed: {(r.BuiltinUsersReadAllowed.Value ? "yes" : "no")}");
            if (r.AdministratorsWriteAllowed.HasValue) sb.AppendSafeLine($"- BUILTIN\\Administrators write allowed: {(r.AdministratorsWriteAllowed.Value ? "yes" : "no")}");
            if (r.AdministratorsReadAllowed.HasValue) sb.AppendSafeLine($"- BUILTIN\\Administrators read allowed: {(r.AdministratorsReadAllowed.Value ? "yes" : "no")}");
            if (r.HasDenyEntries.HasValue) sb.AppendSafeLine($"- Has deny ACEs: {(r.HasDenyEntries.Value ? "yes" : "no")}");
            if (r.TotalAllowCount.HasValue) sb.AppendSafeLine($"- Total allow ACEs: {r.TotalAllowCount.Value}");
            if (r.TotalDenyCount.HasValue) sb.AppendSafeLine($"- Total deny ACEs: {r.TotalDenyCount.Value}");
            if (r.ExplicitAllowCount.HasValue) sb.AppendSafeLine($"- Explicit allow ACEs: {r.ExplicitAllowCount.Value}");
            if (r.ExplicitDenyCount.HasValue) sb.AppendSafeLine($"- Explicit deny ACEs: {r.ExplicitDenyCount.Value}");
            if (r.MotwZoneId.HasValue) sb.AppendSafeLine($"- MOTW ZoneId: {r.MotwZoneId.Value}");
            if (!string.IsNullOrEmpty(r.MotwReferrerUrl)) sb.AppendSafeLine($"- MOTW Referrer URL: {r.MotwReferrerUrl}");
            if (!string.IsNullOrEmpty(r.MotwHostUrl)) sb.AppendSafeLine($"- MOTW Host URL: {r.MotwHostUrl}");
            if (r.AlternateStreamCount.HasValue) sb.AppendSafeLine($"- Alternate stream count: {r.AlternateStreamCount.Value}");
            if (!string.IsNullOrEmpty(r.NameIssuesCsv)) sb.AppendSafeLine($"- Name issues: {r.NameIssuesCsv}");
            sb.AppendLine();
        }

        if (HasScriptData(r))
        {
            sb.AppendLine("### Script");
            if (!string.IsNullOrEmpty(r.ScriptLanguageHuman)) sb.AppendSafeLine($"- Language: {r.ScriptLanguageHuman}");
            else if (!string.IsNullOrEmpty(r.ScriptLanguage)) sb.AppendSafeLine($"- Language: {r.ScriptLanguage}");
            if (!string.IsNullOrEmpty(r.ScriptCmdlets)) sb.AppendSafeLine($"- Cmdlets: {r.ScriptCmdlets}");
            sb.AppendLine();
        }

        if (HasReferenceData(r))
        {
            sb.AppendLine("### References");
            if (!string.IsNullOrEmpty(r.HtmlExternalLinksSample)) sb.AppendSafeLine($"- HTML external links: {r.HtmlExternalLinksSample}");
            if (!string.IsNullOrEmpty(r.HtmlUncSample)) sb.AppendSafeLine($"- HTML UNC paths: {r.HtmlUncSample}");
            if (!string.IsNullOrEmpty(r.ScriptUrlsSample)) sb.AppendSafeLine($"- Script URLs: {r.ScriptUrlsSample}");
            if (!string.IsNullOrEmpty(r.ScriptUncSample)) sb.AppendSafeLine($"- Script UNC paths: {r.ScriptUncSample}");
            if (r.OfficeExternalLinksCount.HasValue) sb.AppendSafeLine($"- Office external links: {r.OfficeExternalLinksCount.Value}");
            if (!string.IsNullOrEmpty(r.HtmlExternalLinksFull)) sb.AppendSafeLine($"- HTML external links (full): {r.HtmlExternalLinksFull}");
            if (!string.IsNullOrEmpty(r.HtmlUncFull)) sb.AppendSafeLine($"- HTML UNC paths (full): {r.HtmlUncFull}");
            if (!string.IsNullOrEmpty(r.ScriptUrlsFull)) sb.AppendSafeLine($"- Script URLs (full): {r.ScriptUrlsFull}");
            if (!string.IsNullOrEmpty(r.ScriptUncFull)) sb.AppendSafeLine($"- Script UNC paths (full): {r.ScriptUncFull}");
            sb.AppendLine();
        }

        if (HasInstallerData(r))
        {
            sb.AppendLine("### Installer");
            if (!string.IsNullOrEmpty(r.InstallerKind)) sb.AppendSafeLine($"- Kind: {r.InstallerKind}");
            if (!string.IsNullOrEmpty(r.InstallerName)) sb.AppendSafeLine($"- Name: {r.InstallerName}");
            if (!string.IsNullOrEmpty(r.InstallerManufacturer)) sb.AppendSafeLine($"- Manufacturer: {r.InstallerManufacturer}");
            if (!string.IsNullOrEmpty(r.InstallerIdentityName)) sb.AppendSafeLine($"- Identity: {r.InstallerIdentityName}");
            if (!string.IsNullOrEmpty(r.InstallerVersion)) sb.AppendSafeLine($"- Version: {r.InstallerVersion}");
            if (!string.IsNullOrEmpty(r.InstallerProductCode)) sb.AppendSafeLine($"- ProductCode: {r.InstallerProductCode}");
            if (!string.IsNullOrEmpty(r.InstallerUpgradeCode)) sb.AppendSafeLine($"- UpgradeCode: {r.InstallerUpgradeCode}");
            if (!string.IsNullOrEmpty(r.InstallerPackageCode)) sb.AppendSafeLine($"- PackageCode: {r.InstallerPackageCode}");
            if (!string.IsNullOrEmpty(r.InstallerScope)) sb.AppendSafeLine($"- Scope: {r.InstallerScope}");
            if (!string.IsNullOrEmpty(r.InstallerAuthor)) sb.AppendSafeLine($"- Author: {r.InstallerAuthor}");
            if (!string.IsNullOrEmpty(r.InstallerComments)) sb.AppendSafeLine($"- Comments: {r.InstallerComments}");
            if (!string.IsNullOrEmpty(r.InstallerUrlInfoAbout)) sb.AppendSafeLine($"- Info URL: {r.InstallerUrlInfoAbout}");
            if (!string.IsNullOrEmpty(r.InstallerUrlUpdateInfo)) sb.AppendSafeLine($"- Update URL: {r.InstallerUrlUpdateInfo}");
            if (!string.IsNullOrEmpty(r.InstallerHelpLink)) sb.AppendSafeLine($"- Help link: {r.InstallerHelpLink}");
            if (!string.IsNullOrEmpty(r.InstallerSupportUrl)) sb.AppendSafeLine($"- Support URL: {r.InstallerSupportUrl}");
            if (!string.IsNullOrEmpty(r.InstallerContact)) sb.AppendSafeLine($"- Contact: {r.InstallerContact}");
            if (!string.IsNullOrEmpty(r.InstallerCreated)) sb.AppendSafeLine($"- Created: {r.InstallerCreated}");
            if (!string.IsNullOrEmpty(r.InstallerLastSaved)) sb.AppendSafeLine($"- Last saved: {r.InstallerLastSaved}");
            if (!string.IsNullOrEmpty(r.InstallerCapabilities)) sb.AppendSafeLine($"- Capabilities: {r.InstallerCapabilities}");
            if (!string.IsNullOrEmpty(r.InstallerExtensions)) sb.AppendSafeLine($"- Extensions: {r.InstallerExtensions}");
            if (r._MsiCAExe.HasValue) sb.AppendSafeLine($"- MSI custom actions (EXE): {r._MsiCAExe.Value}");
            if (r._MsiCADll.HasValue) sb.AppendSafeLine($"- MSI custom actions (DLL): {r._MsiCADll.Value}");
            if (r._MsiCAScript.HasValue) sb.AppendSafeLine($"- MSI custom actions (script): {r._MsiCAScript.Value}");
            if (r._MsiCAOther.HasValue) sb.AppendSafeLine($"- MSI custom actions (other): {r._MsiCAOther.Value}");
            if (!string.IsNullOrEmpty(r._MsiCASamples)) sb.AppendSafeLine($"- MSI custom action samples: {r._MsiCASamples}");
            sb.AppendLine();
        }

        if (HasArchiveData(r))
        {
            sb.AppendLine("### Archive");
            if (r.EncryptedEntryCount.HasValue) sb.AppendSafeLine($"- Encrypted entries: {r.EncryptedEntryCount.Value}");
            if (r.ArchiveEntryCount.HasValue) sb.AppendSafeLine($"- Entry count: {r.ArchiveEntryCount.Value}");
            if (r.ArchiveTopExtensions != null && r.ArchiveTopExtensions.Count > 0)
                sb.AppendSafeLine($"- Top extensions: {string.Join(", ", r.ArchiveTopExtensions)}");
            if (r.InnerExecutablesSampled.HasValue) sb.AppendSafeLine($"- Inner binaries sampled: {r.InnerExecutablesSampled.Value}");
            if (r.InnerSignedExecutables.HasValue) sb.AppendSafeLine($"- Inner signed binaries: {r.InnerSignedExecutables.Value}");
            if (r.InnerValidSignedExecutables.HasValue) sb.AppendSafeLine($"- Inner validly signed binaries: {r.InnerValidSignedExecutables.Value}");
            if (!string.IsNullOrEmpty(r.InnerPublishersHuman))
                sb.AppendSafeLine($"- Inner publishers: {r.InnerPublishersHuman}");
            else if (r.InnerPublisherCounts != null && r.InnerPublisherCounts.Count > 0)
                sb.AppendSafeLine($"- Inner publishers: {string.Join(", ", FormatInnerPublishers(r).Take(5))}");
            if (r.InnerExecutableExtCounts != null && r.InnerExecutableExtCounts.Count > 0)
            {
                var topExts = r.InnerExecutableExtCounts
                    .OrderByDescending(kv => kv.Value)
                    .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                    .Take(6)
                    .Select(kv => $"{kv.Key}={kv.Value}");
                sb.AppendSafeLine($"- {GetInnerTypeSummaryLabel(r.InnerExecutableExtCounts)}: {string.Join(", ", topExts)}");
            }
            if (!string.IsNullOrEmpty(r.InnerBinariesSummary))
                sb.AppendSafeLine($"- {r.InnerBinariesSummary}");
            if (r.ArchivePreview != null && r.ArchivePreview.Count > 0)
                sb.AppendSafeLine($"- Preview: {string.Join(", ", r.ArchivePreview.Take(6))}");
            sb.AppendLine();
        }

        // Flags and findings
        if (!string.IsNullOrEmpty(r.FlagsHumanShort) || !string.IsNullOrEmpty(r.FlagsHumanLong) || !string.IsNullOrEmpty(r.FlagsCsv))
        {
            sb.AppendLine("### Analysis Flags");
            if (!string.IsNullOrEmpty(r.FlagsHumanShort))
                sb.AppendTextLine(r.FlagsHumanShort);
            else if (!string.IsNullOrEmpty(r.FlagsCsv))
                sb.AppendSafeLine($"Flags: {r.FlagsCsv}");
            if (!string.IsNullOrEmpty(r.FlagsHumanLong) &&
                !string.Equals(r.FlagsHumanLong, r.FlagsHumanShort, StringComparison.Ordinal))
            {
                sb.AppendSafeLine($"Details: {r.FlagsHumanLong}");
            }
            sb.AppendLine();
        }
        if (!string.IsNullOrEmpty(r.SecurityFindingsHumanShort) ||
            (r.SecurityFindings != null && r.SecurityFindings.Count > 0) ||
            (r.TopTokens != null && r.TopTokens.Count > 0))
        {
            sb.AppendLine("### Heuristics");
            if (!string.IsNullOrEmpty(r.SecurityFindingsHumanShort))
                sb.AppendTextLine(r.SecurityFindingsHumanShort);
            else if (r.SecurityFindings is { Count: > 0 })
                sb.AppendSafeLine($"Findings: {string.Join(", ", r.SecurityFindings.Take(8))}");
            if (!string.IsNullOrEmpty(r.SecurityFindingsHumanLong) &&
                !string.Equals(r.SecurityFindingsHumanLong, r.SecurityFindingsHumanShort, StringComparison.Ordinal))
            {
                sb.AppendSafeLine($"Details: {r.SecurityFindingsHumanLong}");
            }
            if (r.TopTokens is { Count: > 0 })
                sb.AppendSafeLine($"Top tokens: {string.Join(", ", r.TopTokens.Take(8))}");
            sb.AppendLine();
        }
        if (!string.IsNullOrEmpty(r.InnerFindingsHumanShort) ||
            !string.IsNullOrEmpty(r.InnerFindingsHumanLong) ||
            (r.InnerFindings != null && r.InnerFindings.Count > 0))
        {
            sb.AppendLine("### Inner Findings");
            if (!string.IsNullOrEmpty(r.InnerFindingsHumanShort))
                sb.AppendTextLine(r.InnerFindingsHumanShort);
            else if (r.InnerFindings is { Count: > 0 })
                sb.AppendSafeLine($"Findings: {string.Join(", ", r.InnerFindings.Take(8))}");
            if (!string.IsNullOrEmpty(r.InnerFindingsHumanLong) &&
                !string.Equals(r.InnerFindingsHumanLong, r.InnerFindingsHumanShort, StringComparison.Ordinal))
            {
                sb.AppendSafeLine($"Details: {r.InnerFindingsHumanLong}");
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
                    var evidence = InlineEvidence(f.Evidence);
                    sb.AppendSafeLine($"  - [{f.Confidence}] {f.Code}{linePart}{evidence}");
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
                sb.AppendSafeLine($"- Score: {r.AssessmentScore.Value}");
            if (!string.IsNullOrEmpty(r.AssessmentDecision)) sb.AppendSafeLine($"- Decision: {r.AssessmentDecision}");
            if (!string.IsNullOrEmpty(r.AssessmentDecisionStrict) ||
                !string.IsNullOrEmpty(r.AssessmentDecisionBalanced) ||
                !string.IsNullOrEmpty(r.AssessmentDecisionLenient))
            {
                sb.AppendSafeLine($"- Profile decisions: Strict={r.AssessmentDecisionStrict ?? "n/a"}, Balanced={r.AssessmentDecisionBalanced ?? r.AssessmentDecision ?? "n/a"}, Lenient={r.AssessmentDecisionLenient ?? "n/a"}");
            }
            if (!string.IsNullOrEmpty(r.AssessmentCodesHuman)) sb.AppendSafeLine($"- Drivers: {r.AssessmentCodesHuman}");
            else if (r.AssessmentCodes is { Count: > 0 }) sb.AppendSafeLine($"- Codes: {string.Join(", ", r.AssessmentCodes)}");
            if (!string.IsNullOrEmpty(r.AssessmentCodesHumanLong)) sb.AppendSafeLine($"- Drivers (long): {r.AssessmentCodesHumanLong}");
            if (r.AssessmentFactors != null && r.AssessmentFactors.Count > 0)
            {
                var topFactors = r.AssessmentFactors
                    .OrderByDescending(kv => Math.Abs(kv.Value))
                    .ThenBy(kv => kv.Key, StringComparer.Ordinal)
                    .Take(6)
                    .Select(kv => $"{kv.Key}={kv.Value}");
                sb.AppendSafeLine($"- Factors: {string.Join(", ", topFactors)}");
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
            builder.AppendSafeLine($"- {label}: {value.Value}");
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
               !string.IsNullOrEmpty(view.InstallerIdentityName) ||
               !string.IsNullOrEmpty(view.InstallerVersion) ||
               !string.IsNullOrEmpty(view.InstallerProductCode) ||
               !string.IsNullOrEmpty(view.InstallerUpgradeCode) ||
               !string.IsNullOrEmpty(view.InstallerPackageCode) ||
               !string.IsNullOrEmpty(view.InstallerScope) ||
               !string.IsNullOrEmpty(view.InstallerAuthor) ||
               !string.IsNullOrEmpty(view.InstallerComments) ||
               !string.IsNullOrEmpty(view.InstallerUrlInfoAbout) ||
               !string.IsNullOrEmpty(view.InstallerUrlUpdateInfo) ||
               !string.IsNullOrEmpty(view.InstallerHelpLink) ||
               !string.IsNullOrEmpty(view.InstallerSupportUrl) ||
               !string.IsNullOrEmpty(view.InstallerContact) ||
               !string.IsNullOrEmpty(view.InstallerCreated) ||
               !string.IsNullOrEmpty(view.InstallerLastSaved) ||
               !string.IsNullOrEmpty(view.InstallerCapabilities) ||
               !string.IsNullOrEmpty(view.InstallerExtensions) ||
               view._MsiCAExe.HasValue ||
               view._MsiCADll.HasValue ||
               view._MsiCAScript.HasValue ||
               view._MsiCAOther.HasValue ||
               !string.IsNullOrEmpty(view._MsiCASamples);

        static bool HasPropertiesData(ReportView view)
            => (view.VersionInfo != null && view.VersionInfo.Count > 0) ||
               view.ShellPropertyCount.HasValue ||
               (view.ShellPropertyPreview != null && view.ShellPropertyPreview.Count > 0) ||
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
               view.AuthenticodeEnvelopeValid.HasValue ||
               view.AuthenticodeChainValid.HasValue ||
               view.AuthenticodeTimestampPresent.HasValue ||
               !string.IsNullOrEmpty(view.AuthenticodeDigestAlgorithm) ||
               !string.IsNullOrEmpty(view.AuthenticodeFileDigestAlgorithm) ||
               !string.IsNullOrEmpty(view.AuthenticodeFileDigestAlgorithmOid) ||
               !string.IsNullOrEmpty(view.SignerSubject) ||
               !string.IsNullOrEmpty(view.SignerIssuer) ||
               view.IsTrustedWindowsPolicy.HasValue ||
               view.WinTrustStatusCode.HasValue ||
               !string.IsNullOrEmpty(view.SignerSubjectCN) ||
               !string.IsNullOrEmpty(view.SignerSubjectO) ||
               view.SignerSelfSigned.HasValue ||
               !string.IsNullOrEmpty(view.SignerThumbprint) ||
               !string.IsNullOrEmpty(view.SignerSerialHex) ||
               !string.IsNullOrEmpty(view.SignerSignatureAlgorithm) ||
               view.SignerNotBefore.HasValue ||
               view.SignerNotAfter.HasValue ||
               view.TimestampTime.HasValue ||
               !string.IsNullOrEmpty(view.TimestampAuthority) ||
               !string.IsNullOrEmpty(view.AuthenticodeVerificationNote) ||
               view.AuthenticodeFileHashMatches.HasValue ||
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

        static string GetInnerTypeSummaryLabel(IReadOnlyDictionary<string, int>? counts)
        {
            if (counts == null || counts.Count == 0)
            {
                return "Inner types";
            }

            var keys = counts.Keys
                .Where(static key => !string.IsNullOrWhiteSpace(key))
                .Select(static key => key.Trim().TrimStart('.'))
                .ToArray();

            bool hasScript = keys.Any(IsScriptTypeKey);
            bool hasInstaller = keys.Any(IsInstallerTypeKey);
            bool hasExecutable = keys.Any(IsExecutableTypeKey);

            if (hasScript && !hasInstaller && !hasExecutable) return "Inner script types";
            if (!hasScript && hasInstaller && !hasExecutable) return "Inner installer/package types";
            if (!hasScript && !hasInstaller && hasExecutable) return "Inner executable types";
            if (hasScript && hasExecutable && !hasInstaller) return "Inner script/executable types";
            if (hasInstaller && hasExecutable && !hasScript) return "Inner executable/installer types";
            if (hasScript && hasInstaller && !hasExecutable) return "Inner script/installer types";
            return "Inner active types";
        }

        static bool IsExecutableTypeKey(string value)
        {
            var key = value.Trim().TrimStart('.').ToLowerInvariant();
            return key is "exe" or "dll" or "scr" or "com";
        }

        static bool IsInstallerTypeKey(string value)
        {
            var key = value.Trim().TrimStart('.').ToLowerInvariant();
            return key is "msi" or "msix" or "appx" or "msixbundle" or "msu";
        }

        static bool IsScriptTypeKey(string value)
        {
            var key = value.Trim().TrimStart('.').ToLowerInvariant();
            return key is "ps1" or "psm1" or "psd1" or "bat" or "cmd" or "sh" or "bash" or "zsh" or "ksh" or "vbs" or "js" or "mjs" or "py" or "rb" or "lua";
        }
    }
}
