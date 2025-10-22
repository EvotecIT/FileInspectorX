namespace FileInspectorX;

/// <summary>
/// Flattened, presentation-friendly summary of a FileAnalysis, with helpers to export a key/value map.
/// Intended to let hosts (like TierBridge) present findings without reassembling logic.
/// </summary>
/// <summary>
/// Flattened analysis summary for presentation.
/// </summary>
public sealed class ReportView
{
    /// <summary>Detected extension.</summary>
    public string? DetectedTypeExtension { get; set; }
    /// <summary>Detected MIME type.</summary>
    public string? DetectedTypeName { get; set; }
    /// <summary>Detection confidence (High/Medium/Low).</summary>
    public string? DetectionConfidence { get; set; }
    /// <summary>Short textual reason describing the detection.</summary>
    public string? DetectionReason { get; set; }
    /// <summary>Best-guess extension when ambiguous.</summary>
    public string? GuessedExtension { get; set; }

    /// <summary>WinVerifyTrust final policy verdict (Windows only).</summary>
    public bool? IsTrustedWindowsPolicy { get; set; }
    /// <summary>Raw WinVerifyTrust status code (0 = success).</summary>
    public int? WinTrustStatusCode { get; set; }

    /// <summary>Raw version information as a name/value map.</summary>
    public IReadOnlyDictionary<string,string>? VersionInfo { get; set; }
    /// <summary>Company name from version info.</summary>
    public string? CompanyName { get; set; }
    /// <summary>Product name from version info.</summary>
    public string? ProductName { get; set; }
    /// <summary>File description from version info.</summary>
    public string? FileDescription { get; set; }
    /// <summary>File version string.</summary>
    public string? FileVersion { get; set; }
    /// <summary>Product version string.</summary>
    public string? ProductVersion { get; set; }
    /// <summary>Original filename from version info.</summary>
    public string? OriginalFilename { get; set; }

    /// <summary>Compact comma-separated flag codes suitable for humanization by hosts.</summary>
    public string? FlagsCsv { get; set; }

    /// <summary>Size of the certificate table (PE) when present.</summary>
    public int? CertificateTableSize { get; set; }
    /// <summary>SHA-256 of the raw certificate blob (PE) when present.</summary>
    public string? CertificateBlobSha256 { get; set; }

    /// <summary>Risk score 0-100.</summary>
    public int? AssessmentScore { get; set; }
    /// <summary>Decision label (Allow/Warn/Block/Defer).</summary>
    public string? AssessmentDecision { get; set; }
    /// <summary>Finding codes that drove the score.</summary>
    public IReadOnlyList<string>? AssessmentCodes { get; set; }
    /// <summary>Score contributions by code.</summary>
    public IReadOnlyDictionary<string,int>? AssessmentFactors { get; set; }
    /// <summary>Number of encrypted entries in ZIP (if applicable).</summary>
    public int? EncryptedEntryCount { get; set; }
    /// <summary>Neutral security findings emitted by heuristics (e.g., ps:encoded, js:activex).</summary>
    public IReadOnlyList<string>? SecurityFindings { get; set; }

    /// <summary>
    /// Creates a report view from a FileAnalysis instance.
    /// </summary>
    public static ReportView From(FileAnalysis a)
    {
        var r = new ReportView();
        if (a.Detection != null)
        {
            r.DetectedTypeExtension = a.Detection.Extension;
            r.DetectedTypeName = a.Detection.MimeType;
            r.DetectionConfidence = a.Detection.Confidence;
            r.DetectionReason = a.Detection.Reason;
            if (!string.IsNullOrEmpty(a.Detection.GuessedExtension)) r.GuessedExtension = a.Detection.GuessedExtension;
        }
        if (a.Authenticode != null)
        {
            r.IsTrustedWindowsPolicy = a.Authenticode.IsTrustedWindowsPolicy;
            r.WinTrustStatusCode = a.Authenticode.WinTrustStatusCode;
        }
        if (a.VersionInfo != null)
        {
            r.VersionInfo = a.VersionInfo;
            a.VersionInfo.TryGetValue("CompanyName", out var company);
            a.VersionInfo.TryGetValue("ProductName", out var product);
            a.VersionInfo.TryGetValue("FileDescription", out var fileDesc);
            a.VersionInfo.TryGetValue("FileVersion", out var fver);
            a.VersionInfo.TryGetValue("ProductVersion", out var pver);
            a.VersionInfo.TryGetValue("OriginalFilename", out var origFile);
            r.CompanyName = company; r.ProductName = product; r.FileDescription = fileDesc; r.FileVersion = fver; r.ProductVersion = pver; r.OriginalFilename = origFile;
        }
        // Flags → compact CSV codes for presentation layers to humanize
        var codes = new List<string>(12);
        var f = a.Flags;
        if ((f & ContentFlags.HasOoxmlMacros) != 0) codes.Add("Macros");
        if ((f & ContentFlags.ContainerContainsExecutables) != 0) codes.Add("HasExe");
        if ((f & ContentFlags.ContainerContainsScripts) != 0) codes.Add("HasScript");
        if ((f & ContentFlags.PdfHasJavaScript) != 0) codes.Add("PdfJS");
        if ((f & ContentFlags.PdfHasOpenAction) != 0) codes.Add("PdfOpen");
        if ((f & ContentFlags.PdfHasAA) != 0) codes.Add("PdfAA");
        if ((f & ContentFlags.PeIsDotNet) != 0) codes.Add("DotNet");
        if ((f & ContentFlags.ArchiveHasEncryptedEntries) != 0) codes.Add("ZipEnc");
        if ((f & ContentFlags.OoxmlEncrypted) != 0) codes.Add("OoxmlEnc");
        if ((f & ContentFlags.ContainerHasDisguisedExecutables) != 0) codes.Add("DisgExec");
        if ((f & ContentFlags.PeHasAuthenticodeDirectory) != 0) codes.Add("SigPresent");
        if (codes.Count > 0) r.FlagsCsv = string.Join(",", codes);

        if (a.Signature != null)
        {
            r.CertificateTableSize = a.Signature.CertificateTableSize;
            if (!string.IsNullOrEmpty(a.Signature.CertificateBlobSha256)) r.CertificateBlobSha256 = a.Signature.CertificateBlobSha256;
        }

        try
        {
            var assess = FileInspector.Assess(a);
            r.AssessmentScore = assess.Score;
            r.AssessmentDecision = assess.Decision.ToString();
            r.AssessmentCodes = assess.Codes;
            r.AssessmentFactors = assess.Factors;
        } catch { }
        r.EncryptedEntryCount = a.EncryptedEntryCount;
        r.SecurityFindings = a.SecurityFindings;

        return r;
    }

    /// <summary>
    /// Exports the report as a dictionary compatible with typical templating and logging sinks.
    /// </summary>
    /// <summary>Exports the report as a key/value map.</summary>
    public Dictionary<string, object?> ToDictionary()
    {
        var d = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        if (DetectedTypeExtension != null) d["DetectedTypeExtension"] = DetectedTypeExtension;
        if (DetectedTypeName != null) d["DetectedTypeName"] = DetectedTypeName;
        if (DetectionConfidence != null) d["DetectionConfidence"] = DetectionConfidence;
        if (DetectionReason != null) d["DetectionReason"] = DetectionReason;
        if (!string.IsNullOrEmpty(GuessedExtension)) d["GuessedExtension"] = GuessedExtension;
        if (IsTrustedWindowsPolicy.HasValue) d["IsTrustedWindowsPolicy"] = IsTrustedWindowsPolicy.Value;
        if (WinTrustStatusCode.HasValue) d["WinTrustStatusCode"] = WinTrustStatusCode.Value;
        if (VersionInfo != null) d["VersionInfo"] = VersionInfo;
        if (CompanyName != null) d["CompanyName"] = CompanyName;
        if (ProductName != null) d["ProductName"] = ProductName;
        if (FileDescription != null) d["FileDescription"] = FileDescription;
        if (FileVersion != null) d["FileVersion"] = FileVersion;
        if (ProductVersion != null) d["ProductVersion"] = ProductVersion;
        if (OriginalFilename != null) d["OriginalFilename"] = OriginalFilename;
        if (!string.IsNullOrEmpty(FlagsCsv)) d["AnalysisFlags"] = FlagsCsv;
        if (CertificateTableSize.HasValue) d["CertificateTableSize"] = CertificateTableSize.Value;
        if (!string.IsNullOrEmpty(CertificateBlobSha256)) d["CertificateBlobSha256"] = CertificateBlobSha256;
        if (AssessmentScore.HasValue) d["AssessmentScore"] = AssessmentScore.Value;
        if (!string.IsNullOrEmpty(AssessmentDecision)) d["AssessmentDecision"] = AssessmentDecision;
        if (AssessmentCodes != null && AssessmentCodes.Count > 0) d["AssessmentCodes"] = AssessmentCodes;
        if (AssessmentFactors != null && AssessmentFactors.Count > 0) d["AssessmentFactors"] = AssessmentFactors;
        if (EncryptedEntryCount.HasValue) d["EncryptedEntryCount"] = EncryptedEntryCount.Value;
        if (SecurityFindings != null && SecurityFindings.Count > 0) d["SecurityFindings"] = SecurityFindings;
        return d;
    }
}
