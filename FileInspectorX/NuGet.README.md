# FileInspectorX

Minimal, dependency‑free content detection + lightweight analysis for .NET.

## Install

```bash
dotnet add package FileInspectorX
```

## Quick Start (C#)

```csharp
using FileInspectorX;

// Full analysis (defaults)
var fa = FileInspector.Analyze(path, new FileInspector.DetectionOptions { ComputeSha256 = true });
Console.WriteLine($"{fa.Detection?.Extension} {fa.Detection?.MimeType} {fa.Kind} {fa.Flags}");
Console.WriteLine($"Assessment: {fa.Assessment?.Decision} ({fa.Assessment?.Score})");

// Detection only
var det = FileInspector.Detect(path, new FileInspector.DetectionOptions { MagicHeaderBytes = 16 });

// Views (optional, for display)
var summary = fa.ToSummaryView(path);

// Present findings without reassembling logic: ReportView
var report = FileInspectorX.ReportView.From(fa);
var map = report.ToDictionary();
// Example keys: DetectedTypeExtension, DetectedTypeName, DetectionConfidence, DetectionReason,
// CompanyName, ProductName, FileDescription, FileVersion, ProductVersion, OriginalFilename,
// AnalysisFlags (CSV of compact codes), AssessmentScore, AssessmentDecision, AssessmentCodes,
// CertificateBlobSha256, EncryptedEntryCount (ZIP only)
```

## Include/Exclude Sections

```csharp
var lean = FileInspector.Analyze(path, new FileInspector.DetectionOptions {
    IncludePermissions = false,
    IncludeReferences = false,
    IncludeInstaller  = true,
    IncludeAuthenticode = true,
    IncludeAssessment = true
});

// Deep container scanning (opt-in)
Settings.DeepContainerScanEnabled = true;
Settings.DeepContainerMaxEntries = 64;
Settings.DeepContainerMaxEntryBytes = 262_144; // 256 KB
Settings.KnownToolNameIndicators = new[] { "pingcastle", "bloodhound" };
Settings.KnownToolHashes = new Dictionary<string,string> { /* name => lowercase sha256 */ };
```

## Assessment & Policy

```csharp
Settings.AllowedVendors = new[] { "Microsoft", "YourCompany" };
Settings.VendorMatchMode = VendorMatchMode.Contains;
var assess = fa.Assessment ?? FileInspector.Assess(fa);
Console.WriteLine(string.Join(",", assess.Codes));
foreach (var kv in assess.Factors) Console.WriteLine($"{kv.Key} => {kv.Value}");
```

See repository for more examples and PowerShell module.
