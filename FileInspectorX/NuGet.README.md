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
// AnalysisFlags (CSV of compact codes), AnalysisFlagsHuman (short), AnalysisFlagsHumanLong,
// InnerFindings, InnerFindingsHuman, InnerFindingsHumanLong,
// AssessmentScore, AssessmentDecision, AssessmentCodes,
// CertificateBlobSha256, EncryptedEntryCount (ZIP only)

// Human-friendly fallback example (if you only have AnalysisFlags CSV):
string flagsShort = map.TryGetValue("AnalysisFlagsHuman", out var sh) ? sh?.ToString() ?? string.Empty
                             : FileInspectorX.Legend.HumanizeFlagsCsv(map.GetValueOrDefault("AnalysisFlags")?.ToString());

// Or consume typed legends directly and render your own legend box
foreach (var entry in FileInspectorX.Legend.GetAnalysisFlagLegend())
{
    Console.WriteLine($"{entry.Short} = {entry.Long}");
}

// Assessment codes → human text
var drivers = map.GetValueOrDefault("AssessmentCodesHuman")?.ToString() ??
              FileInspectorX.AssessmentLegend.HumanizeCodes(fa.Assessment?.Codes);

// Render a Markdown report (dependency-free)
var md = FileInspectorX.MarkdownRenderer.From(fa);
```

## Detection Ordering & Declared Extension Bias

- Detection runs magic signatures first, then container refinements, then text/markup heuristics, with plain-text fallback last.
- `Detect(path)` uses the path extension as the declared type.
- `Detect(stream, options, declaredExtension)` and `Detect(ReadOnlySpan<byte>, options, declaredExtension)` let you pass a declared extension to mirror path-based behavior.
- Declared extension bias applies only for ambiguous/low-confidence text cases (e.g., cmd vs bat, admx/adml vs xml, inf vs ini, ini vs toml, log/txt/md/ps1/psm1/psd1). Strong magic-byte matches are not overridden.
- NDJSON detection requires at least two consecutive JSON-looking lines; single-line files are detected as JSON.
- When `DetectionMaxAlternatives` > 0, `Detection.Alternatives` includes ranked candidates (excluding the primary) with `Score` values; treat scores as relative within the same file and influenced by `DetectionScoreAdjustments`, `DetectionPrimaryScoreMargin`, and `DetectionDeclaredTieBreakerMargin`.

## Thread Safety Notes

- Settings are static/global; configure once at startup.
- Avoid concurrent mutation while detection is running; if you need runtime updates, protect changes with your own lock.
- `DetectionScoreAdjustments` defaults to a `ConcurrentDictionary`; if you replace it with a non-thread-safe dictionary, you are responsible for synchronization.

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
