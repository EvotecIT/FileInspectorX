<!-- Badges -->

# FileInspectorX — Content Type Detection and Analysis for .NET and PowerShell

📦 NuGet (Library)

[![nuget downloads](https://img.shields.io/nuget/dt/FileInspectorX?label=nuget%20downloads)](https://www.nuget.org/packages/FileInspectorX)
[![nuget version](https://img.shields.io/nuget/v/FileInspectorX)](https://www.nuget.org/packages/FileInspectorX)

💻 PowerShell Module

[![powershell gallery version](https://img.shields.io/powershellgallery/v/FileInspectorX.PowerShell.svg)](https://www.powershellgallery.com/packages/FileInspectorX.PowerShell)
[![powershell gallery preview](https://img.shields.io/powershellgallery/vpre/FileInspectorX.PowerShell.svg?label=powershell%20gallery%20preview&colorB=yellow)](https://www.powershellgallery.com/packages/FileInspectorX.PowerShell)
[![powershell gallery platforms](https://img.shields.io/powershellgallery/p/FileInspectorX.PowerShell.svg)](https://www.powershellgallery.com/packages/FileInspectorX.PowerShell)
[![powershell gallery downloads](https://img.shields.io/powershellgallery/dt/FileInspectorX.PowerShell.svg)](https://www.powershellgallery.com/packages/FileInspectorX.PowerShell)

🛠️ Project Information

[![top language](https://img.shields.io/github/languages/top/EvotecIT/FileInspectorX.svg)](https://github.com/EvotecIT/FileInspectorX)
[![license](https://img.shields.io/github/license/EvotecIT/FileInspectorX.svg)](https://github.com/EvotecIT/FileInspectorX)

👨‍💻 Author & Social

[![Twitter follow](https://img.shields.io/twitter/follow/PrzemyslawKlys.svg?label=Twitter%20%40PrzemyslawKlys&style=social)](https://twitter.com/PrzemyslawKlys)
[![Blog](https://img.shields.io/badge/Blog-evotec.xyz-2A6496.svg)](https://evotec.xyz/hub)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-pklys-0077B5.svg?logo=LinkedIn)](https://www.linkedin.com/in/pklys)
[![Threads](https://img.shields.io/badge/Threads-@PrzemyslawKlys-000000.svg?logo=Threads&logoColor=White)](https://www.threads.net/@przemyslaw.klys)
[![Discord](https://img.shields.io/discord/508328927853281280?style=flat-square&label=discord%20chat)](https://evo.yt/discord)

## What it's all about

FileInspectorX is a library for content type detection (magic bytes + heuristics) and lightweight analysis (containers, PDFs, PE triage, text/script cues) across .NET 8, .NET Standard 2.0 and .NET Framework 4.7.2. A thin PowerShell module provides pipeline‑friendly cmdlets with reusable typed views.

## Install

### NuGet (Library)

```bash
dotnet add package FileInspectorX
```

### PowerShell (Module)

```powershell
Install-Module FileInspectorX.PowerShell
# or local build
Import-Module .\FileInspectorX.PowerShell\bin\Debug\net8.0\FileInspectorX.PowerShell.dll
```

## C# Quick Start

```csharp
using FileInspectorX;

var options = new FileInspector.DetectionOptions { ComputeSha256 = true, MagicHeaderBytes = 16 };
var analysis = FileInspector.Analyze(path, options);

Console.WriteLine($"{analysis.Detection?.Extension} {analysis.Detection?.MimeType} {analysis.Kind} {analysis.Flags}");

// Flatten for tabular/log display
var summary = SummaryView.From(path, analysis);
var perms   = PermissionsView.From(path, analysis.Security);
var sig     = SignatureView.From(path, analysis.Authenticode);

// Detection only
var detOnly = FileInspector.Detect(path, options);
```

## PowerShell Examples

```powershell
# Raw is default (full object)
Get-FileInsight -Path .\file.bin | Format-List

# Opt-in compact views
Get-FileInsight -Path .\file.bin -View Summary | Format-Table -Auto

# Other views: Summary | Detection | Permissions | Signature | Analysis
Get-FileInsight -Path .\file.bin -View Detection | Format-Table -Auto
Get-FileInsight -Path .\file.bin -View Permissions | Format-Table Path,Owner,Group,ModeSymbolic,EveryoneWriteAllowed -Auto
Get-FileInsight -Path .\app.exe -View Signature | Format-List
Get-FileInsight -Path .\package.msix -View Installer | Format-Table -Auto

# Exclude sections to trim work/shape
Get-FileInsight -Path .\file.bin -ExcludePermissions -ExcludeReferences | Format-List

# Back-compat: detection only
Get-FileInsight -Path .\file.bin -DetectOnly | Format-List
```

## Views

- SummaryView: Path, Kind, Extension, MimeType, Confidence, Reason, Flags
- DetectionView: Path, Extension, MimeType, Confidence, Reason, ReasonDetails, BytesInspected, Sha256Hex, MagicHeaderHex
- AnalysisView: container/text/script/PE/Auth summaries
- PermissionsView (Windows & Unix): Owner/Group (+ IDs), ModeOctal/ModeSymbolic, IsExecutable, Everyone/Users/Admins read/write, HasDenyEntries
- SignatureView: Present, EnvelopeSignatureValid, ChainValid, Timestamp, signer info, FileHashMatches, SubjectCN/Org, IssuerCN/Org, IsSelfSigned
- InstallerView: Name/Publisher/Version/Manufacturer/ProductCode for MSI; Identity/Publisher/Display for MSIX/APPX; Publisher for VSIX
- ReferencesView: (generic) FilePath/Url/Command values found in configs (Task XML, scripts.ini), with Exists and Issues flags
- AssessmentView: compact risk score (0–100), decision (Allow/Warn/Block/Defer), and finding codes
  - Codes include: Package.VendorPresent/VendorUnknown/VendorAllowed, Sig.VendorAllowed/Sig.VendorUnknown, Archive.* and Pdf.* flags, etc.

## Usage Model: Raw + Views + Exclude Toggles

- Default Raw
  - The cmdlet returns the full `FileAnalysis` object by default (`-View Raw`). This is a single, rich object with Detection, Flags, Security, Authenticode/Installer, References, Assessment, Secrets summary, and more.

- Views for display
  - Use `-View Summary|Detection|Analysis|Permissions|Signature|References|Assessment|Installer` to get compact, tabular shapes.
  - Every view carries `.Raw` so you can drill back into the full object without re‑invoking.

- Trim work/shape with excludes
  - `-ExcludePermissions`, `-ExcludeSignature`, `-ExcludeInstaller`, `-ExcludeReferences`, `-ExcludeContainer`, `-ExcludeAssessment`.
  - In C#, use `new FileInspector.DetectionOptions { IncludePermissions = false, ... }`.

## API Choices: Detect vs Inspect vs Analyze

Pick the API based on how much work you want the library to do and how much metadata you need:

- Detect(path[, options]) → ContentTypeDetectionResult
  - Fast header-only magic/heuristics (null if unknown)
  - Minimal I/O, ideal for bulk triage or hot loops
  - options can still capture Sha256Hex and MagicHeaderHex

- Inspect(path[, options]) → FileAnalysis (single entry point)
  - If options.DetectOnly = true → returns a minimal FileAnalysis wrapping Detect
  - Otherwise → performs full analysis (same as Analyze)

- Analyze(path[, options]) → FileAnalysis
  - Full analysis: container/PDF/PE/Auth/permissions/script cues/CSV estimates
  - Returns everything Detect provides plus extra flags and metadata

Examples (C#)

```csharp
// Detection only (fast)
var det = FileInspector.Detect(path, new FileInspector.DetectionOptions { MagicHeaderBytes = 16 });

// Single entry point (detect-only)
var detFa = FileInspector.Inspect(path, new FileInspector.DetectionOptions { DetectOnly = true });

// Full analysis
var full = FileInspector.Inspect(path, new FileInspector.DetectionOptions { ComputeSha256 = true });
var summary = full.ToSummaryView(path);
```

## Features

- Fast detection: magic bytes + heuristics (images, archives, PDFs, executables, text/markup, scripts, CSV/TSV, DMG/ISO/UDF, etc.)
- Analysis helpers
  - ZIP/TAR summaries (entry count, top extensions, nested-archive hints)
  - PDF flags (JavaScript, OpenAction, AA, Names tree, EmbeddedFiles, ManyEmbeddedFiles)
  - PE triage (machine/subsystem, UPX hint)
  - Text family & CSV/TSV line estimates
- Script safety cues (neutral): ps:encoded, ps:iex, py:exec-b64, lua:exec, rb:eval (no raw high‑signal strings)
- Permissions snapshot: cross‑platform owner/group + Unix modes; Windows ACL summaries (Everyone/Users/Admins read/write, deny ACEs)
- Signatures: Authenticode summary everywhere; optional WinVerifyTrust policy (Windows)
- AOT‑friendly: safe for NativeAOT
 - Name/path checks: BiDi controls, double extension, extension mismatch, suspicious whitespace
 - Archive safety: traversal/absolute paths/symlinks flags from ZIP sampling
- Installer/container focus:
  - ZIP subtype detection (apk/jar/ipa/vsix/xap/appx/msix)
  - ZIP inventory flags for executables, scripts, installers (msi/msix/appx/msixbundle)
  - Appx/MSIX signature extraction (AppxSignature.p7x) → SignatureView shows vendor/cert
 - Office & PDF flags:
   - OOXML (Word): Remote template (OfficeRemoteTemplate), possible DDE (OfficePossibleDde)
   - OOXML (Excel): External links (OfficeExternalLinks) and count (OfficeExternalLinksCount)
   - PDF: XFA (PdfHasXfa), Encrypted (PdfEncrypted), ManyIncrementalUpdates (PdfManyIncrementalUpdates)

## References & Recipes

The library can extract generic references from common configuration files so consumers can validate what will execute or be accessed. This is domain‑agnostic and useful for many scenarios (build pipelines, endpoint hygiene, or pre‑upload checks).

- Extracted kinds: FilePath, Url, Command, EnvVar, RegistryPath, Clsid.
- Current extractors:
  - Windows Task Scheduler Task XML: captures `<Exec><Command>`, `<Arguments>`, `<WorkingDirectory>` and `<ClassId>` (COM handler). Flags unquoted paths, UNC usage, relative paths.
  - GPO scripts INI (scripts.ini / psscripts.ini): captures `nCmd` and `nParameters` values, extracts paths and URLs.

PowerShell

```powershell
# List references from a Task XML
Get-FileInsight -Path .\Task.xml -View References | Format-Table -Auto

# List references in a GPO scripts.ini
Get-FileInsight -Path .\scripts.ini -View References | Format-Table -Auto
```

C#

```csharp
var a = FileInspector.Analyze(path);
foreach (var r in a.References ?? Array.Empty<Reference>())
{
    Console.WriteLine($"{r.Kind} {r.Value} exists={r.Exists} issues={r.Issues}");
}
```

C# (Assessment)

```csharp
var full = FileInspector.Analyze(path);
var assess = FileInspector.Assess(full);
Console.WriteLine($"Score={assess.Score} Decision={assess.Decision} Codes={string.Join(" ", assess.Codes)}");

// Factors show score contributions per code (explainability)
foreach (var kv in assess.Factors)
{
    Console.WriteLine($"{kv.Key} => {kv.Value}");
}
```

PowerShell (Assessment)

```powershell
Get-FileInsight -Path .\file.bin -View Assessment | Format-Table -Auto
```

This stays generic by design. A higher‑level component (e.g., TierBridge) can layer policy (allow/warn/block) using these references and the existing Flags/SecurityFindings.

## Flags → Assessment Codes (Quick Map)

- Archive safety
  - ArchiveHasPathTraversal → Archive.PathTraversal (+40)
  - ArchiveHasAbsolutePaths → Archive.AbsolutePath (+15)
  - ArchiveHasSymlinks → Archive.Symlink (+20)
  - ContainerContainsExecutables → Archive.ContainsExecutables (+25)
  - ContainerContainsScripts → Archive.ContainsScripts (+20)
  - ContainerContainsArchives → Archive.ContainsArchives (+15)

- Office / OOXML
  - HasOoxmlMacros → Office.Macros (+30)
  - OfficeRemoteTemplate → Office.RemoteTemplate (+25)
  - OfficePossibleDde → Office.PossibleDde (+15)
  - OfficeExternalLinks → Office.ExternalLinks (+5) [count exposed as OfficeExternalLinksCount]

- PDF
  - PdfHasJavaScript → Pdf.JavaScript (+20)
  - PdfHasOpenAction → Pdf.OpenAction (+15)
  - PdfHasLaunch → Pdf.Launch (+20)
  - PdfHasNamesTree → Pdf.NamesTree (+10)
  - PdfHasXfa → Pdf.Xfa (+10)
  - PdfEncrypted → Pdf.Encrypted (+10)
  - PdfManyIncrementalUpdates → Pdf.ManyUpdates (+5)

- PE hardening
  - PeLooksPackedUpx → PE.PackerSuspect (+20)
  - PeNoAslr → PE.NoASLR (+15)
  - PeNoNx → PE.NoNX (+20)
  - PeNoCfg → PE.NoCFG (+15)
  - PeNoHighEntropyVa (x64) → PE.NoHighEntropyVA (+5)

- Signatures
  - Self‑signed → Sig.SelfSigned (+20)
  - Chain invalid → Sig.ChainInvalid (+25)
  - Bad envelope → Sig.BadEnvelope (+15)
  - Vendor allowed (allowed list) → Sig.VendorAllowed (−10)

- Vendor / Package
  - Vendor present → Package.VendorPresent (0)
  - Vendor allowed (allowed list) → Package.VendorAllowed (−15)
  - Vendor unknown → Package.VendorUnknown (0)
  - MSI CustomActions (EXE/Script/DLL) → Msi.CustomActionExe (+20) / Msi.CustomActionScript (+20) / Msi.CustomActionDll (+10)

- Scripts & secrets (neutral categories)
  - Script.Encoded (+25), Script.IEX (+20), Script.WebDownload (+15), Script.Reflection (+10)
  - Secret.PrivateKey (+40), Secret.JWT (+25), Secret.KeyPattern (+15)

## Settings

- HeaderReadBytes (default 4096)
- DetectionReadBudgetBytes (default 1 MB)
- SecurityScanScripts (default true)
- VerifyAuthenticodeWithWinTrust (default true on Windows)
- VerifyAuthenticodeRevocation (default false)
- JS minified heuristics: JsMinifiedMinLength, JsMinifiedAvgLineThreshold, JsMinifiedDensityThreshold
- Assessment thresholds: AssessmentWarnThreshold, AssessmentBlockThreshold
- Vendor allow‑list: AllowedVendors (string[]), VendorMatchMode (Contains|Exact)
 - Secrets: SecretsScanEnabled (default true)

## Secrets Summary (privacy‑safe)

The full object (Raw/FileAnalysis) exposes <code>Secrets</code> with category counts only — no values are stored:

```powershell
$fa = Get-FileInsight -Path .\script.ps1
$fa.Secrets | Format-List
```

```csharp
var fa = FileInspector.Analyze(path);
var s = fa.Secrets;
Console.WriteLine($"privKeys={s?.PrivateKeyCount} jwt={s?.JwtLikeCount} keyPat={s?.KeyPatternCount}");
```

## Signatures (Authenticode)

- Cross‑platform
  - Parses Authenticode PKCS#7 and extracts the content digest (SpcIndirectDataContent)
  - Recomputes PE image digest excluding checksum and WIN_CERTIFICATE table
  - Sets AuthenticodeInfo.FileHashMatches and FileDigestAlgorithm
- Windows (optional)
  - WinVerifyTrust policy verification (catalog-aware) → IsTrustedWindowsPolicy + WinTrustStatusCode

## Permissions & Ownership

- Unix: mode bits via .NET (UnixFileMode); owner/group names via `stat` where available
- Windows: Owner/Group friendly names (NTAccount), ACL summaries
  - EveryoneReadAllowed/EveryoneWriteAllowed
  - BuiltinUsersReadAllowed/BuiltinUsersWriteAllowed
  - AdministratorsReadAllowed/AdministratorsWriteAllowed
  - HasDenyEntries

## Platforms & AOT

- .NET 8, .NET Standard 2.0, .NET Framework 4.7.2
- NativeAOT friendly; WinVerifyTrust runs only on Windows

## Build

- Library: `dotnet build FileInspectorX/FileInspectorX.csproj`
- Tests: `dotnet test`
- PowerShell module: `dotnet build FileInspectorX.PowerShell` (then Import-Module the built DLL)

## Notes

- Script “security findings” are neutral codes — reduces AV triggers
- Owner/group on Unix via `stat` when available (fields may be null; mode bits still populate)
