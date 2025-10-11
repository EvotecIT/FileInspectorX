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
# Summary is default (compact)
Get-FileInsight -Path .\file.bin | Format-Table -Auto

# Other views: Summary | Detection | Permissions | Signature | Analysis
Get-FileInsight -Path .\file.bin -View Detection | Format-Table -Auto
Get-FileInsight -Path .\file.bin -View Permissions | Format-Table Path,Owner,Group,ModeSymbolic,EveryoneWriteAllowed -Auto
Get-FileInsight -Path .\app.exe -View Signature | Format-List

# Back-compat
Get-FileInsight -Path .\file.bin -DetectOnly | Format-List
```

## Views

- SummaryView: Path, Kind, Extension, MimeType, Confidence, Reason, Flags
- DetectionView: Path, Extension, MimeType, Confidence, Reason, ReasonDetails, BytesInspected, Sha256Hex, MagicHeaderHex
- AnalysisView: container/text/script/PE/Auth summaries
- PermissionsView (Windows & Unix): Owner/Group (+ IDs), ModeOctal/ModeSymbolic, IsExecutable, Everyone/Users/Admins read/write, HasDenyEntries
- SignatureView (PE): Present, EnvelopeSignatureValid, ChainValid, Timestamp, signer info, FileHashMatches

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

## Settings

- HeaderReadBytes (default 4096)
- DetectionReadBudgetBytes (default 1 MB)
- SecurityScanScripts (default true)
- VerifyAuthenticodeWithWinTrust (default true on Windows)
- VerifyAuthenticodeRevocation (default false)
- JS minified heuristics: JsMinifiedMinLength, JsMinifiedAvgLineThreshold, JsMinifiedDensityThreshold

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
