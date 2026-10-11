# Filesystem query prototype

This standalone evaluation project compares an MFT-backed filesystem alternative to `Get-ChildItem` with ordinary enumeration. It is excluded from FileInspectorX's normal solutions, packages and module exports. The [implementation plan](PLAN.md) describes the supported subset, visibility contract, dependency decision and qualification gates.

Build with existing compatible .NET SDKs and route intermediate output to your configured mounted scratch volume:

```powershell
$prototype = Join-Path $PWD 'Prototypes/FileSystem'
$scratch = Join-Path $env:EVOTEC_SCRATCH_ROOT 'fileinspectorx-mft-childitem-prototype'
# Verify the configured scratch volume exists before creating task output.
dotnet build (Join-Path $prototype 'FileInspectorX.FileSystem.Prototype.csproj') --artifacts-path (Join-Path $scratch 'artifacts')
$framework = if ($PSVersionTable.PSEdition -eq 'Desktop') { 'net472' } else { 'net8.0' }
$module = Join-Path $scratch "artifacts/bin/FileInspectorX.FileSystem.Prototype/debug_$framework/FileInspectorX.FileSystem.Prototype.psd1"
Import-Module $module
Get-FileSystemItem -LiteralPath $PWD -Recurse -File -Backend Walk
Get-FileSystemItem -LiteralPath $PWD -Depth 1 -Name
Get-FileSystemItem -LiteralPath $PWD -Filter '*.cs' -AsFileSystemInfo
```

`Auto` defaults to ordinary caller-visible enumeration. An explicit `-AllowVolumeInventory` permits the experimental MFT visibility contract, with fallback before output when the capability is unavailable. A forced `-Backend Mft` fails visibly instead. Raw NTFS capture requires Windows administrator access and reads the entire volume, even for a small requested subtree. The default MFT metadata budget is 512 MiB; total process memory can exceed that input size.

On Windows PowerShell 5.1, automatic capture stays on ordinary enumeration until the legacy reader is qualified. Forced MFT capture remains available for isolated diagnostics. This avoids losing fallback classification through the released reader's generic I/O exceptions; cancellation and unexpected parser/I/O failures are not swallowed.

```powershell
Get-FileSystemItem -LiteralPath $PWD -Recurse -AllowVolumeInventory -Verbose
$snapshot = [FileInspectorX.Prototypes.FileSystem.MftSnapshot]::CaptureAsync(
    $PWD.Path, [Threading.CancellationToken]::None).GetAwaiter().GetResult()
Get-FileSystemItem -LiteralPath $PWD -Recurse -Backend Mft -Snapshot $snapshot
```

Snapshot results are point-in-time metadata and have no `FileInfo` mutation methods. `-AsFileSystemInfo` creates live native objects with additional property-access costs. A snapshot is an in-memory node table, not an atomic filesystem snapshot or a persistent index. The candidate reader is not qualified for complete hard-link or extension-record coverage.

Run focused tests in a fresh process for each target framework, using Pester 5.7.1:

```powershell
Import-Module Pester -RequiredVersion 5.7.1
$container = New-PesterContainer -Path (Join-Path $prototype 'Tests/Compatibility.Tests.ps1') -Data @{ ModulePath = $module }
Invoke-Pester -Container $container -Output Detailed
```

Create a new synthetic fixture outside the repository and use the existing PowerForge runner:

```powershell
& (Join-Path $prototype 'New-PrototypeFixture.ps1') -Root (Join-Path $scratch 'fixture') -Files 10000
& (Join-Path $prototype 'Invoke-PrototypeComparison.ps1') -ModulePath $module -FixtureRoot (Join-Path $scratch 'fixture') -OutputRoot (Join-Path $scratch 'comparison') -Plan
& (Join-Path $prototype 'Invoke-PrototypeComparison.ps1') -ModulePath $module -FixtureRoot (Join-Path $scratch 'fixture') -OutputRoot (Join-Path $scratch 'comparison')
# In an explicitly approved elevated PowerShell 7 process, add -RunMft for raw-volume lanes.
```

The comparison wrapper requires Windows PowerShell 7 and PSPublishModule 3.0.153 or later; the experimental command itself also targets Windows PowerShell 5.1. It temporarily uses logical CPU 0 for every lane and restores affinity on exit. MFT capture is included in the fresh lane and reported separately for the retained-snapshot lane. Validation failures stay visible in PowerForge's output.

The pinned LGPL-2.1-or-later reader is evaluation-only. No new production dependency is approved by this prototype. Keep build binaries and raw benchmark reports in task-owned scratch; retain compact evidence and remove disposable fixtures after review.

The [current evidence](RESULTS.md) includes failed raw sector acquisition on the assessed workstation, successful Windows MFT-record retrieval, and successful normal-enumeration measurements. A source evaluation can reproduce the native access-flag and error-preservation corrections without replacing an ordinary cached package:

```powershell
& (Join-Path $prototype 'Build-ReaderEvaluation.ps1') -OutputRoot (Join-Path $scratch 'reader-evaluation')
# Use the module beneath reader-evaluation/prototype-artifacts for this patched variant.
```

This build uses an isolated local feed and package cache and records source/archive/patch provenance. It requires a compiler supporting the pinned reader's C# 14 source. `Tests/Invoke-IsolatedNtfsComparison.ps1` creates a disposable virtual volume and requires explicit separate approval; it must never be used as a general disk-formatting helper.
