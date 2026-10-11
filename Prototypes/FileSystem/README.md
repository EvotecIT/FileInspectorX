# FileInspectorX filesystem prototype

This isolated evaluation compares Windows MFT APIs with ordinary enumeration and `Get-ChildItem`. It does not change the published module or replace the built-in command. See [the plan](PLAN.md) for the supported subset and production gates, and [results](RESULTS.md) for measured performance and compatibility limits.

The MFT backend uses `FSCTL_ENUM_USN_DATA` for names and identities, then ordinary file APIs for selected-path metadata. It requires Windows, a local NTFS volume and administrator access. Names are indexed in memory; no persistent index, journal or virtual disk is created. The current inventory can miss hard-link aliases, so `Auto` retains normal enumeration on both runtimes. Forced MFT mode is explicitly experimental.

## Build and deterministic tests

Resolve `EVOTEC_SCRATCH_ROOT` to an existing mounted volume first. Use a task-owned subdirectory for artifacts, test temporary files and reports. The project is excluded from normal FileInspectorX builds and cannot be packed or published.

```powershell
$taskRoot = Join-Path $env:EVOTEC_SCRATCH_ROOT 'fileinspectorx-mft-evaluation'
# Create only beneath an already verified, mounted scratch root.
$artifacts = Join-Path $taskRoot 'artifacts'
dotnet build ./Prototypes/FileSystem/FileInspectorX.FileSystem.Prototype.csproj --artifacts-path $artifacts
```

Run `Invoke-PrototypeTests.ps1` in a fresh PowerShell 7 host against the `debug_net8.0` module manifest and in Windows PowerShell 5.1 against `debug_net472`. Supply `-ModulePath` and an optional `-OutputPath` for Pester XML. The tests require Pester 5.7.1. They cover the supported filesystem subset and the native USN decoder without requiring elevation.

## Query the evaluation module

After importing its built manifest:

```powershell
Get-FileSystemItem -LiteralPath $directory -Recurse                 # safe automatic walk
Get-FileSystemItem -LiteralPath $directory -Depth 1 -AsFileSystemInfo
Get-FileSystemItem -LiteralPath $directory -Recurse -Backend Mft   # explicit elevated inventory
```

The default MFT-length guard is 512 MiB. Larger existing volumes require an explicit `-MaximumMftBytes` allowance. Separate index limits are exposed through `-MaximumIndexRecords`, `-MaximumIndexBytes` and `-MaximumCaptureSeconds`; conservative accounting is not a measured heap cap. Do not set arbitrary large allowances without checking available RAM and scope.

A retained `MftSnapshot` can be supplied through `-Snapshot`; its name/identity index is reused while selected metadata is fetched again. It does not include newly created paths until recaptured, and it is not a point-in-time view. `-Filter` values other than `*` use normal enumeration in `Auto` and are rejected by forced MFT mode.

## Reproduce the comparison

`New-PrototypeFixture.ps1` creates a new task-owned synthetic tree. `Invoke-PrototypeComparison.ps1` calls the shared PowerForge benchmark runner; use `-Plan` before measurement. `-RunMft` requires elevated read-only volume access. Fresh MFT timings include inventory setup; retained-index timings report setup separately. Correctness validation remains outside the clock.

`Tests/Measure-MftCompatibility.ps1` compares paths and metadata against `Get-ChildItem` and records differences rather than accepting missing aliases. `Invoke-ElevatedPrototypeComparison.ps1` runs both runtime diagnostics and the PowerShell 7 timing matrix from a reviewed JSON request. Inputs and outputs must be inside the existing configured scratch root. It accepts no arbitrary command payload and does not modify the volume, services, caches or databases.

Use these scripts only with synthetic task fixtures. Preserve the compact results, remove superseded build/intermediate output under the shared storage policy, and never use an inventory as authority to delete files.
