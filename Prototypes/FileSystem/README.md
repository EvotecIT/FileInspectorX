# FileInspectorX filesystem prototype

This isolated evaluation compares direct Windows NTFS metadata with ordinary enumeration and `Get-ChildItem`. It does not change the published module or alias the built-in command. See [the plan](PLAN.md) for the supported subset and production gates, and [results](RESULTS.md) for measured performance and compatibility limits.

The explicit MFT backend reads base and extension records through `FSCTL_GET_NTFS_FILE_RECORD`. It reconstructs long-name hardlinks and captures attributes, timestamps and default-stream logical length directly. Contradictory header reference hints receive an identity-checked, metadata-only Windows link-count probe; unverifiable records remain errors. It requires Windows, a local NTFS 3.0/3.1 volume and administrator access. The index is memory-only; no journal, database, raw-sector reader or virtual disk is created.

`Auto` retains normal enumeration. A privileged, aging metadata snapshot has different visibility and freshness from a caller-visible directory walk. Forced MFT mode is experimental.

Live fixture checks in PowerShell 7 and Windows PowerShell 5.1 match all 34 paths and exercised file metadata, including hardlink aliases. One directory last-access timestamp differs. Whole-drive access/error behavior and the live index's freshness still require qualification; the measured cached-query results are mixed. Read [the comparison results](RESULTS.md) before selecting this backend.

## Build and deterministic tests

Resolve `EVOTEC_SCRATCH_ROOT` to an existing mounted volume first. Use a task-owned subdirectory for artifacts, temporary files and reports. The project is excluded from normal FileInspectorX builds and cannot be packed or published.

```powershell
$taskRoot = Join-Path $env:EVOTEC_SCRATCH_ROOT 'fileinspectorx-mft-evaluation'
# Create only beneath an already verified, mounted scratch root.
$artifacts = Join-Path $taskRoot 'artifacts'
dotnet build ./Prototypes/FileSystem/FileInspectorX.FileSystem.Prototype.csproj --artifacts-path $artifacts
```

Run `Invoke-PrototypeTests.ps1` in a fresh PowerShell 7 host against the `debug_net8.0` module manifest and in Windows PowerShell 5.1 against `debug_net472`. Supply `-ModulePath` and optional `-OutputPath` for Pester XML. Tests use Pester 5.7.1 and exercise the supported normal-enumeration subset, routing and logical NTFS record decoding without elevation.

## Query the evaluation module

After importing its built manifest:

```powershell
Get-FileSystemItem -LiteralPath $directory -Recurse
Get-FileSystemItem -LiteralPath $directory -Depth 1 -AsFileSystemInfo
Get-FileSystemItem -LiteralPath $directory -Recurse -Backend Mft
```

The default MFT-length guard is 512 MiB. Larger volumes require explicit `-MaximumMftBytes`; separate index limits are `-MaximumIndexRecords`, `-MaximumIndexBytes` and `-MaximumCaptureSeconds`. Conservative accounting is not an exact heap cap. Check available RAM and scope before raising allowances.

A retained `MftSnapshot` can be passed through `-Snapshot`. Queries reuse captured names and metadata without refreshing every path. New paths and metadata changes require recapture; this is not an atomic point-in-time view. Native object conversion can trigger additional live metadata I/O. `-Filter` other than `*` uses normal enumeration in `Auto` and is rejected by forced MFT.

## Reproduce the comparison

`New-PrototypeFixture.ps1` creates a new task-owned synthetic tree, up to 500,000 files. `Invoke-LargeTreeComparison.ps1` calls the shared PowerForge runner for the tree, a tenth-sized subtree and an optional existing whole drive:

```powershell
$comparison = @{
    ModulePath = $moduleManifest
    FixtureRoot = $fixtureRoot
    CompatibilityRoot = $compatibilityRoot
    VolumeRoot = $volumeRoot
    OutputRoot = $newResultDirectory
}
./Prototypes/FileSystem/Invoke-LargeTreeComparison.ps1 @comparison -Plan
# RunMft requires explicitly authorized elevated read-only volume access.
./Prototypes/FileSystem/Invoke-LargeTreeComparison.ps1 @comparison
# Ordinary enumeration can be compared without volume access.
./Prototypes/FileSystem/Invoke-LargeTreeComparison.ps1 @comparison -NormalOnly
```

`-Plan` skips capture, fixture baselines and output creation. `-SkipVolume` limits measurement to synthetic trees. The common streaming consumer reads metadata inside the clock and retains only compact fingerprints. Fatal aborts fail a sample. Whole-drive visibility, errors and concurrent changes are reported without an equivalence claim.

`Tests/Measure-MftCompatibility.ps1` compares paths and metadata with `Get-ChildItem` and exercises capture/query guards. `Invoke-ElevatedPrototypeComparison.ps1 -LargeTree` runs PowerShell 7 timings and compatibility diagnostics in both hosts from a reviewed JSON request. Inputs/results must be under the existing configured scratch root; whole-drive mode uses that scratch volume, distinct from the system volume. It accepts no arbitrary command payload and changes no services, caches or databases.

Capture cost, allocation and retained heap are separate from retained-index query timings. Preserve compact results and remove superseded builds and large fixtures under the shared storage policy. An inventory is never authority to delete its discovered paths.
