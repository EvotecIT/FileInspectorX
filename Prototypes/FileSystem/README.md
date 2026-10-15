# FileInspectorX filesystem prototype

This isolated evaluation compares direct Windows NTFS metadata with ordinary enumeration and `Get-ChildItem`. It does not change the published module or alias the built-in command. See [the plan](PLAN.md) for the supported subset and production gates, and [results](RESULTS.md) for measured performance and compatibility limits.

The explicit MFT backend reads mapped MFT extents in large aligned buffers, bootstrapping the layout through logical Windows file-record controls. Its read-only physical-partition route is used only after an unsupported volume read and strict mapping/NTFS identity checks. `-MftReadMode RecordApi` selects the retained individual-record diagnostic route. It reconstructs long-name hardlinks and captures attributes, timestamps and default-stream logical length directly. Contradictory header reference hints receive an identity-checked, metadata-only Windows link-count probe; unverifiable records remain errors. It requires Windows, a local NTFS 3.0/3.1 volume and administrator access. The index is memory-only; raw buffers are not persisted and no journal, database or virtual disk is created.

`Auto` retains normal enumeration. A privileged, aging metadata snapshot has different visibility and freshness from a caller-visible directory walk. Forced MFT mode is experimental.

Live fixture checks in PowerShell 7 and Windows PowerShell 5.1 match all 34 paths and exercised file metadata, including hardlink aliases. One directory last-access timestamp differs. Whole-drive access/error behavior and the live index's freshness still require qualification; bulk acquisition and retained-index query costs are reported separately. Read [the comparison results](RESULTS.md) before selecting this backend.

## Build and deterministic tests

Resolve the configured scratch root to an existing mounted volume first and assign it to `$scratchRoot`. Use a task-owned subdirectory for artifacts, temporary files and reports. The project is excluded from normal FileInspectorX builds and cannot be packed or published.

```powershell
$taskRoot = Join-Path $scratchRoot 'fileinspectorx-mft-evaluation'
# Create only beneath an already verified, mounted scratch root.
$artifacts = Join-Path $taskRoot 'artifacts'
dotnet build ./Prototypes/FileSystem/FileInspectorX.FileSystem.Prototype.csproj --artifacts-path $artifacts
```

Run `Invoke-PrototypeTests.ps1` in a fresh PowerShell 7 host against the `debug_net8.0` module manifest and in Windows PowerShell 5.1 against `debug_net472`. Supply `-ModulePath` and optional `-OutputPath` for Pester XML. The 37 tests use Pester 5.7.1 and exercise the supported normal-enumeration subset, routing, raw and logical record decoding, runlist bounds, synthetic 4KiB-sector geometry and handled-error accounting without elevation.

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

`New-PrototypeFixture.ps1` creates a new task-owned synthetic tree with up to 500,000 files. `Invoke-BulkStageComparison.ps1` uses the shared PowerForge runner to separate fresh acquisition, C# metadata scanning, C# folder totals and PowerShell count-only delivery:

```powershell
$comparison = @{
    ModulePath = $moduleManifest
    FixtureRoot = $fixtureRoot
    VolumeRoot = $volumeRoot
    OutputRoot = $newResultDirectory
}
./Prototypes/FileSystem/Invoke-BulkStageComparison.ps1 @comparison -Plan
# Requires explicitly authorized, elevated read-only volume access.
./Prototypes/FileSystem/Invoke-BulkStageComparison.ps1 @comparison
# Focused synthetic rerun; still captures the existing NTFS volume index.
./Prototypes/FileSystem/Invoke-BulkStageComparison.ps1 @comparison -SkipVolume -SkipAcquisition
```

`-Plan` skips capture, baselines and output creation. `-SkipAcquisition` omits timed acquisition cases; it does not eliminate the snapshot needed by cached query cases. The runner validates synthetic normal/repeated-normal/MFT baseline fingerprints before starting timings and preserves failed samples. Whole-drive counts, errors and live changes are reported without an equivalence claim. C# folder totals count hardlink paths separately; inspect the supplied error sink for partial folder coverage.

`Tests/Measure-MftCompatibility.ps1` compares paths and metadata with Get-ChildItem and exercises capture/query guards in either PowerShell host. The older `Invoke-LargeTreeComparison.ps1` retains the earlier per-entry metadata-consumer experiment; its durations have different timer boundaries and should not be mixed with the bulk-stage matrix.

Capture cost, allocation and retained heap are separate from retained-index query timings. Preserve compact results and remove superseded builds and large fixtures under the shared storage policy. An inventory is never authority to delete its discovered paths.
