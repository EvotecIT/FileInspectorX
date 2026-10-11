# MFT-backed filesystem query and Get-ChildItem replacement plan

Status: Windows API evaluation prototype, 2026-10-11. The published FileInspectorX API and module are unchanged. This plan covers a reusable filesystem engine with an MFT inventory backend and ordinary enumeration as the safe default and fallback.

## Outcome and ownership

The useful consumers are large file inventories, directory-size assessments and development-storage review. FileInspectorX owns the reusable C# query engine; PowerShell and future CLI adapters stay thin. Content analysis runs on selected files after discovery. PowerForge/PSPublishModule owns benchmark scheduling, warmups, rotated ordering and normalized reports.

The prototype is deliberately separate under `Prototypes/FileSystem`, targets .NET 8 and .NET Framework 4.7.2, and is excluded from normal solutions, module builds, packing and publishing. It exports `Get-FileSystemItem` without overriding or aliasing `Get-ChildItem`. No external MFT parser or reader is required by the current prototype. Production integration, the public command name, publication and destructive file operations remain outside this evaluation.

A file inventory never authorizes deletion. Storage-maintenance consumers still need fresh ownership, Git, activity, reparse-point and preservation checks.

## Current Windows API route

1. Resolve a literal directory root and reject network/non-NTFS volumes and reparse roots or ancestors for MFT access.
2. Open the existing volume read-only and query `FSCTL_GET_NTFS_VOLUME_DATA`. The MFT length is a volume-size guard, not the number of bytes this backend reads into memory.
3. Use batched `FSCTL_ENUM_USN_DATA` calls with `MFT_ENUM_DATA_V0`. Decode bounds-checked `USN_RECORD_V2` names, attributes and full 64-bit file/parent identities, including NTFS sequence bits.
4. Build an in-memory parent/children lookup. Close the volume handle before returning it. Do not create a journal, persistent database, disk image or virtual volume.
5. Identify the requested directory through `GetFileInformationByHandle`, traverse the indexed children and hydrate selected paths through ordinary `FileSystemInfo` metadata APIs. Length and creation/write/access times are therefore live metadata obtained during the query, not fields from USN records.
6. Return metadata snapshots, relative names, or explicit native `FileInfo`/`DirectoryInfo` objects. Native object hydration has a separate comparison lane.

The fresh MFT lane includes volume inventory and selected-path hydration. The retained-index lane includes querying and hydration but reports inventory setup time, allocation and retained heap separately. A retained index is not an atomic filesystem snapshot: names can age while metadata stays live.

Defaults bound the capture to four million records, 2 GiB of conservative index accounting and two minutes, plus the existing 512 MiB MFT-length guard. The assessed D: volume needs an explicit 4 GiB length allowance. Accounting is not an exact heap cap. Cancellation is checked between synchronous native calls, each parsed record and each emitted query item; it cannot interrupt a native call already executing. No background unbounded worker is started.

## Compatibility and routing contract

The supported normal-enumeration subset includes literal directory roots, multiple roots, default children, recursion, implicit recursion through `Depth`, files/directories, hidden/system filtering through `Force`, provider-native `Filter`, relative `Name`, and explicit native objects. The C# engine owns routing and iteration; the PowerShell adapter uses the existing shared async cmdlet base and resolves provider paths on the pipeline thread.

`Auto` uses ordinary enumeration by default. Even with `AllowVolumeInventory`, automatic MFT selection stays disabled until complete path semantics are qualified. Forced `-Backend Mft` is an explicit experimental inventory. Capability failures remain visible there; cancellation and malformed native records must never masquerade as successful fallback.

Known boundaries:

- A USN inventory does not guarantee all hard-link aliases. One missing alias can also place the selected name outside the requested subtree. Complete `Get-ChildItem` path coverage is a production gate.
- Native wildcard filters use normal enumeration. Forced MFT accepts only `*`.
- Recursion stops at directory reparse points. PowerShell runtime differences around junctions must be recorded, not normalized away silently.
- Results are metadata snapshots. Native objects are an explicit additional conversion with additional I/O; they do not make the inventory atomic or complete.
- File inputs, wildcard `Path`, `Include`/`Exclude`, dynamic provider parameters, Registry/Certificate providers, streams, exact ordering, provider formatting and full error-continuation behavior are unimplemented contracts.
- An explicitly privileged volume inventory has different visibility from a caller-visible directory walk. It must remain opt-in if it becomes available through automatic routing.
- Filesystem changes, directory identity reuse, access-denied paths, long paths, case-sensitive directories and extension/hard-link records need additional production qualification. Do not infer their correctness from a small synthetic tree.

## Comparison and evidence

Use existing task-owned synthetic fixtures on a mounted configured scratch root. Keep all large or intermediate output there. Do not create a virtual disk. Read existing D: metadata with the previously authorized elevated comparison driver and write only task results.

The PowerForge matrix compares `GetChildItem`, metadata `Walk`, `WalkNativeObjects`, automatic fallback, `MftFresh`, `MftSnapshot`, and `MftSnapshotNativeObjects` on the same 10,110-entry tree and 1,010-entry subtree. Full-result validation compares paths, length, attributes and last-write time outside the timed operation. Separate compatibility diagnostics compare creation/write/access timestamps and paths on hidden, Unicode, empty, nested, junction and hard-link fixtures in Windows PowerShell 5.1 and PowerShell 7.

Report total elapsed time, time to first result, process allocation, index capture cost and retained heap separately. Capture CPU, affinity, priority, runtime, OS and assembly hash. Retain outliers. The current exploratory matrix uses one logical CPU, warm filesystem caches, one warmup and three rotated measured iterations. These conditions do not establish cold-cache throughput, a universal whole-drive scan time or optimal multi-core performance.

Deterministic correctness tests cover the supported walk/routing contracts and native record decoding: record and name bounds, unsupported layouts, Unicode, full identities, path-component containment and cancellation after enumeration starts. Live diagnostics exercise record/memory budgets and cancellation during capture/query. Keep performance out of ordinary correctness gates.

The earlier direct-sector reader failed with Win32 error 50 on this environment; aligned native probes confirmed it. Windows volume-data and individual file-record control calls succeeded. The rejecting sector-read component is unidentified. Historical raw-reader results remain evidence in Git/task outputs; obsolete reader patches and virtual-disk experiment scripts are removed from the current prototype.

## Remaining implementation decisions

- [x] Isolate the prototype and preserve the dirty primary checkout.
- [x] Add a bounded native Windows MFT name inventory without an external reader dependency.
- [x] Keep normal enumeration and a familiar thin PowerShell surface.
- [x] Validate deterministic contracts on both PowerShell runtimes.
- [x] Complete the native elevated timing/compatibility matrix and independent review; record all losses and mismatches.
- [ ] Choose the production shape from the measurements: separate explicit inventory command, a compatibility-preserving hybrid, or further MFT metadata acquisition.
- [ ] Implement complete hard-link path coverage and stable identity validation before enabling automatic MFT selection.
- [ ] Qualify concurrent changes, access/visibility, reparse behavior, cancellation latency and real peak-memory bounds.
- [ ] Compare broad inventories and repeated queries, cold/warm caches and representative CPU domains before defining workload-based routing thresholds.
- [ ] Integrate a qualified engine into the main library and thin module surface, then validate CI and package artifacts. Any new production dependency needs separate approval.

Prefer the smallest engine that earns its maintenance cost. A slower native prototype is still a useful result if it shows where indexing pays and where ordinary enumeration should remain the selected backend.

## Platform contracts

- [FSCTL_ENUM_USN_DATA](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_enum_usn_data)
- [MFT_ENUM_DATA_V0](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-mft_enum_data_v0)
- [USN_RECORD_V2](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v2)
- [GetFileInformationByHandle](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfileinformationbyhandle)
