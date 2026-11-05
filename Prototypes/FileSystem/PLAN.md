# MFT-backed filesystem query and Get-ChildItem replacement plan

FileInspectorX owns the reusable filesystem query engine. The isolated prototype under `Prototypes/FileSystem` evaluates direct NTFS metadata and normal enumeration behind a thin `Get-FileSystemItem` adapter. The published library and module remain unchanged. This is a filesystem subset, not a replacement for every PowerShell provider or every `Get-ChildItem` parameter.

## Implemented shape

The evaluation targets .NET 8 and .NET Framework 4.7.2, is excluded from normal solutions and module builds, and cannot be packed or published. It adds no external reader dependency and does not alias the built-in command. PowerForge/PSPublishModule owns benchmark execution and reports.

`Auto` keeps caller-visible normal enumeration, including when volume inventory is allowed. Explicit `Mft` mode requires Windows, administrator access and an existing local NTFS 3.0/3.1 volume. It rejects reparse roots and ancestors. Unsupported native filters use normal enumeration in `Auto`; forced MFT accepts only `*`. Cancellation and malformed records remain failures, never successful fallback.

The explicit MFT backend defaults to bulk capture:

1. Query NTFS geometry and initial MFT valid length through the existing read-only volume handle.
2. Decode the MFT's own unnamed-data mapping pairs, including attribute-list extension records. Reject missing identities, sparse/compressed metadata mappings, gaps, overlaps and out-of-partition reads.
3. Attempt aligned volume reads. If the volume returns ERROR_NOT_SUPPORTED, resolve its single physical partition extent and verify physical-disk bounds plus NTFS boot serial, geometry and MFT location before reading the mapped metadata. Unsupported multi-extent layouts remain errors. This fallback opens the physical disk read-only; it never locks, dismounts or writes the volume.
4. Read metadata in multi-megabyte buffers. Raw FILE records use NTFS's fixed 512-byte update-sequence protection stride, independently of device-sector I/O alignment. Verify every trailer before restoring any bytes. Logical FSCTL record output remains a distinct route without raw fixups.
5. Decode standard information, default-stream logical length and all non-DOS hardlink names, merge sequence-qualified extensions and build the in-memory parent/child index. Contradictory header-reference hints use the existing supported identity-checked Windows link-count validation.
6. Recheck layout extents, report I/O/parse/index evidence and close raw handles. Deadline/cancellation checks run between bootstrap, stream and final-verification operations; synchronous kernel calls remain uninterruptible.

`MftReadMode.RecordApi` retains the individual-record acquisition route for diagnostics and comparisons. No external reader dependency is introduced. Raw MFT buffers can contain resident data; only inventory metadata is decoded/retained, and raw buffers are never persisted.

`InventoryScan` computes bounded path/metadata fingerprints entirely in C#. Its returned summary records handled errors while preserving a supplied caller callback and options. `FolderTotals` aggregates logical file-path counts and lengths per folder, retaining only folder rows with an explicit folder budget. Hardlinks count per path; allocated-space and unique-file accounting are separate contracts. Without an error sink, enumeration errors are fatal; with one, folder-total callers must inspect it for partial coverage. The PowerShell adapter reports directory read errors and continues through independent directories.

## Compatibility boundaries

Normal enumeration supports literal directory roots, multiple roots, children, recursion, implicit recursion through `Depth`, files/directories, `Force`, native `Filter`, relative `Name`, and explicit native objects. Recursion stops at directory reparse points. Preserve runtime differences rather than silently treating them as equivalent.

MFT records include metadata captured at different instants during acquisition. The index is not an atomic snapshot; new paths are absent until recapture, and links or identities can change during capture or query. Root identity validation and sequence-qualified parent/base identities improve correctness without establishing complete concurrent-change safety. Privileged raw-volume visibility also differs from directory ACL visibility.

File roots, wildcard `Path`, `Include`/`Exclude`, provider dynamic parameters, Registry/Certificate providers, streams, exact ordering, formatting and complete provider error continuation remain outside the prototype contract. Hardlink fixtures establish only the exercised cases; they do not prove every namespace and concurrent-mutation combination.

Normal enumeration can continue after an inaccessible directory when an explicit error sink is supplied. The PowerShell adapter supplies that sink; C# consumers retain the errors separately or in the inventory summary. The direct backend can finish traversal of its reachable captured graph after link-count validation, but that is not an equivalence proof for every current filesystem path. A live acquisition can also observe an extension whose base identity is absent; this is preserved as a failure with identities for diagnosis.

The preceding individual-record evaluation and the bulk evaluation cover live fixtures and four budget/cancellation guards in both PowerShell 7 and Windows PowerShell 5.1. All 34 fixture paths and exercised file metadata match; one directory last-access timestamp differs. Both deterministic suites pass 37 tests, including raw-record corruption, fixed 512-byte protection strides on synthetic 4KiB-sector geometry, runlist bounds and handled-error accounting. No physical 4KiB-sector volume was qualified. Bulk performance and the preceding individual-record measurements are reported separately in [results](RESULTS.md), with failures and source provenance retained.

An inventory never authorizes deletion. Development-storage consumers still require fresh ownership, Git, activity, reparse and preservation checks before any cleanup.

## Acquisition and query budgets

Defaults are four million records, 2 GiB conservative index accounting, two minutes and a 512 MiB MFT-length guard. Evaluation overrides are explicit and require available RAM. Accounting is not an exact heap ceiling. Cancellation and timeout checks run between synchronous control calls, decoded records, merges and emitted entries; they cannot interrupt an executing native call. No background unbounded worker, persistent database, journal or virtual disk is created. Physical metadata reads are limited to the verified partition and decoded MFT layout.

Bulk capture reads mapped buffers; the explicit RecordApi diagnostic reads one record per control call. Acquisition cost is reported separately from repeated queries; fast retained-index queries cannot establish fast fresh whole-volume scans. A cached index also needs a freshness design before it can serve as a transparent enumeration backend.

## Comparison contract

Use an existing mounted `EVOTEC_SCRATCH_ROOT`, task-owned fixtures and the reviewed read-only elevation driver. Machine-local paths stay in request/results files. The bulk matrix separates fresh acquisition/index construction, C# metadata scanning, C# folder totals and PowerShell count-only output on 500,000 files, a 50,000-file subtree and an existing whole drive. Fresh MFT capture and a normal streaming scan have different retained-output and visibility contracts; report their coverage instead of implying exact equivalence. No virtual disk is used.

The shared streaming consumer reads paths, attributes, default-stream lengths, creation and last-write times inside each timed operation. Compact order-independent fingerprints validate synthetic counts and metadata outside the clock without retaining millions of paths. Synthetic errors or fatal traversal aborts invalidate a sample. Whole-drive counts, errors and visibility differences are reported without claiming exact equivalence or ranking an incomplete walk.

The bulk matrix records elapsed time, CPU time and process allocation separately. First-result latency and post-collection retained heap are retained only where separately measured; they are not supplied by the bulk matrix. Capture records estimated index bytes, mapped read bytes/calls, record/link/extension counts and incomplete records. Native mapped-read counters exclude boot probes and logical control calls. Preserve source/assembly provenance, CPU affinity, priority, power plan, OS and actual host runtime. Two rotated warm-cache samples with retained outliers are exploratory evidence, not a universal performance guarantee. No cold-cache or peak-memory claim follows from them.

Both PowerShell hosts run live hardlink/extension, Unicode, resident/nonresident, empty-file and alternate-stream compatibility checks, plus record/memory budget and capture/query cancellation guards. Deterministic tests cover normal routing/options and bounded direct-record decoding. Keep timing assertions out of correctness tests.

## Remaining production decisions

- [ ] Choose a public explicit inventory/index workflow or a compatibility-preserving hybrid from the measured acquisition and query costs.
- [ ] Define logical path size, unique-file size, allocated size, hardlink attribution, alternate-stream and sparse/compressed-file accounting explicitly before using the index as a disk-space assessment engine. Resident data and shared MFT records must not be assigned a fictional per-file cluster allocation.
- [ ] Qualify concurrent replacement, freshness, access/visibility, reparse behavior, long paths and case-sensitive directories before automatic selection.
- [ ] Resolve directory timestamp semantics and provider-style error continuation before claiming filesystem compatibility with Get-ChildItem.
- [ ] Establish cancellation latency, actual peak-memory bounds and a cache invalidation/update strategy.
- [ ] Add finite per-engine benchmark budgets and progress counters before repeated unattended whole-volume qualification. An interrupted or timed-out scan must retain partial status and must not enter successful timing rankings.
- [ ] Compare cold/warm workloads and representative CPU domains before defining routing thresholds or promising whole-drive scan times.
- [ ] Integrate only a qualified engine into the main library and thin module; validate CI and packaged artifacts. New production dependencies require separate approval.

The earlier USN name index and per-path metadata hydration remain historical comparison evidence. Its missed hardlink alias and lack of same-tree speed gain motivated direct metadata acquisition. Bulk MFT capture now reads about five million records in the measured 11.67–22.88 seconds; retained-index folder totals and PowerShell delivery remain separately measured, with acquisition cost and unmatched whole-drive coverage disclosed. Retain negative results and keep ordinary enumeration wherever the indexed route does not earn its setup and compatibility costs.

## Platform references

- [FSCTL_GET_NTFS_FILE_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_get_ntfs_file_record)
- [OpenFileById](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-openfilebyid)
- [GetFileInformationByHandle](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfileinformationbyhandle)
- [NTFS_FILE_RECORD_OUTPUT_BUFFER](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-ntfs_file_record_output_buffer)
- [FILE_RECORD_SEGMENT_HEADER](https://learn.microsoft.com/en-us/windows/win32/devnotes/file-record-segment-header)
- [ATTRIBUTE_RECORD_HEADER](https://learn.microsoft.com/en-us/windows/win32/devnotes/attribute-record-header)
- [FILE_NAME](https://learn.microsoft.com/en-us/windows/win32/devnotes/file-name)
