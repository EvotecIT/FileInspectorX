# MFT-backed filesystem query and Get-ChildItem replacement plan

FileInspectorX owns the reusable filesystem query engine. The isolated prototype under `Prototypes/FileSystem` evaluates direct NTFS metadata and normal enumeration behind a thin `Get-FileSystemItem` adapter. The published library and module remain unchanged. This is a filesystem subset, not a replacement for every PowerShell provider or every `Get-ChildItem` parameter.

## Implemented shape

The evaluation targets .NET 8 and .NET Framework 4.7.2, is excluded from normal solutions and module builds, and cannot be packed or published. It adds no external reader dependency and does not alias the built-in command. PowerForge/PSPublishModule owns benchmark execution and reports.

`Auto` keeps caller-visible normal enumeration, including when volume inventory is allowed. Explicit `Mft` mode requires Windows, administrator access and an existing local NTFS 3.0/3.1 volume. It rejects reparse roots and ancestors. Unsupported native filters use normal enumeration in `Auto`; forced MFT accepts only `*`. Cancellation and malformed records remain failures, never successful fallback.

The direct backend:

1. Opens the volume read-only and queries record geometry, NTFS version and MFT valid length with `FSCTL_GET_NTFS_VOLUME_DATA`.
2. Descends through in-use base and extension records with `FSCTL_GET_NTFS_FILE_RECORD`. A request can return a lower ordinal; the next request uses the returned ordinal minus one.
3. Bounds-checks logical API records and decodes standard-information timestamps/attributes, unnamed default-stream logical length, and all long-name `FILE_NAME` links. It counts DOS aliases for completeness without emitting duplicate short names. Named alternate streams do not inflate default-stream length.
4. Merges extension records through full sequence-qualified base identities, then builds parent/children adjacency. A contradictory header reference hint triggers an identity-checked, metadata-only Windows link-count probe. Captured non-DOS links must match that supported live count; failed probes remain incomplete. Missing owners, duplicate links and incomplete queried records remain visible errors.
5. Closes the volume handle, resolves the requested directory's current identity, and emits captured metadata without refreshing each path through ordinary metadata APIs. Native `FileInfo`/`DirectoryInfo` conversion remains explicit and can incur additional live I/O.

The API decoder accepts logical filesystem-control output only. Live Windows output can have logical sector trailers that differ from the update-sequence array; it validates structural bounds without applying raw-disk sector replacements. It is not a raw disk-image parser.

## Compatibility boundaries

Normal enumeration supports literal directory roots, multiple roots, children, recursion, implicit recursion through `Depth`, files/directories, `Force`, native `Filter`, relative `Name`, and explicit native objects. Recursion stops at directory reparse points. Preserve runtime differences rather than silently treating them as equivalent.

MFT records include metadata captured at different instants during acquisition. The index is not an atomic snapshot; new paths are absent until recapture, and links or identities can change during capture or query. Root identity validation and sequence-qualified parent/base identities improve correctness without establishing complete concurrent-change safety. Privileged raw-volume visibility also differs from directory ACL visibility.

File roots, wildcard `Path`, `Include`/`Exclude`, provider dynamic parameters, Registry/Certificate providers, streams, exact ordering, formatting and complete provider error continuation remain outside the prototype contract. Hardlink fixtures establish only the exercised cases; they do not prove every namespace and concurrent-mutation combination.

The whole-drive normal prototype stops at the first inaccessible directory. Get-ChildItem continues and reports errors. The direct backend can finish traversal of its reachable captured graph after link-count validation, but that is not an equivalence proof for every current filesystem path. A live acquisition can also observe an extension whose base identity is absent; this is preserved as a failure with identities for diagnosis.

The completed evaluation covers live fixtures and four budget/cancellation guards in both PowerShell 7 and Windows PowerShell 5.1. All 34 fixture paths and exercised file metadata match; one directory last-access timestamp differs. Both deterministic suites pass 29 tests. The rotated large-tree comparison shows mixed cached-query performance, with expensive acquisition and no equivalent whole-drive timing result. [Results](RESULTS.md) retains the measurements, failures and source provenance. The next performance experiment should compare a bounded C# size/count aggregate with its ordinary-enumeration equivalent before expanding the PowerShell replacement surface.

An inventory never authorizes deletion. Development-storage consumers still require fresh ownership, Git, activity, reparse and preservation checks before any cleanup.

## Acquisition and query budgets

Defaults are four million records, 2 GiB conservative index accounting, two minutes and a 512 MiB MFT-length guard. Evaluation overrides are explicit and require available RAM. Accounting is not an exact heap ceiling. Cancellation and timeout checks run between synchronous control calls, decoded records, merges and emitted entries; they cannot interrupt an executing native call. No background unbounded worker, persistent database, journal, raw-sector read or virtual disk is created.

Capture reads one record per filesystem control call. Its cost must be reported separately from repeated queries; fast retained-index queries cannot establish fast fresh whole-volume scans. A cached index also needs a freshness design before it can serve as a transparent enumeration backend.

## Comparison contract

Use an existing mounted `EVOTEC_SCRATCH_ROOT`, task-owned fixtures and the reviewed read-only elevation driver. Machine-local paths stay in request/results files. The large matrix compares `GetChildItem`, `Walk` and retained `MftSnapshot` on 500,000 files, a 50,000-file subtree and an existing whole drive. No virtual disk is used.

The shared streaming consumer reads paths, attributes, default-stream lengths, creation and last-write times inside each timed operation. Compact order-independent fingerprints validate synthetic counts and metadata outside the clock without retaining millions of paths. Synthetic errors or fatal traversal aborts invalidate a sample. Whole-drive counts, errors and visibility differences are reported without claiming exact equivalence or ranking an incomplete walk.

Record elapsed time, first-result latency, CPU time and process allocation separately. Record index capture time, allocation, post-collection retained heap, estimated bytes, native output bytes, record/link/extension counts and incomplete records. Preserve source/assembly provenance, CPU affinity, priority, power plan, OS and actual host runtime. Two rotated warm-cache samples with retained outliers are exploratory evidence, not a universal performance guarantee. No cold-cache or peak-memory claim follows from them.

Both PowerShell hosts run live hardlink/extension, Unicode, resident/nonresident, empty-file and alternate-stream compatibility checks, plus record/memory budget and capture/query cancellation guards. Deterministic tests cover normal routing/options and bounded direct-record decoding. Keep timing assertions out of correctness tests.

## Remaining production decisions

- [ ] Choose a public explicit inventory/index workflow or a compatibility-preserving hybrid from the measured acquisition and query costs.
- [ ] Compare engine-level aggregation with emitting millions of PowerShell objects. Directory-size/count consumers should aggregate in the C# owner and return bounded summaries; object enumeration remains a separate contract.
- [ ] Define logical path size, unique-file size, allocated size, hardlink attribution, alternate-stream and sparse/compressed-file accounting explicitly before using the index as a disk-space assessment engine. Resident data and shared MFT records must not be assigned a fictional per-file cluster allocation.
- [ ] Qualify concurrent replacement, freshness, access/visibility, reparse behavior, long paths and case-sensitive directories before automatic selection.
- [ ] Resolve directory timestamp semantics and provider-style error continuation before claiming filesystem compatibility with Get-ChildItem.
- [ ] Establish cancellation latency, actual peak-memory bounds and a cache invalidation/update strategy.
- [ ] Add finite per-engine benchmark budgets and progress counters before repeated unattended whole-volume qualification. An interrupted or timed-out scan must retain partial status and must not enter successful timing rankings.
- [ ] Compare cold/warm workloads and representative CPU domains before defining routing thresholds or promising whole-drive scan times.
- [ ] Integrate only a qualified engine into the main library and thin module; validate CI and packaged artifacts. New production dependencies require separate approval.

The earlier USN name index and per-path metadata hydration remain historical comparison evidence. Its missed hardlink alias and lack of same-tree speed gain motivated this direct-record experiment. Retain negative results and keep ordinary enumeration wherever the indexed route does not earn its setup and compatibility costs.

## Platform references

- [FSCTL_GET_NTFS_FILE_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_get_ntfs_file_record)
- [OpenFileById](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-openfilebyid)
- [GetFileInformationByHandle](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfileinformationbyhandle)
- [NTFS_FILE_RECORD_OUTPUT_BUFFER](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-ntfs_file_record_output_buffer)
- [FILE_RECORD_SEGMENT_HEADER](https://learn.microsoft.com/en-us/windows/win32/devnotes/file-record-segment-header)
- [ATTRIBUTE_RECORD_HEADER](https://learn.microsoft.com/en-us/windows/win32/devnotes/attribute-record-header)
- [FILE_NAME](https://learn.microsoft.com/en-us/windows/win32/devnotes/file-name)
