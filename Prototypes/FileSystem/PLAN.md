# MFT-backed filesystem query and Get-ChildItem replacement plan

Status: evaluation prototype, 2026-10-11. The existing published FileInspectorX API and module are unchanged. This plan replaces the earlier walk-first implementation sequence with an MFT-first comparison, while retaining ordinary enumeration as an essential supported backend.

## Objective and scope

Build a filesystem alternative to `Get-ChildItem` in FileInspectorX: fast metadata discovery on local NTFS volumes, ordinary directory enumeration where it is cheaper or required, and a familiar PowerShell surface over one reusable C# engine. Select a backend without changing the caller's visibility or pretending that a metadata snapshot is a live `FileInfo`.

The immediate deliverable is a runnable prototype and evidence about speed and compatibility. Production adoption, the final public command name, a complete provider replacement, package publication, persistent indexing, ACL acceleration and destructive file operations are separate steps. No universal speed multiplier or fixed whole-drive scan time is promised.

The useful initial consumers are large file inventories, directory-size assessments and development-storage review. Existing content analysis remains a separate operation on selected paths. A storage review consumer must still perform fresh ownership, Git, activity, reparse-point and preservation checks before deletion; an MFT record never grants cleanup authority.

## Starting point and ownership

Assessment base: FileInspectorX `e9e706dfd6487fa415bfa28bc7d63e64d5094693`. The primary checkout has existing version, build-default and generated-help edits. Work takes place in an isolated `feature/mft-childitem-prototype` worktree.

FileInspectorX already owns content inspection, filesystem metadata and per-file permission snapshots. Its existing `AnalyzeDirectory` path enumerates directories and then opens selected file contents; it is not a volume-wide metadata index. The reusable inventory/query engine belongs in FileInspectorX, with thin PowerShell and future CLI adapters. Benchmark scheduling, warmups, rotated ordering, summaries and comparisons remain in PowerForge/PSPublishModule.

The prototype under `Prototypes/FileSystem` is a standalone, nonpackable, nonpublishable project targeting .NET 8 and .NET Framework 4.7.2. No normal solution, library or module references it. The existing asynchronous cmdlet base is linked unchanged; the command awaits real MFT I/O and uses the established pipeline communication route.

## Prototype contract

`Get-FileSystemItem` is an experimental command name. It does not shadow `Get-ChildItem` or install an alias.

| Behavior | Prototype |
|---|---|
| Input | One or more literal directory roots in the FileSystem provider |
| Traversal | Children, `-Recurse`, implicit recursion with `-Depth`, no descent into directory reparse points |
| Selection | `-File`, `-Directory`, `-Force`; normal backend uses native `-Filter` semantics |
| Default output | Typed metadata snapshots with `FullName`, `Name`, `Extension`, `PSIsContainer`, size, attributes and timestamps |
| Native output | `-AsFileSystemInfo` constructs live `FileInfo`/`DirectoryInfo` objects; later property access can perform I/O |
| Names | `-Name` emits paths relative to the requested directory |
| Routing | `-Backend Walk`, `Mft`, or `Auto`; chosen backend and fallback reason appear in verbose output |
| Snapshot reuse | Explicit `-Snapshot` for repeated queries; capture time and volume identity stay visible |
| Cancellation | Capture and ordinary iteration observe cancellation; cancellation is not successful fallback |
| Errors | Root and enumeration failures remain visible; partial output is not a proof of complete coverage |

Directory lengths are absent rather than fabricated. Ordering is unspecified. ACLs, content hashes and file content are not loaded by enumeration. The prototype does not implement wildcard `-Path`, `-Include`, `-Exclude`, `-Attributes`, alternate data streams, provider-specific options, every PowerShell extended property, or individual-file input. Enumeration errors currently stop the affected root, rather than reproducing every nonterminating provider error and sibling-continuation behavior.

## Backend selection and visibility

`Walk` streams ordinary directory enumeration. Native filter matching is delegated to the platform. Traversal continues through nonmatching directories; hidden/system directories are not entered unless `-Force` is present. Directory links are returned as entries but not followed.

`Mft` reads the whole local NTFS volume into memory before querying a directory prefix. An explicit trailing separator prevents a sibling such as `build-old` from matching `build`. Hidden and reparse ancestors are excluded during recursion. Capture closes its raw volume handle before handing the node table to the caller.

Raw-volume inventory is an elevated visibility contract. It can reveal paths that the user's normal directory access would not enumerate. It cannot silently become the default for an ordinary PowerShell filesystem query. `Auto` therefore uses normal enumeration unless `-AllowVolumeInventory` explicitly enables experimental raw-volume visibility. With that opt-in, unavailable raw access, unsupported filesystems/platforms, an exceeded capture budget, or unsupported MFT filter syntax select normal enumeration **before any MFT output**. A forced `Mft` request reports those failures. Corrupt reader data and cancellation are not silently converted into success.

The prototype MFT backend supports only `-Filter '*'`; other native wildcard filters use the ordinary backend in `Auto`, or fail explicitly in `Mft`. This avoids substituting PowerShell wildcard semantics for the filesystem provider's DOS wildcard rules. Later qualification must supply equivalent native matching before expanding this subset.

A read-only `FSCTL_GET_NTFS_VOLUME_DATA` preflight preserves Win32 access-denied errors and limits MFT metadata length to 512 MiB by default. This limit is a guard on input size, **not a hard process-memory ceiling**. Reader arrays, names and query results allocate additional memory. The current reader's prefix query visits the full in-memory table and materializes its results before yielding; warm queries are not an efficient persistent subtree index, and query-phase cancellation cannot interrupt that internal parallel pass.

Backend decisions must eventually be workload based. A small directory or a request for an early result often favors walking; a broad inventory or repeated indexed query may favor MFT. An MFT setup cost cannot be hidden in untimed setup and then presented as a fresh scan result.

## Reader evaluation and dependency boundary

The comparison project pins `itsWindows11.NtfsReader` **0.1.0**, licensed **LGPL-2.1-or-later**, with package source commit `1ec8aeb2950c082d31593791dcced249b2d201df`. This is an evaluation-only dependency. `PrivateAssets="all"`, project isolation and disabled packing/publishing are complementary controls; none of them alone would make a shipped runtime dependency test-only.

The reader supplies live raw-volume acquisition and names, sizes, attributes and standard-information timestamps without per-file metadata calls. It is not yet qualified as the production backend. Its documented/observed design limits include incomplete extension-attribute-list handling, 32-bit record indices and one selected name per record. Alternate hard-link paths require explicit compatibility assessment. Its async initializer closes the raw handle in a `finally` block on success or failure; the adapter also closes the completed reader before handing off the in-memory snapshot.

The exact pinned source passes `(creation, fileChange, lastAccess)` into a constructor declared `(creation, lastAccess, lastChange)`. The adapter explicitly reverses those two exposed fields to recover last-write and last-access timestamps. Real-volume metadata comparison must verify this mapping; a future version change must reassess it rather than retaining an undocumented workaround.

Live comparison on the assessed D: volume is currently blocked at raw I/O. Native aligned `ReadFile` probes return Win32 `ERROR_NOT_SUPPORTED` (50) through both drive-letter and volume-GUID handles; deliberately unaligned probes return `ERROR_INVALID_PARAMETER` (87). The ordinary fallback works and preserves all synthetic fixture paths. This establishes an acquisition limitation on this environment, not a parser-throughput result or complete proof of its cause. Do not infer an MFT speed result from this failed acquisition.

A separate source evaluation corrects the reader's `CreateFile` access flag from `1` to Win32 `GENERIC_READ` and preserves native errors from handle creation and legacy reads. `Build-ReaderEvaluation.ps1` downloads the pinned source, applies the reviewable patch, limits the build to the evaluated target frameworks, and builds version `0.1.0-mft-prototype.2` into a task-local feed/cache. The earlier flag-only variant, `0.1.0-mft-prototype.1`, also encounters the volume I/O limitation here. Original and patched results stay distinct; no source is vendored into the production engine or ordinary package cache. Legacy automatic capture remains disabled until it is qualified; forced MFT diagnostics remain available. Do not classify a generic `IOException` as unavailable access or suppress parser failures.

A later read-only diagnostic establishes that D: is healthy and online, with ordinary NTFS access working and no BitLocker encryption. Explicit uncached, aligned sector reads at offsets 0 and 4096 still return error 50. On the same elevated process, `FSCTL_GET_NTFS_VOLUME_DATA` and `FSCTL_GET_NTFS_FILE_RECORD` both succeed, including the `FILE` signature for record zero. This is a sector-read-path failure, not evidence that D: or its MFT is generally unreadable. The rejecting OS/filter/storage component is unidentified; installed filters alone do not establish causation.

The next acquisition investigation should compare supported Windows MFT control APIs with direct sector acquisition before creating a test volume or changing machine configuration. `FSCTL_GET_NTFS_FILE_RECORD` retrieves one in-use record per call, so its success does not establish fast whole-volume acquisition. A batched name/identity inventory through `FSCTL_ENUM_USN_DATA` plus selected record hydration is a possible evaluation route; it must expose the extra metadata cost and hard-link/extension-record limits. Keep the present normal-enumeration fallback while this route is assessed.

Eric Zimmerman's MIT-licensed MFT parser remains an alternative for captured-record parsing, but live-volume acquisition, dependency scope, memory cost and correctness would need separate qualification. Supported Windows APIs are preferred for capability discovery. `FSCTL_ENUM_USN_DATA` provides file identity/name records, not file lengths or complete ACLs, so a USN-only implementation cannot honestly replace this metadata workload without additional work.

Before introducing any production reader, obtain an explicit dependency/role decision with its license obligations, maintenance, supported runtimes, distribution model, native privileges, failure behavior and alternatives. Prototype success is evidence for that decision, not approval to ship the dependency.

## Comparison and acceptance evidence

The committed PowerForge spec compares these lanes on identical frozen synthetic trees:

1. Native `Get-ChildItem` with equivalent literal root, recursion and force options.
2. Ordinary prototype enumeration returning metadata snapshots.
3. Ordinary prototype enumeration returning native objects.
4. Automatic routing, including real access-denied fallback in a non-elevated process.
5. A fresh MFT capture plus query, including the whole-volume capture in the measured operation.
6. An explicit retained MFT snapshot query, with its initial capture cost recorded separately.

The fixture has 10,000 eight-byte files, 100 group directories and 10 top-level directories. A subtree case queries one top-level directory. Fixture creation and validation stay outside timed operations. Validation compares sorted paths, sizes, attributes and last-write ticks for every output item. Metrics include elapsed time, time to first result, process allocations and item count. Failed compatibility remains a failed lane; unavailable optional MFT lanes appear as skipped.

Use a fixed logical CPU domain for the entire matrix, normal priority, rotated order, one warmup and three measured iterations for the prototype. Record CPU model, affinity, OS build, runtime, active power plan, DLL hash, exact reader version/license and capture metadata. These are exploratory local measurements with warm filesystem caches; they do not establish cold-disk throughput, best multi-core performance or another machine's behavior. Retain negative results and individual samples.

A separate real-volume diagnostic compares children, recursion, force, file/directory selection and depth against native enumeration on a small controlled fixture. Include distinct timestamps, hidden ancestors, hard-link aliases, reparse directories and sibling-prefix paths. Record missing/extra paths and every requested metadata mismatch. A known reader limitation must not be renamed a successful compatibility test.

Current proof: both frameworks and the isolated patched-reader variant compile without warnings. The 20-contract suite includes a legacy automatic-routing guard: all 20 apply on Windows PowerShell 5.1; 19 apply on PowerShell 7.6.6, with the legacy-only check skipped. Raw MFT measurement requires explicit Windows elevation and remains separately recorded. An isolated NTFS virtual-disk comparison is prepared as a separate opt-in experiment; creation/formatting requires explicit authority beyond the read-only D: comparison. It remains unapproved and unexecuted. Its completion requires verified detachment; a cleanup failure produces a failed invocation and receipt. It cannot establish whole-drive performance on D:. Results belong in a compact evidence file alongside this plan, not in the published module's command documentation.

## Delivery checklist

- [x] Inspect the current implementation, shared owners and local dirty state; preserve the primary checkout.
- [x] Build an isolated MFT/normal-query prototype and thin PowerShell adapter for both supported Windows hosts.
- [x] Prove the ordinary filesystem subset and actual permission fallback on both runtimes.
- [x] Declare reproducible PowerForge comparison lanes and visible compatibility validation.
- [x] Complete the normal timing matrix and record elevated acquisition diagnostics.
- [ ] Complete MFT timing and metadata compatibility; sector acquisition is blocked, while Windows MFT control APIs are accessible.
- [x] Complete one independent read-only code/contract review and remediate valid in-scope findings.
- [ ] Retain compact evidence, remove disposable synthetic/build output and report storage.
- [ ] Decide the production reader/dependency and public API after reviewing results.
- [ ] Implement the qualified engine in the normal FileInspectorX core and expose thin module/CLI surfaces.
- [ ] Qualify filesystem/provider compatibility, cancellation, partial errors and package/runtime behavior in CI.

## Production qualification after the prototype

The production design must preserve all names for hard links, file/parent identities and sequence numbers, resident/nonresident data, sparse/compressed/allocated-size distinctions, extension records, reparse/mount boundaries and supported path lengths. Large-directory traversal and full-volume indexing require finite memory/concurrency bounds and responsive cancellation, including query construction. Use captured parser fixtures for malformed records and isolated live fixtures for filesystem behavior. Never alter production ACLs or databases to create benchmarks.

Treat caller-visible enumeration and privileged volume inventory as distinct public modes. Qualify normal filesystem fallback on SMB, non-NTFS filesystems, unsupported platforms and denied access. On Windows PowerShell 5.1 and current PowerShell 7, compare output types, native filtering, names, depth, hidden/system behavior, errors and downstream pipeline callers. Test Linux/macOS walking independently before claiming portability. Select `Auto` thresholds only after these paths and workload costs are supported by evidence.

Add logical/allocated/deduplicated directory-size APIs after file-identity semantics are established. Add permission snapshots as an explicit cost: ordinary ACL reads initially, with any bulk `$Secure` work qualified separately. ACL summaries are not effective-access decisions. Persistent indexing and USN refresh are later capabilities, justified by repeat-query demand; they require journal-wrap/deletion/rename recovery, freshness reporting, privacy, bounded storage and a rebuild path.

The development-storage maintenance integration should consume the read-only query API for discovery. It must preserve the existing independent deletion gates. Copy/move/delete replacements and a complete cross-provider `Get-ChildItem` clone remain outside this plan's first product release.

## Primary references

- [Get-ChildItem contract](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-childitem)
- [Direct volume access](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [NTFS volume metadata](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-ntfs_volume_data_buffer)
- [NTFS record retrieval](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_get_ntfs_file_record)
- [USN enumeration](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_enum_usn_data)
- [USN record fields](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v2)
- [Pinned evaluation package](https://www.nuget.org/packages/itsWindows11.NtfsReader/0.1.0)
- [Pinned reader source](https://github.com/itsWindows11/NtfsReader/tree/1ec8aeb2950c082d31593791dcced249b2d201df)
- [Alternative captured-MFT parser](https://github.com/EricZimmerman/MFT)
