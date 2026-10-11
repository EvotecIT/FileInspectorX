# Direct MFT metadata prototype results

Direct Windows file-record capture reconstructs the exercised hardlinks and reads file metadata without per-path refresh. It does not establish a generally faster Get-ChildItem replacement. Retained-index queries won on the tested 50,000-file subtree and lost on the 500,000-file tree. Fresh capture is expensive. Both prototype backends aborted on the whole drive, so their partial durations are excluded from performance rankings. Automatic routing keeps normal enumeration.

## Measured candidate and method

PowerForge run `20261011-162040-997e2242` measured clean source `dfeedd203af544370a1c5c8c1a66c3897394021a`. Assembly SHA-256: `0B210359908771DA8EE764C68E90FEE68C9CBDFC0A4C3DDB6ED0F307EEE0FB98`. Later diagnostics or documentation changes must be identified separately from this measured candidate.

Windows build 26300, Ryzen 9 9950X3D2, PowerShell 7.6.6 on .NET 10.0.12, normal priority, high-performance power plan, affinity mask `1`. The assembly targets .NET 8; the actual benchmark host used .NET 10. Two rotated measured iterations, no warmups or outlier removal, warm filesystem state and an active workstation. These are exploratory observations, not cold-cache or universal performance guarantees.

The same streaming PowerShell consumer reads paths, attributes, default-stream lengths, creation and last-write times inside the clock. Synthetic counts and order-independent path/metadata fingerprints are validated outside the clock; no multi-million-path inventory is persisted. First-result latency, CPU and allocation are recorded separately. The MFT query lane reuses a captured index and excludes acquisition.

## Comparable synthetic queries

All twelve synthetic samples passed counts, paths, checked metadata and zero-error validation. The full tree contains 500,000 files and 110 directories; the subtree contains 50,000 files and ten directories.

| Engine | 500,000-file median | Observed range | 50,000-file median | Observed range |
| --- | ---: | ---: | ---: | ---: |
| Get-ChildItem | 24.81 s | 21.35–28.26 s | 2.54 s | 1.37–3.71 s |
| Normal walk | 29.63 s | 7.64–51.62 s | 1.49 s | 1.04–1.94 s |
| Retained direct MFT snapshot | 36.99 s | 24.75–49.23 s | 1.09 s | 1.090–1.098 s |

The retained MFT query is about 2.32 times faster by the subtree median, but about 49% slower on the larger tree. The setup cost is separate. Large variation in the normal walk and direct MFT tree samples prevents a stable ranking from two observations; both samples and all outliers are retained.

| Engine, 500,000-file tree | Median CPU | Median first result | Median process allocation |
| --- | ---: | ---: | ---: |
| Get-ChildItem | 12.41 s | 19.51 ms | 4.35 GB |
| Normal walk | 8.73 s | 30.42 ms | 4.63 GB |
| Retained direct MFT snapshot | 8.59 s | 11.20 ms | 4.60 GB |

GB is decimal. Allocation is process-wide accumulated allocation, not live heap or peak memory. Lower CPU or first-result latency does not imply lower elapsed duration. The per-object PowerShell path and an engine-level aggregate are different products and should be measured separately before choosing the storage-inventory API.

## Capture cost and memory

Direct logical `FSCTL_GET_NTFS_FILE_RECORD` acquisition took **256.16 seconds**, **50.48 seconds of process CPU**, and **1,909,057,736 allocated bytes**. Post-collection retained managed heap increased by **1,527,838,880 bytes**, approximately **1.42 GiB**. Conservative index accounting was **3,226,376,620 bytes**; it is not an exact heap ceiling or peak-memory measurement.

Capture read 4,315,962 records, including 16,757 extension records, and indexed 4,347,031 non-DOS links. It marked 5,364 base records incomplete. Native output total was 4,471,336,632 bytes; MFT valid length was 4,424,990,720 bytes. These describe different quantities. Record buffers are logical Windows API output, not raw disk sectors.

The direct backend uses one control call per returned record. Cached-query latency cannot establish a fast fresh whole-drive inventory. No persistent index, journal or virtual disk was created.

## Whole-drive coverage

Get-ChildItem completed two traversals, each reporting twenty errors. Durations were **24.25 and 23.00 minutes**. First pass: 3,576,805 files and 784,586 directories; second: 3,585,849 files and 783,487 directories. Counts and logical bytes changed while other applications used D:. These are live, caller-visible traversals with errors, not complete atomic inventories.

Both normal-walk samples aborted after 91,983 files and 44,255 directories. Both retained-MFT samples aborted after 1,597,918 files and 343,538 directories. The repeated partial fingerprints match within each backend. All four are failed samples; no duration comparison or speedup is reported for them.

The consumer correctly treats fatal query/enumeration errors as aborted coverage. It discarded the underlying exception details in this measured run. A bounded read-only core diagnostic identified access denial at a protected directory for normal enumeration. The prototype currently aborts the root instead of continuing with provider-style errors.

The MFT stop was a false completeness rejection: Office identity `0001000000207884` had a header reference hint of 84, twenty-two captured names and twenty-two current links reported by Windows. Independent `fsutil hardlink list` also returned twenty-two aliases. Microsoft documents that header member as reserved, so its value is not accepted as an authoritative live hardlink count.

Follow-up source **`65e8b9a839bf73e38e183e2cbfd69d7031b26ada`**, DLL **`049CA85D70A306D16E82384627D008B9EB26C2281EAD757C7C58F54ADFAD73FC`**, validates contradictory hints through metadata-only `OpenFileById` and `GetFileInformationByHandle`. Full identity must match, and the live link count must equal the captured non-DOS link count. Failed or mismatched checks remain incomplete errors. Timestamps and lengths still come from captured MFT records.

Its focused modern diagnostic validated all 5,364 contradictory records, reported zero incomplete records, and matched all twenty-two Office aliases. The core traversal completed its reachable index with **3,671,964 entries**. This is traversal of a captured graph, not proof that all current filesystem paths are present or equivalent to the earlier Get-ChildItem passes.

That diagnostic captured **4,162,339 records in 48.73 seconds**, with an unpinned fresh host and different live volume contents. Core iteration took 1.19 seconds and did not include a common PowerShell pipeline consumer or fingerprint work. Neither number belongs in the earlier timing comparison or proves a production whole-drive speedup. No full Get-ChildItem traversal or timing matrix was repeated.

The follow-up benchmark retains the first error's ID, category, exception and bounded message. A missing-root matrix verified those details for all eight intentionally failed samples. Whole-drive caller-visible coverage and error-continuation compatibility remain production gates.

## Compatibility and safeguards

Deterministic tests: **29 passed in PowerShell 7.6.6 and 29 in Windows PowerShell 5.1**, Pester 5.7.1. Both target frameworks build with zero warnings/errors. Contracts cover normal routing/options, sequence-qualified identities, logical API records with stale update-sequence entries, malformed boundaries, resident/nonresident lengths, DOS-name counting, extension merges and abort classification.

Modern live compatibility matches all **34 paths**, including thirty hardlink aliases whose source lies outside the queried tree. File attributes, creation/write/access times and default-stream lengths match for the exercised resident, nonresident, empty, Unicode and alternate-stream fixtures. One directory last-access timestamp differs across directory-bearing cases. An ordinary listing also disagrees with DirectoryInfo.Refresh, recorded with exact UTC ticks; that does not isolate the cause of the first MFT mismatch. Historical mismatch strings lose fractional precision and must not be treated as exact tick evidence.

Four modern live guards pass: record-budget rejection, estimated-memory-budget rejection, cancellation during capture, and deferred-query cancellation. They prove observed exceptions, not cancellation latency or a hard heap ceiling. The follow-up diagnostics preserve exact UTC strings and ticks for future mismatches.

The explicitly approved legacy-only relaunch completed at **2026-10-11 17:47 UTC** using the corrected native candidate and its .NET Framework 4.7.2 assembly. Windows PowerShell 5.1 matched all **34 paths**, all exercised file metadata and all four guards. Its seven query cases match counts; the same directory last-access difference appears in the six directory-bearing cases, with no other differences. Capture took **43.00 seconds**, indexed 3,657,843 base records and 3,688,815 non-DOS links, merged 16,717 extensions and reported zero incomplete records. The large fixture had already been deleted and the host was unpinned, so these counts and acquisition timing are separate compatibility evidence, not another sample in the original performance comparison. Full timestamp compatibility is not established.

## Retained negative evidence

The first direct capture rejected logical API records using a raw-sector update-sequence check. Numeric output probes showed logical sector trailers and stale array values. The corrected parser validates structural layout without applying raw-sector replacements; it remains explicitly unsuitable for raw disk images.

Earlier large benchmarks failed due to an invocation-scope bug or detected source changes; those samples are excluded. A missing-root diagnostic proves fatal query errors are aborted and synthetic errors fail validation. Compact failures are retained alongside successful evidence.

The original legacy capture failed when an extension's base identity was absent from the live acquisition. This failure is preserved; the follow-up reports both identities if it recurs. A later wrapper mistakenly passed the text `8GB` to the legacy process, and the first corrected launch was canceled. The subsequently approved legacy-only relaunch used the integer byte limit and completed. Initial failed status and logs remain alongside the successful retry; the successful acquisition does not erase the observed concurrent-change failure mode.

An independent read-only review and one targeted confirmation covered the initial direct-record parser, native/routing boundary and benchmark contracts. The later supported link-count validation is covered by the observed Office regression, complete modern core traversal, live fixture/guard checks and both deterministic suites; it has not received another independent pass.

The earlier USN name index plus ordinary metadata hydration remains separate historical evidence: Get-ChildItem medians **119.58 / 14.18 ms** describe different 10,110/1,010-entry trees, not competing engines. Reused USN-plus-hydration took **129.08 / 15.41 ms** on those same workloads and did not win. Its fixture missed a hardlink alias. Direct file-record decoding addresses the exercised alias loss, but does not retroactively validate the old backend.

## Disposition

Keep the isolated prototype and normal automatic routing. Before production integration, finish error continuation, directory timestamp semantics, freshness/concurrent identity qualification, access/visibility semantics, bounded peak-memory/cancellation proof and repeatable performance work. Compare a C# directory-size/count aggregate separately from emitting millions of PowerShell objects. The published FileInspectorX library/module and packages remain unchanged.

Platform contracts: [file-record header](https://learn.microsoft.com/en-us/windows/win32/devnotes/file-record-segment-header), [OpenFileById](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-openfilebyid), [GetFileInformationByHandle](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfileinformationbyhandle).
