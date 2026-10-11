# Windows MFT API prototype results

The Windows API backend works on the assessed D: volume. It inventories names and identities through `FSCTL_ENUM_USN_DATA`, then reads full metadata for selected paths through ordinary file APIs. It is useful evidence for an explicit volume index, but the measured full-metadata queries do not justify replacing normal enumeration automatically.

## Reproducible comparison

Valid PowerForge run: `20261011-151824-f3d9a0fb`. Measured source: `c9fb0505837fa9fe81ed10edd84646a45238403d`, clean worktree. Prototype assembly SHA-256: `DCE98754BE607306171A3F2C617DDF2956B830F3DBF547C821ED05017CDE222D`.

Environment: Windows build 26300, Ryzen 9 9950X3D2, PowerShell 7.6.6 on .NET 10.0.12, normal process priority, high-performance power plan, affinity mask `1` (one logical CPU). Filesystem caches were warm. PowerForge used one warmup and three rotated measured iterations, retaining every outlier. Timing covers enumeration and output consumption into an array; full-result correctness validation runs outside the clock.

All **36 measured samples succeeded**. The two automatic-fallback cases were explicitly skipped in this elevated matrix; fallback is covered by the runtime contract tests and a separate elevated path-parity diagnostic. MFT lanes were measured, not skipped.

| Full-metadata engine | 10,110-entry tree median | 1,010-entry subtree median | Tree mean time to first result | Tree mean process allocation |
| --- | ---: | ---: | ---: | ---: |
| Get-ChildItem | 119.58 ms | 14.18 ms | 3.11 ms | 63.15 MB |
| Normal walk, metadata objects | 93.18 ms | 11.44 ms | 2.58 ms | 85.43 MB |
| Fresh MFT inventory plus hydration | 8,731.72 ms | 7,484.29 ms | 8,383.36 ms | 1,029.62 MB |
| Reused MFT index plus hydration | 129.08 ms | 15.41 ms | 3.52 ms | 88.88 MB |

MB above is decimal. Median duration, mean first-result latency and mean allocation are different statistics. The full-tree Get-ChildItem samples ranged from **113.47 to 576.13 ms**; its median is 119.58 ms and its mean is 269.73 ms. Three samples on a busy workstation are exploratory evidence, not a portable ranking. Allocation is process-wide and is not retained heap or peak memory.

The fresh lane inventories D: even when the requested subtree is small. It includes that setup cost and selected-path metadata hydration. The reused-index lane does not include recapture. On these trees, reused MFT metadata queries were slightly slower than Get-ChildItem and fresh capture was much slower. The normal walk was faster by median while allocating more memory.

Native-object construction lanes were also measured: normal walk **111.13 / 10.74 ms**, reused MFT **162.36 / 12.03 ms** for tree/subtree. These include constructing returned FileInfo/DirectoryInfo objects after initial metadata hydration. Consumers can trigger additional metadata I/O when reading those native objects; validation reads their properties outside the measured operation. Do not interpret these lanes as the cost of every downstream property access.

## Volume inventory and memory

The retained-index setup in the valid timing run captured **3,614,940 records in 15.24 seconds** on the single logical CPU. It read **385,547,160 bytes** of API output, while the underlying MFT valid length was **3,801,088,000 bytes**. These are different quantities.

Setup allocated **945,357,640 bytes** process-wide and increased post-collection managed heap by **515,510,376 bytes**, approximately **492 MiB**. Conservative index accounting was **1,084,006,496 bytes**, approximately 1.01 GiB. The accounting deliberately includes slack and adjacency overhead; it is not an exact heap cap. End-of-run process working set was about 2.09 GiB, including the host and benchmark work; this is neither the index size nor a peak-memory measurement.

Independent runtime diagnostics captured **3,614,917 records in 11.92 seconds in PowerShell 7 using the net8.0 build** and **3,616,751 in 13.99 seconds in Windows PowerShell 5.1 using the net472 build**. Those diagnostic hosts were not pinned to the benchmark CPU domain. Counts differ because other applications continued changing D:. The inventory does not provide an atomic point-in-time snapshot.

These are name/identity acquisition results. A complete whole-drive size inventory must also obtain lengths and other required metadata. No whole-drive Get-ChildItem comparison, cold-cache measurement or complete whole-drive metadata speed claim is established here.

## Compatibility and safeguards

Deterministic tests: **26 passed on Windows PowerShell 5.1 and 26 passed on PowerShell 7.6.6**, with Pester 5.7.1. Both target frameworks built with zero warnings and errors. Contracts include the supported walk options, provider/routing behavior, Unicode/full identities, malformed native record boundaries, unsafe path components, and cancellation after enumeration begins.

Live diagnostics ran seven compatibility cases in each runtime: children, recursion, Force, files, directories and Depth 0/1. Both reported **14 Get-ChildItem paths versus 13 MFT paths** in the full forced case. The missing path was `a.txt`, one name of a hard-linked file. Other present file lengths, attributes and creation/write/access times matched in these fixtures.

Directory last-access timestamps differed. The same differences reproduce between Get-ChildItem directory entries and a freshly refreshed DirectoryInfo without using MFT. The separate observation report records exact UTC values. This is a compatibility difference between metadata access paths, not evidence of a USN timestamp-decoding defect: the USN decoder does not supply those timestamps.

Four live guards passed on each runtime: record-budget rejection, estimated-memory-budget rejection, cancellation during capture, and cancellation of a deferred query before output. These prove exceptions were observed; they do not measure cancellation latency, a hard heap ceiling or timeout latency.

Automatic routing remains on normal enumeration, including when volume inventory is allowed. Forced MFT mode is explicitly experimental and preserves failures. Full hard-link coverage, stable identity under concurrent replacement, access/visibility, long paths, case-sensitive directories and provider error-continuation behavior remain production gates.

## Failure evidence and review

The first native run stopped at its 1 GiB index-accounting guard. The explicit evaluation budget was increased to 2 GiB; record/time limits remained in place. A later timing attempt was discarded when the source-provenance gate detected a plan commit during measurement. The final valid run used unchanged source throughout. Compact failures remain alongside the successful evidence.

The earlier raw-sector reader failed with ERROR_NOT_SUPPORTED on this environment. Supported Windows control calls work; the rejecting raw-read component is unidentified. The native prototype removes the external reader dependency, patches, private package staging and virtual-disk experiment source. No virtual disk was created.

A fresh independent read-only review covered the native API layouts, decoder, bounds/cancellation/lifetime, routing, adapter, benchmark and dependency isolation. It found no actionable technical defects and accepted this shape for the isolated evaluation, while holding production integration. Reviewed native candidate: `6afd2ccd2db37e2b9669d36c7b909a15047e2c5f`, plus the timing-only driver addendum committed as `c9fb050`. Review coverage remains current; no targeted confirmation was needed.

## Next useful work

Keep normal enumeration for ordinary filesystem queries. A separate reusable volume-index workflow is the next candidate: capture once, search names/identities repeatedly, and hydrate metadata only for selected results. Before automatic MFT selection, implement complete hard-link paths and identity-safe traversal, then qualify a metadata acquisition strategy on broad and repeated workloads. Reusing this partial index alone did not improve the tested full-metadata workload.

The [plan](PLAN.md) records the remaining production gates. Published FileInspectorX projects and packages remain unchanged.
