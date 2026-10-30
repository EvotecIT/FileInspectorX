# Bulk MFT filesystem prototype results

Bulk MFT acquisition substantially reduces the cost of the preceding individual-record implementation on this workstation. The index also supports useful C# folder totals without emitting a PowerShell object for every entry. Normal enumeration remains the automatic backend: capture cost, memory, live namespace coverage and directory timestamp behavior still prevent a transparent Get-ChildItem replacement.

## Measured source and timer boundaries

The full matrix is PowerForge run `20261015-101834-d0ef1a91`, completed on 2026-10-15. Both it and focused synthetic run `20261015-112254-023c9f83` used clean source `f8f18e7d66c1de9193dbd093053249a71ec63606` and DLL SHA-256 `8D05B7312711A122181BE112714D087CCF109018CEEE99D6D8389F9A798AE6AC`. A subsequent benchmark-only change at `73ee1e20b824faa7d1c32df9bf08e306b975cb25` adds early baseline checks; it does not alter that engine binary. Its qualification run `20261015-112832-beb9345b` passed both early baseline comparisons and all 24 synthetic measured samples, with twelve planned skips. Final documentation commits are distinct from measured source.

Host: Windows build 26300, Ryzen 9 9950X3D2, 32 logical processors, normal priority, high-performance plan, affinity `FFFFFFFF`, PowerShell 7.6.6 on .NET 10.0.12. The assembly targets .NET 8. Two rotated measured iterations, no warmups or outlier removal, warm filesystem state and an active development workstation. The previous experiment used affinity `1`; its durations are not a controlled before/after pair.

Four operations have separate clocks:

- **Acquisition:** construct a fresh whole-volume MFT index with bulk reads or individual-record controls. The normal lane streams paths and metadata into a C# fingerprint; it does not construct the same retained index.
- **C# metadata scan:** enumerate paths, attributes, lengths, creation and write times into bounded order-independent fingerprints.
- **C# folder totals:** aggregate recursive logical file-path counts and sizes, retaining folder rows. Hardlink names count per path; this is not unique-file or allocated-space accounting.
- **PowerShell output:** Get-ChildItem or the thin MFT cmdlet piped to Measure-Object. It measures object delivery and count only, without the previous expensive PowerShell metadata-fingerprint consumer.

Cached MFT rows exclude acquisition. CPU and process-wide accumulated allocation are separate from elapsed time; allocation is not live heap or peak memory. The bulk matrix does not measure first-result latency, cold-cache performance or post-collection retained heap. Estimated index bytes are conservative accounting, not a measured heap ceiling.

## Fresh acquisition

| Acquisition / streaming scan | Median | Observed range | Median process CPU | Median process allocation |
| --- | ---: | ---: | ---: | ---: |
| Bulk MFT index | 17.28 s | 11.67–22.88 s | 13.20 s | 2.02 GB |
| Individual-record MFT index | 136.27 s | 101.49–171.05 s | 64.00 s | 2.18 GB |
| Normal C# streaming scan | 181.47 s | 122.44–240.50 s | 123.42 s | 2.79 GB |

Bulk capture decoded roughly 5.04 million records and 5.07 million non-DOS links, merged about 17,000 extensions and reported **zero incomplete records** in both acquisition samples. Initial MFT valid lengths were 5,183,373,312 and 5,197,791,232 bytes. Estimated retained-index accounting was about 3.78 GB. Actual retained heap was not remeasured.

Mapped reads numbered 2,473 and 2,481. Raw-read work took 2.56 and 2.57 seconds; record parsing took 15.19 and 5.48 seconds. These are measured subintervals, not a complete additive breakdown of capture. Counters include final mapped verification reads and exclude boot probes and logical FSCTL calls. No raw buffers or complete path inventories were written to disk.

The two MFT acquisition routes have the same intended index contract, but captured changing live contents at different instants. The normal scan reported twenty handled errors per pass and has different privilege, namespace and retained-output semantics. Its duration cannot establish an equivalent-coverage whole-drive speedup.

## Synthetic results from the full matrix

The full tree contains 500,000 resident eight-byte files, 110 directories and 4,000,000 logical file bytes. Its subtree contains 50,000 files and ten directories. Small resident files and few directories favor warm normal enumeration; this is not a representative model of every repository or drive.

| Workload and consumer | Normal median | Retained MFT median |
| --- | ---: | ---: |
| 500,000 files: C# metadata scan | Excluded: failed validation | Excluded: failed validation |
| 500,000 files: C# folder totals | 674.23 ms | 280.15 ms |
| 500,000 files: PowerShell count-only output | 7961.35 ms | 1999.39 ms |
| 50,000 files: C# metadata scan | 86.48 ms | 56.81 ms |
| 50,000 files: C# folder totals | 94.85 ms | 36.38 ms |
| 50,000 files: PowerShell count-only output | 992.04 ms | 236.64 ms |

All synthetic folder rows and subtree totals match, not just the root sum. Count-only PowerShell paths match entry counts with zero errors. The 50,000-file C# metadata fingerprints also pass.

Four 500,000-file C# samples failed against the initial metadata baseline. Both timed engines and both iterations returned the same paths, counts, sizes and metadata fingerprints as each other, but differed from the earlier baseline in MetadataXor/MetadataSum. The full run is therefore **failed overall**: 38 measured samples passed and four failed. Failed durations remain recorded and excluded from rankings.

The initial baseline's individual path metadata was not persisted, so its changed field or cause cannot be reconstructed. Directory last-access behavior does not explain this fingerprint failure: access time is deliberately outside that fingerprint. No parser defect was established by this failure.

## Focused field-level proof and synthetic rerun

A fresh field-level check compared all **500,110 entries** against an immutable normal-enumeration baseline. MFT and repeated normal walks match paths, attributes, lengths, creation times and write times, with zero missing or extra paths and identical fingerprints. Access time differs for 110 directories against the MFT capture and 100 directories between two ordinary walks. File metadata has no differences in that check.

The subsequent synthetic-only matrix used the same measured engine and passed all **24 measured samples**, with twelve deliberately skipped acquisition combinations:

| Workload and consumer | Normal median | Retained MFT median |
| --- | ---: | ---: |
| 500,000 files: C# metadata scan | 449.37 ms | 199.17 ms |
| 500,000 files: C# folder totals | 419.12 ms | 213.64 ms |
| 500,000 files: PowerShell count-only output | 6692.05 ms | 1537.84 ms |
| 50,000 files: C# metadata scan | 80.57 ms | 62.70 ms |
| 50,000 files: C# folder totals | 69.01 ms | 57.21 ms |
| 50,000 files: PowerShell count-only output | 721.63 ms | 313.27 ms |

This later success does not relabel the original failed samples. It establishes the exercised metadata contract on the stable rerun. The benchmark now records normal, repeated-normal and captured-MFT baseline fingerprints before timing and rejects a mismatch immediately, avoiding an expensive whole-drive matrix with a known inconsistent starting baseline.

## Whole-drive observations and coverage

| Whole-D: consumer | Normal observed median | Retained MFT observed median |
| --- | ---: | ---: |
| C# metadata scan | 183.83 s | 4.30 s |
| C# folder totals | 156.64 s | 3.53 s |
| PowerShell count-only output | 562.76 s | 17.74 s |

These are **unranked observations with different coverage**. Every normal whole-drive traversal reported twenty access errors. The MFT query completed its reachable captured graph without a fatal error; that is not proof that every current filesystem path is represented. The retained snapshot predates the individual timed queries, and other applications changed D: throughout the run.

| Whole-drive lane | First pass | Second pass | Reported errors |
| --- | --- | --- | ---: |
| CSharpScan, Normal | 3,901,514 files / 649,946 directories | 3,917,886 files / 653,216 directories | 20 / 20 |
| CSharpScan, CachedMft | 3,893,436 files / 647,527 directories | 3,893,436 files / 647,527 directories | 0 / 0 |
| FolderTotals, Normal | 3,912,099 files / 652,683 directories | 3,922,079 files / 653,341 directories | 20 / 20 |
| FolderTotals, CachedMft | 3,893,436 files / 647,527 directories | 3,893,436 files / 647,527 directories | 0 / 0 |
| PowerShellOutput, Normal | 5,087,982 entries | 5,097,251 entries | 20 / 20 |
| PowerShellOutput, CachedMft | 4,540,963 entries | 4,540,963 entries | 0 / 0 |

No matched whole-drive path or metadata inventory was produced. Neither zero incomplete decoded records nor faster traversal proves namespace equivalence, ACL equivalence or an atomic snapshot. Root identity checks, sequence-qualified links and a final extent-layout check protect specific invariants; they do not freeze file metadata or namespace activity.

## Why D: rejects raw volume reads

Read-only controls establish:

- Win32 ReadFile and native NtReadFile through both D: aliases fail with error 50 / STATUS_NOT_SUPPORTED (0xC00000BB), across ordinary, unbuffered and backup-intent opens.
- The same aligned raw read succeeds through C:.
- FSCTL_ALLOW_EXTENDED_DASD_IO succeeds on the D: handle, but its subsequent raw read still fails.
- A raw read from D:'s verified partition on PhysicalDrive1 succeeds. D: is a single extent on partition 3 of the NVMe disk, beginning at byte 122,683,392.

The bulk implementation uses that physical route only after the unsupported volume-read result. It validates the single extent, physical-disk length and partition bounds, then checks NTFS boot signature, serial, sector/cluster geometry and MFT location against the opened volume. All handles are read-only; no volume lock, dismount, write, virtual disk or filter configuration change is used.

D: has wcifs, PrjFlt and FileCrypt instances absent from C:. Bounded static inspection of immutable Microsoft driver copies found a concrete **wcifs raw-volume rejection path**:

- FLT_REGISTRATION points to an operation table registering MajorFunction 3 (IRP_MJ_READ) with pre-read callback 0x1400016e0.
- The callback checks FILE_OBJECT flag 0x400000 (FO_VOLUME_OPEN), UserMode request origin, a global guard byte and an instance/silo predicate.
- The guarded branch writes STATUS_NOT_SUPPORTED, zeroes Information and returns FLT_PREOP_COMPLETE. Both pseudocode and instructions show that behavior.
- The predicate returns true when an instance-context field is nonzero or the file object's silo is not the host silo.

This is a strong explanation consistent with the live D:/C:/physical-route controls. **Live predicate values and the actual rejected request stack were not observed**, so wcifs causality remains an inference. No filter was detached, no kernel debugger attached and no security policy changed. FileCrypt's sole literal status match inspected belonged to destination-name processing; PrjFlt was not imported after the wcifs path supplied a useful discriminating result.

Analysis identity: REA 6.5.0 stock package, Ghidra 12.1.4, JDK 21.0.12.1; driver version 10.0.26100.9711. wcifs SHA-256 C87F098524FD6FE5718B010CA77C7FCC8726A48965646318CCE595169930B66B. PDB load state was unknown; original function names and types were unavailable. Complete bounded evidence is retained in the machine-local raw-read-filter-analysis.json; the owned native session was closed.

## Compatibility, safeguards and review

**37 tests pass in each runtime**, PowerShell 7.6.6 and Windows PowerShell 5.1, Pester 5.7.1. Both target builds have zero warnings/errors. New contracts cover raw USA fixups and torn-record rejection, unused slots, signed fragmented runlists and malformed mappings, fixed 512-byte protection strides on synthetic 4KiB-sector geometry, logical folder totals, optional error continuation and inventory summary error counts. No physical 4Kn volume was qualified.

Reviewed-candidate live checks in both hosts match all **34 fixture paths** and exercised file attributes/times/lengths, including thirty hardlink aliases whose source lies outside the query. One directory last-access discrepancy repeats across six directory-bearing cases. Four live guards pass: record budget, estimated-index budget, cancellation during capture and deferred query cancellation. These prove observed rejection/cancellation behavior, not a hard heap bound or cancellation latency.

A fresh independent bulk-reader review and one targeted confirmation completed. Findings were fixed before the measured full candidate: 512-byte update-sequence protection independent of device I/O alignment, capture deadlines through bootstrap/final verification, handled errors included in InventorySummary and final-read counters. The two relevant regression tests failed on the preceding candidate and pass on the corrected source.

Auto keeps normal enumeration. Forced MFT is experimental, privileged and snapshot-based. Native Filter other than '*' falls back in Auto and is rejected in forced MFT mode. Native object conversion can perform live metadata I/O. Registry/Certificate providers, wildcard Path, Include/Exclude, file roots, streams, ordering and complete provider error behavior remain outside this filesystem prototype's supported contract.

## Retained earlier results and failures

The individual-record matrix on 2026-10-11 used source dfeedd203af544370a1c5c8c1a66c3897394021a, affinity 1 and a PowerShell consumer that fingerprinted every entry. Capture took 256.16 seconds, allocated 1.91 GB and retained about 1.42 GiB managed heap after collection. Those memory figures belong to that candidate, not this bulk measurement.

On its synthetic workloads, Get-ChildItem versus cached direct-MFT medians were 24.81 versus 36.99 seconds for 500,000 files and 2.54 versus 1.09 seconds for 50,000 files. Its whole-drive normal and MFT prototype samples aborted and remain excluded. Supported identity-checked Windows link-count validation subsequently fixed a false hardlink rejection; the current bulk experiment retains it. Different affinity, live volume contents and consumers prevent a controlled cross-run speedup claim.

Earlier USN-plus-hydration evidence also remains: Get-ChildItem 119.58 / 14.18 ms were different 10,110/1,010-entry trees, not competing engines. Reused USN-plus-hydration 129.08 / 15.41 ms did not win and missed a hardlink alias.

Preserved failures include initial raw-fixup rejection of logical API records with stale USA entries; absent extension-base identity during live capture; an invocation-scope failure; detected source changes; legacy wrapper byte-limit parsing and canceled elevation; and initial bulk smoke count-type/metadata-baseline validation failures. Logical API records and raw records now have separate validation routes. Later successes do not erase those failures. Earlier exact tables and diagnostics remain in Git history and the compact task evidence.

## Disposition

The requested bulk implementation and separate consumer comparison are local prototypes. C# aggregation is the useful disk-inventory direction: it avoids paying PowerShell delivery costs for millions of entries. Ordinary enumeration remains cheaper for a one-off small subtree when a full-volume capture would be required first.

Before production integration, qualify whole-drive namespace/access semantics, directory timestamp behavior, freshness and concurrent replacement, reparse and case-sensitive paths, measured peak memory and cancellation latency, and representative cold/warm workloads. Define unique-file versus logical-path versus allocated-space totals before using this as a disk-space accounting engine. No published library, module, package, service or database was changed.

Platform references: [multi-sector header](https://learn.microsoft.com/en-us/windows/win32/devnotes/multi-sector-header), [volume extents](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-ioctl_volume_get_volume_disk_extents), [extended DASD access](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_allow_extended_dasd_io), [FILE_OBJECT](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_file_object), [filter callback data](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/ns-fltkernel-_flt_callback_data).
