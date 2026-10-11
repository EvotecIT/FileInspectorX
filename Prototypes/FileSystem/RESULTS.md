# Prototype comparison evidence

Date: 2026-10-11. These are exploratory local results, not a published FileInspectorX performance guarantee.

## Environment and proof

Windows build 26300, AMD Ryzen 9 9950X3D2, PowerShell 7.6.6. The complete matrix uses logical CPU 0, normal process priority, rotated engine order, one warmup and three measured iterations. Filesystem caches are warm. Fixtures reside on local NTFS D: and contain synthetic eight-byte files; no production files are benchmarks. Native `Get-ChildItem` and prototype commands receive equivalent literal paths, recursion and `-Force` options.

Both .NET 8 and .NET Framework 4.7.2 builds pass without warnings. Nineteen focused normal-enumeration/routing contracts pass in each of Windows PowerShell 5.1 and PowerShell 7.6.6. The tests include real non-elevated MFT denial and fallback, native wildcard semantics, metadata, depth, literal brackets, Unicode names and cancellation.

## Ordinary enumeration

PowerForge run `20261011-133957-53425428`. All active lanes passed path, length, attribute and last-write metadata validation. Raw-MFT lanes are explicitly skipped in this non-elevated matrix.

| Workload | Items | Get-ChildItem median | Walk metadata median | Walk native objects median | Auto after denied MFT access median |
|---|---:|---:|---:|---:|---:|
| Entire synthetic tree | 10,110 | 465.01 ms | 237.57 ms | 405.49 ms | 301.03 ms |
| One top-level subtree | 1,010 | 56.48 ms | 11.39 ms | 20.53 ms | 19.22 ms |

The metadata lane is faster on these inputs, but allocates more: about 64.0 MB for the full tree versus 48.9 MB for native enumeration, using the operation's process-allocation metric. Native-object conversion adds work and narrows the speed advantage. Timing alone does not establish a better choice for every caller.

Mean time to first result on the full tree is 15.15 ms for Walk versus 29.10 ms for native enumeration; on the subtree it is 1.89 versus 8.33 ms. These are means across the measured samples, distinct from the median completion times above.

A superseded initial run found a real native-output mismatch: newly constructed `DirectoryInfo` objects lacked the provider's `PSIsContainer` decoration. The adapter now supplies that property, a contract assertion covers it, and the successful matrix above includes the corrected lane. Failed measurements are retained as diagnostic evidence rather than counted as successful comparisons.

## Raw MFT qualification

The initial elevated preflight reports D:'s MFT metadata length as **3,801,088,000 bytes** (3.54 GiB). It correctly rejects the default 512 MiB input budget before scanning the table. The approved read-only comparison is retried with an explicit 4 GiB metadata-input budget. This is not a hard total-memory limit.

The released reader's modern and legacy raw I/O paths both fail before MFT parsing. A separate source build corrects its native access flag to `GENERIC_READ`, labelled `0.1.0-mft-prototype.1`; both patched paths still fail at acquisition on D:. The modern host reports `ERROR_NOT_SUPPORTED`, and automatic routing falls back successfully with all 10,110 synthetic paths preserved. The older reader path loses the native error code and reports a generic volume-read failure.

A direct Windows probe independently opens D: with `GENERIC_READ` through both its drive-letter and volume-GUID names, with share modes 3 and 7. For 512-byte and 4,096-byte reads, 64-KiB-aligned buffers consistently return Win32 error 50; deliberately unaligned buffers return error 87. This narrows the failure to the environment's raw-volume acquisition path. It does not prove the responsible storage filter or OS component. No storage/security settings were changed.

No successful live-D: MFT timing or hard-link/timestamp compatibility result is available. A completed MFT scan, a fast query and complete native compatibility are separate claims. A prepared disposable virtual-volume test may provide controlled MFT evidence after separate approval; it cannot prove throughput on D:'s 3.54 GiB MFT.

## Reproducibility and retention

The committed PowerForge spec, fixture generator, dual-runtime test runner and elevated entrypoint reproduce the workloads. Machine-local full reports live under the task scratch root recorded in its `storage-manifest.json`. Keep the final compact result and necessary diagnostic failures; remove synthetic fixtures and superseded build output after validation. The task plan artifact is a copy of `PLAN.md`; the repository file is the maintained source.
