# Detection benchmarks

The suites compare complete-input detection and full analysis, filesystem scans, and optional Magika inference. PowerForge owns timing, warmups, rotated order, validation, comparison tables and JSON/CSV output. Detection covers padded JSON, 1/16MiB hashing and a 2050-entry OOXML archive; each sample verifies type, completed call count, full hashes and requested metrics.

Use PowerShell 7 and PSPublishModule 3.0.153 or newer. Build the workload against the baseline before changing core source, then keep that output directory:

```powershell
dotnet build ./Benchmarks/Workloads/FileInspectorX.BenchmarkWorkloads.csproj -c Release -o ./artifacts/benchmarks/baseline
```

After changing core source, build the candidate in a separate directory:

```powershell
dotnet build ./Benchmarks/Workloads/FileInspectorX.BenchmarkWorkloads.csproj -c Release -o ./artifacts/benchmarks/candidate
Copy-Item ./artifacts/benchmarks/baseline/FileInspectorX.BenchmarkWorkloads.dll ./artifacts/benchmarks/candidate/FileInspectorX.BenchmarkWorkloads.dll
./Benchmarks/Invoke-DetectionBenchmark.ps1 -BaselineRoot ./artifacts/benchmarks/baseline -CandidateRoot ./artifacts/benchmarks/candidate -OutputRoot ./artifacts/benchmarks/results -Plan
./Benchmarks/Invoke-DetectionBenchmark.ps1 -BaselineRoot ./artifacts/benchmarks/baseline -CandidateRoot ./artifacts/benchmarks/candidate -OutputRoot ./artifacts/benchmarks/results -Calls 500
```

If the workload changes after preserving core, rebuild it against the preserved assembly without rebuilding that core:

```powershell
$baselineAssembly = (Resolve-Path ./artifacts/benchmarks/baseline/FileInspectorX.dll).Path
dotnet build ./Benchmarks/Workloads/FileInspectorX.BenchmarkWorkloads.csproj -c Release -o ./artifacts/benchmarks/baseline "-p:FileInspectorXReferencePath=$baselineAssembly"
Copy-Item ./artifacts/benchmarks/baseline/FileInspectorX.BenchmarkWorkloads.dll ./artifacts/benchmarks/candidate/FileInspectorX.BenchmarkWorkloads.dll
```

Use the same workload assembly, inputs and options in both lanes. Hash generation and input setup happen before timing. The wrapper unloads its isolated assembly contexts and fails when a sample fails validation. Results remain in the chosen output directory for inspection; remove superseded output after retaining the evidence needed.

On machines with multiple cache or processor domains, record topology and run the entire matrix on each fixed domain with the same priority and placement for both lanes. Keep outliers and compare rotated samples. The suite records assembly hashes and initial Windows placement; PowerForge's configured placement records actual applied values for the complete run. Compare `metadata.json`, `samples.json`, `summary.json` and `comparison.md` before making a throughput claim. Benchmarks are opt-in and do not run in correctness CI.

## Directory scans

Supply an existing directory of JSON files to compare synchronous enumeration, asynchronous sequential enumeration and four-worker scans. Hash setup stays outside timing. Each sample verifies the complete hash multiset and file count, including duplicate-content inputs and reordered results. Allocation totals cover the process because workers allocate on other threads; use a dedicated host and retain background outliers.

```powershell
./Benchmarks/Invoke-DetectionBenchmark.ps1 -Suite directory -FixtureRoot ./fixtures/json `
    -BaselineRoot ./artifacts/benchmarks/baseline -CandidateRoot ./artifacts/benchmarks/candidate `
    -OutputRoot ./artifacts/benchmarks/directory-results
```

## Magika inference

Build `Benchmarks/MagikaWorkloads/FileInspectorX.Magika.BenchmarkWorkloads.csproj` and preserve baseline provider/core binaries before editing them. Use the same workload, dependency manifest, ONNX Runtime binaries and pinned reference corpus in both directories. The baseline measures scalar inference with runtime defaults; candidate lanes compare scalar and 32-row batching with default, one, two and four native threads.

```powershell
./Benchmarks/Invoke-MagikaBenchmark.ps1 -BaselineRoot ./artifacts/magika/baseline `
    -CandidateRoot ./artifacts/magika/candidate -OutputRoot ./artifacts/magika/results
```

Only one native session is active at a time, with initialization and corpus priming outside timing. Every measured sample reuses that session across the complete corpus, verifies all expected labels and probability ranges, then releases it before the next lane. The wrapper closes native sessions and unloads collectible dependency contexts. Batching can reduce managed allocations; elapsed time depends on native thread count, placement and workload. Configuring fewer threads can increase single-call latency.
