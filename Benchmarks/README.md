# Detection benchmarks

The suite compares complete-input array, span and seekable-stream detection for padded JSON, full SHA-256 hashing and an OOXML ZIP. PowerForge owns timing, warmups, rotated order, validation, comparison tables and JSON/CSV output. Each sample proves the expected type, completed call count and hash; allocation totals cover the detection batch.

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

On machines with multiple cache or processor domains, record topology and run the entire matrix on each fixed domain with the same priority and placement for both lanes. Keep outliers and compare rotated samples. The suite records assembly hashes and Windows process affinity/priority; compare `metadata.json`, `samples.json`, `summary.json` and `comparison.md` before making a throughput claim. Benchmarks are opt-in and do not run in correctness CI.
