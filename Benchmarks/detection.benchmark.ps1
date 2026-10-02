$baselineRoot = Get-BenchmarkInput BaselineRoot
$candidateRoot = Get-BenchmarkInput CandidateRoot
$calls = Get-BenchmarkInput Calls 200 -Int
$contextPrefix = Get-BenchmarkInput ContextPrefix 'FileInspectorX-benchmark'
$roots = [ordered]@{ Baseline = $baselineRoot; Candidate = $candidateRoot }
$contexts = @{}
$workloadTypes = @{}
$baselineWorkloadHash = (Get-FileHash (Join-Path $baselineRoot 'FileInspectorX.BenchmarkWorkloads.dll')).Hash
$candidateWorkloadHash = (Get-FileHash (Join-Path $candidateRoot 'FileInspectorX.BenchmarkWorkloads.dll')).Hash
if ($baselineWorkloadHash -ne $candidateWorkloadHash) { throw 'Use the same workload assembly in both lanes.' }
foreach ($lane in $roots.Keys) {
    if (-not $roots[$lane]) { throw "$lane requires a built workload directory." }
    $root = [IO.Path]::GetFullPath($roots[$lane])
    $context = [Runtime.Loader.AssemblyLoadContext]::new("$contextPrefix-$lane", $true)
    $null = $context.LoadFromAssemblyPath((Join-Path $root 'FileInspectorX.dll'))
    $assembly = $context.LoadFromAssemblyPath((Join-Path $root 'FileInspectorX.BenchmarkWorkloads.dll'))
    $contexts[$lane] = $context
    $workloadTypes[$lane] = $assembly.GetType('FileInspectorX.Benchmarks.DetectionWorkload', $true)
}

New-BenchmarkSuite 'fileinspectorx-detection' {
    Add-BenchmarkMetadata BaselineSha256 (Get-FileHash (Join-Path $baselineRoot 'FileInspectorX.dll')).Hash
    Add-BenchmarkMetadata CandidateSha256 (Get-FileHash (Join-Path $candidateRoot 'FileInspectorX.dll')).Hash
    Add-BenchmarkMetadata WorkloadSha256 $baselineWorkloadHash
    if ($IsWindows) {
        Add-BenchmarkMetadata ProcessAffinity ([Diagnostics.Process]::GetCurrentProcess().ProcessorAffinity.ToInt64())
        Add-BenchmarkMetadata ProcessPriority ([Diagnostics.Process]::GetCurrentProcess().PriorityClass)
    }
    Set-BenchmarkPolicy -Warmup 3 -Iteration 9 -Order Rotated -OutlierMode None
    Add-BenchmarkCaseSource @(
        [pscustomobject]@{ Name = 'Json4KiB'; Workload = 'Json4KiB'; Calls = $calls }
        [pscustomobject]@{ Name = 'Json1MiB'; Workload = 'Json1MiB'; Calls = $calls }
        [pscustomobject]@{ Name = 'Hash1MiB'; Workload = 'Hash1MiB'; Calls = [Math]::Max(1, [int]($calls / 20)) }
        [pscustomobject]@{ Name = 'ZipDocx'; Workload = 'ZipDocx'; Calls = $calls }
    )
    Add-BenchmarkAxis Shape Array, Span, Stream
    Set-BenchmarkSetup {
        param($case, $run)
        $run.Workload = [Activator]::CreateInstance($workloadTypes[$case.Engine], [object[]]@([string]$case.Workload, [string]$case.Shape, [int]$case.Calls))
    }
    foreach ($lane in $roots.Keys) {
        Add-BenchmarkEngine $lane {
            Add-BenchmarkOperation Detect {
                param($case, $run)
                $run.Result = $run.Workload.Run()
            }
        }
    }
    Add-BenchmarkValidation {
        param($case, $run)
        Assert-BenchmarkValue -Actual $run.Result.Calls -Expected $case.Calls
        Assert-BenchmarkValue -Actual $run.Result.Matches -Expected $case.Calls
        Assert-BenchmarkValue -Actual $run.Result.HashMatches -Expected $true
    }
    Add-BenchmarkMetric BatchAllocatedBytes { param($case, $run) $run.Result.AllocatedBytes }
    Add-BenchmarkMetric CompletedCalls { param($case, $run) $run.Result.Calls }
    Add-BenchmarkComparison -Dimension Engine -Baseline Baseline -Metric MedianMs -TieTolerance 0.05
}
