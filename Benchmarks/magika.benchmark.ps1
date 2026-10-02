$baselineRoot = Get-BenchmarkInput BaselineRoot
$candidateRoot = Get-BenchmarkInput CandidateRoot
$corpus = Get-BenchmarkInput CorpusPath
$calls = Get-BenchmarkInput Calls 3 -Int
if ($calls -lt 1) { throw 'Calls must be positive so each sample measures inference.' }
$contextPrefix = Get-BenchmarkInput ContextPrefix 'FileInspectorX-Magika'
$workloadName = 'FileInspectorX.Magika.BenchmarkWorkloads.dll'
$hash = (Get-FileHash (Join-Path $baselineRoot $workloadName)).Hash
if ($hash -ne (Get-FileHash (Join-Path $candidateRoot $workloadName)).Hash) { throw 'Use identical workload binaries.' }
$contextType = [Reflection.Assembly]::LoadFrom((Join-Path $candidateRoot $workloadName)).GetType('FileInspectorX.Benchmarks.ProviderBenchmarkContext', $true)
$contexts = @{}
foreach ($lane in @('Baseline', 'Candidate')) {
    $root = if ($lane -eq 'Baseline') { $baselineRoot } else { $candidateRoot }
    $context = [Activator]::CreateInstance($contextType, [object[]]@([string]$root, "$contextPrefix-$lane"))
    $contexts[$lane] = $context
}
$lanes = [ordered]@{
    Baseline = @('Baseline', 'Scalar', 0)
    CandidateDefault = @('Candidate', 'Scalar', 0)
    Scalar1 = @('Candidate', 'Scalar', 1)
    Scalar2 = @('Candidate', 'Scalar', 2)
    Scalar4 = @('Candidate', 'Scalar', 4)
    BatchDefault = @('Candidate', 'Batch', 0)
    Batch1 = @('Candidate', 'Batch', 1)
    Batch2 = @('Candidate', 'Batch', 2)
    Batch4 = @('Candidate', 'Batch', 4)
}
New-BenchmarkSuite 'fileinspectorx-magika' {
    Add-BenchmarkMetadata CorpusSha256 (Get-FileHash $corpus).Hash
    Add-BenchmarkMetadata WorkloadSha256 $hash
    Add-BenchmarkMetadata BaselineProviderSha256 (Get-FileHash (Join-Path $baselineRoot 'FileInspectorX.Magika.dll')).Hash
    Add-BenchmarkMetadata CandidateProviderSha256 (Get-FileHash (Join-Path $candidateRoot 'FileInspectorX.Magika.dll')).Hash
    Add-BenchmarkMetadata OnnxRuntimeSha256 (Get-FileHash (Join-Path $candidateRoot 'Microsoft.ML.OnnxRuntime.dll')).Hash
    Add-BenchmarkMetadata HostRuntime ([Runtime.InteropServices.RuntimeInformation]::FrameworkDescription)
    Set-BenchmarkPolicy -Warmup 3 -Iteration 9 -Order Rotated -OutlierMode None
    Add-BenchmarkCaseSource @([pscustomobject]@{ Name = 'PinnedCorpus'; Calls = $calls })
    Set-BenchmarkSetup {
        param($case, $run)
        foreach ($context in $contexts.Values) { $context.DisposeWorkloads() }
        $lane = $lanes[$case.Engine]
        $run.Workload = $contexts[$lane[0]].CreateWorkload([string]$corpus, [string]$lane[1], [int]$lane[2], [int]$case.Calls)
        # Prime this reusable session outside timing. Only one native worker pool
        # remains active, including during rotated before/after comparisons.
        $null = $run.Workload.Run()
    }
    foreach ($lane in $lanes.Keys) {
        Add-BenchmarkEngine $lane {
            Add-BenchmarkOperation Predict { param($case, $run) $run.Result = $run.Workload.Run() }
        }
    }
    Add-BenchmarkValidation {
        param($case, $run)
        Assert-BenchmarkValue -Actual $run.Result.Inputs -Expected (47 * $case.Calls)
        Assert-BenchmarkValue -Actual $run.Result.Matched -Expected $run.Result.Inputs
    }
    Add-BenchmarkMetric PredictedInputs { param($case, $run) $run.Result.Inputs }
    Add-BenchmarkMetric BatchAllocatedBytes { param($case, $run) $run.Result.AllocatedBytes }
    Add-BenchmarkComparison -Dimension Engine -Baseline Baseline -Metric MedianMs -TieTolerance 0.05
}
