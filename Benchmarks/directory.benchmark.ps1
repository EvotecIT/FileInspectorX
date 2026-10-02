$baselineRoot = Get-BenchmarkInput BaselineRoot
$candidateRoot = Get-BenchmarkInput CandidateRoot
$fixtureRoot = Get-BenchmarkInput FixtureRoot -Required
$contextPrefix = Get-BenchmarkInput ContextPrefix 'FileInspectorX-directory'
$hash = (Get-FileHash (Join-Path $baselineRoot 'FileInspectorX.BenchmarkWorkloads.dll')).Hash
if ($hash -ne (Get-FileHash (Join-Path $candidateRoot 'FileInspectorX.BenchmarkWorkloads.dll')).Hash) { throw 'Use identical workload binaries.' }
$types = @{}
foreach ($lane in @('Baseline', 'Candidate')) {
    $root = if ($lane -eq 'Baseline') { $baselineRoot } else { $candidateRoot }
    $context = [Runtime.Loader.AssemblyLoadContext]::new("$contextPrefix-$lane", $true)
    $null = $context.LoadFromAssemblyPath((Join-Path $root 'FileInspectorX.dll'))
    $assembly = $context.LoadFromAssemblyPath((Join-Path $root 'FileInspectorX.BenchmarkWorkloads.dll'))
    $types[$lane] = $assembly.GetType('FileInspectorX.Benchmarks.DirectoryWorkload', $true)
}
$expected = @(Get-ChildItem -LiteralPath $fixtureRoot -File).Count
New-BenchmarkSuite 'fileinspectorx-directory' {
    Add-BenchmarkMetadata WorkloadSha256 $hash
    Add-BenchmarkMetadata BaselineSha256 (Get-FileHash (Join-Path $baselineRoot 'FileInspectorX.dll')).Hash
    Add-BenchmarkMetadata CandidateSha256 (Get-FileHash (Join-Path $candidateRoot 'FileInspectorX.dll')).Hash
    Add-BenchmarkMetadata AllocationScope 'Process; includes async workers'
    Set-BenchmarkPolicy -Warmup 3 -Iteration 9 -Order Rotated -OutlierMode None
    Add-BenchmarkCaseSource @(
        [pscustomobject]@{ Name = 'Sequential'; Mode = 'Sequential' }
        [pscustomobject]@{ Name = 'AsyncSequential'; Mode = 'AsyncSequential' }
        [pscustomobject]@{ Name = 'Parallel4'; Mode = 'Parallel4' }
    )
    Set-BenchmarkSetup {
        param($case, $run)
        $run.Workload = [Activator]::CreateInstance($types[$case.Engine], [object[]]@([string]$fixtureRoot, [string]$case.Mode))
    }
    foreach ($lane in @('Baseline', 'Candidate')) {
        Add-BenchmarkEngine $lane { Add-BenchmarkOperation Scan { param($case, $run) $run.Result = $run.Workload.Run() } }
    }
    Add-BenchmarkValidation {
        param($case, $run)
        Assert-BenchmarkValue -Actual $run.Result.Calls -Expected $expected
        Assert-BenchmarkValue -Actual $run.Result.Matches -Expected $expected
        Assert-BenchmarkValue -Actual $run.Result.HashMatches -Expected $true
    }
    Add-BenchmarkMetric ProcessAllocatedBytes { param($case, $run) $run.Result.AllocatedBytes }
    Add-BenchmarkMetric ReadOperations { param($case, $run) $run.Result.ReadOperations }
    Add-BenchmarkComparison -Dimension Engine -Baseline Baseline -Metric MedianMs -TieTolerance 0.05
}
