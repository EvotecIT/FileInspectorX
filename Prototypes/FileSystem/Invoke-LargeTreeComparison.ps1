param([Parameter(Mandatory)] [string] $ModulePath, [Parameter(Mandatory)] [string] $FixtureRoot,
    [Parameter(Mandatory)] [string] $OutputRoot, [Parameter(Mandatory)] [string] $VolumeRoot,
    [Parameter(Mandatory)] [string] $CompatibilityRoot, [switch] $SkipVolume, [switch] $Plan)
$ErrorActionPreference = 'Stop'
Import-Module PSPublishModule -MinimumVersion 3.0.153
$process = [Diagnostics.Process]::GetCurrentProcess()
$oldAffinity = $process.ProcessorAffinity
try {
    $process.ProcessorAffinity = [IntPtr]1
    $result = Invoke-BenchmarkSuite -Path (Join-Path $PSScriptRoot 'large-tree.benchmark.ps1') -OutputRoot $OutputRoot -Variable @{
        ModulePath = $ModulePath; FixtureRoot = $FixtureRoot; VolumeRoot = $VolumeRoot; IncludeVolume = -not [bool]$SkipVolume
        EvidencePath = (Join-Path $OutputRoot 'inventory-checkpoints.jsonl')
        CompatibilityRoot = $CompatibilityRoot
    } -Plan:$Plan
    $result
    if (-not $Plan -and @($result.Samples | Where-Object Status -eq 'Failed').Count) { throw 'Large-tree comparison has validation failures; retain evidence.' }
} finally { $process.ProcessorAffinity = $oldAffinity }
