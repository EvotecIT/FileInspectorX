param(
    [Parameter(Mandatory)] [string] $ModulePath,
    [Parameter(Mandatory)] [string] $FixtureRoot,
    [Parameter(Mandatory)] [string] $OutputRoot,
    [switch] $RunMft,
    [ValidateRange(1, [long]::MaxValue)] [long] $MaximumMftBytes = 536870912,
    [switch] $Plan
)
$ErrorActionPreference = 'Stop'
Import-Module PSPublishModule -MinimumVersion 3.0.153 -ErrorAction Stop
$process = [Diagnostics.Process]::GetCurrentProcess()
$oldAffinity = $process.ProcessorAffinity
try {
    # One logical CPU is a reproducible domain, not a claim about optimal multi-core throughput.
    $process.ProcessorAffinity = [IntPtr]1
    $result = Invoke-BenchmarkSuite -Path (Join-Path $PSScriptRoot 'filesystem.benchmark.ps1') -OutputRoot $OutputRoot -Variable @{
        ModulePath = $ModulePath; FixtureRoot = $FixtureRoot; RunMft = [bool]$RunMft; MaximumMftBytes = $MaximumMftBytes; Planning = [bool]$Plan
    } -Plan:$Plan -ErrorAction Stop
    $result
    if (-not $Plan -and @($result.Samples | Where-Object Status -eq 'Failed').Count) { throw 'Prototype comparison has failed lanes; retain the validation failures.' }
} finally { $process.ProcessorAffinity = $oldAffinity }
