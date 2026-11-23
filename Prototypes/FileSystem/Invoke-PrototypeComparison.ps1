param(
    [Parameter(Mandatory)] [string] $ModulePath,
    [Parameter(Mandatory)] [string] $FixtureRoot,
    [Parameter(Mandatory)] [string] $OutputRoot,
    [switch] $RunMft,
    [ValidateRange(1, [long]::MaxValue)] [long] $MaximumMftBytes = 536870912,
    [switch] $Plan
)
$ErrorActionPreference = 'Stop'
Import-Module PSPublishModule -MinimumVersion 3.0.155 -ErrorAction Stop
$process = [Diagnostics.Process]::GetCurrentProcess()
$oldAffinity = $process.ProcessorAffinity
try {
    # One logical CPU is a reproducible domain, not a claim about optimal multi-core throughput.
    try { $process.ProcessorAffinity = [IntPtr]1 }
    catch { Write-Warning "Could not pin the comparison to processor zero; retaining the permitted affinity: $($_.Exception.Message)" }
    $result = Invoke-BenchmarkSuite -Path (Join-Path $PSScriptRoot 'filesystem.benchmark.ps1') -OutputRoot $OutputRoot -Variable @{
        ModulePath = $ModulePath; FixtureRoot = $FixtureRoot; RunMft = [bool]$RunMft; MaximumMftBytes = $MaximumMftBytes; Planning = [bool]$Plan
    } -Plan:$Plan -ErrorAction Stop
    $result
    if (-not $Plan -and @($result.Samples | Where-Object Status -eq 'Failed').Count) { throw 'Prototype comparison has failed lanes; retain the validation failures.' }
} finally {
    try { $process.ProcessorAffinity = $oldAffinity }
    catch { Write-Warning "Could not restore the original processor affinity: $($_.Exception.Message)" }
}
