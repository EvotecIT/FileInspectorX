param([Parameter(Mandatory)] [string] $ModulePath, [Parameter(Mandatory)] [string] $FixtureRoot,
    [Parameter(Mandatory)] [string] $OutputRoot, [Parameter(Mandatory)] [string] $VolumeRoot,
    [Parameter(Mandatory)] [string] $CompatibilityRoot, [switch] $SkipVolume, [switch] $NormalOnly, [switch] $Plan,
    [ValidateRange(1, [long]::MaxValue)] [long] $MaximumMftBytes = 536870912)
$ErrorActionPreference = 'Stop'
Import-Module PSPublishModule -MinimumVersion 3.0.155
$process = [Diagnostics.Process]::GetCurrentProcess()
$oldAffinity = $process.ProcessorAffinity
if (-not $Plan -and (Test-Path -LiteralPath $OutputRoot)) { throw 'Choose a fresh result directory; preserve prior evidence.' }
if (-not $NormalOnly) {
    foreach ($queryRoot in @($FixtureRoot, $CompatibilityRoot)) {
        if ([IO.Path]::GetPathRoot([IO.Path]::GetFullPath($queryRoot)) -ne [IO.Path]::GetPathRoot([IO.Path]::GetFullPath($VolumeRoot))) {
            throw 'FixtureRoot and CompatibilityRoot must be on the snapshot volume.'
        }
    }
}
try {
    try { $process.ProcessorAffinity = [IntPtr]1 }
    catch { Write-Warning "Could not pin the comparison to processor zero; retaining the permitted affinity: $($_.Exception.Message)" }
    if (-not $Plan) { $null = New-Item -ItemType Directory -Path $OutputRoot }
    $result = Invoke-BenchmarkSuite -Path (Join-Path $PSScriptRoot 'large-tree.benchmark.ps1') -OutputRoot $OutputRoot -Variable @{
        ModulePath = $ModulePath; FixtureRoot = $FixtureRoot; VolumeRoot = $VolumeRoot; IncludeVolume = -not [bool]$SkipVolume
        EvidencePath = (Join-Path $OutputRoot 'inventory-checkpoints.jsonl')
        CompatibilityRoot = $CompatibilityRoot
        Planning = [bool]$Plan; RunMft = -not [bool]$NormalOnly; MaximumMftBytes = $MaximumMftBytes
    } -Plan:$Plan
    $result
    if (-not $Plan -and @($result.Samples | Where-Object Status -eq 'Failed').Count) { throw 'Large-tree comparison has validation failures; retain evidence.' }
} finally {
    try { $process.ProcessorAffinity = $oldAffinity }
    catch { Write-Warning "Could not restore the original processor affinity: $($_.Exception.Message)" }
}
