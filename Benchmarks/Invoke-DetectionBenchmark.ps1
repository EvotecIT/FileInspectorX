param(
    [Parameter(Mandatory)] [string] $BaselineRoot,
    [Parameter(Mandatory)] [string] $CandidateRoot,
    [Parameter(Mandatory)] [string] $OutputRoot,
    [ValidateRange(1, 100000)] [int] $Calls = 200,
    [string[]] $Case,
    [ValidateSet('detection', 'directory')] [string] $Suite = 'detection',
    [string] $FixtureRoot,
    [switch] $Plan
)

Import-Module PSPublishModule -MinimumVersion 3.0.153 -ErrorAction Stop
$contextPrefix = 'FileInspectorX-' + [guid]::NewGuid().ToString('N')
try {
    $result = Invoke-BenchmarkSuite -Path (Join-Path $PSScriptRoot "$Suite.benchmark.ps1") -OutputRoot $OutputRoot -Variable @{
        BaselineRoot = $BaselineRoot; CandidateRoot = $CandidateRoot; Calls = $Calls; ContextPrefix = $contextPrefix; FixtureRoot = $FixtureRoot
    } -Case $Case -Plan:$Plan -ErrorAction Stop
} finally {
    foreach ($context in [Runtime.Loader.AssemblyLoadContext]::All) {
        if ($context.Name -and $context.Name.StartsWith($contextPrefix + '-', [StringComparison]::Ordinal)) { $context.Unload() }
    }
}
$result
if (-not $Plan -and @($result.Samples | Where-Object { $_.Status -eq 'Failed' }).Count -gt 0) {
    throw 'Detection benchmark validation failed. Inspect the PowerForge samples and run report.'
}
