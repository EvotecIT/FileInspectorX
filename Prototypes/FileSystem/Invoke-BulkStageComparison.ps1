param(
    [Parameter(Mandatory)][string]$ModulePath,
    [Parameter(Mandatory)][string]$FixtureRoot,
    [Parameter(Mandatory)][string]$VolumeRoot,
    [Parameter(Mandatory)][string]$OutputRoot,
    [switch]$SkipVolume,
    [switch]$SkipAcquisition,
    [switch]$Plan
)
$ErrorActionPreference='Stop'
Import-Module PSPublishModule -MinimumVersion 3.0.168
if (-not $Plan) {
    if (Test-Path -LiteralPath $OutputRoot) {throw 'Choose a fresh result directory; preserve prior evidence.'}
    $null=New-Item -ItemType Directory -Path $OutputRoot
}
$variables=@{
    ModulePath=$ModulePath;FixtureRoot=$FixtureRoot;VolumeRoot=$VolumeRoot
    EvidencePath=(Join-Path $OutputRoot 'checkpoints.jsonl');IncludeVolume=-not [bool]$SkipVolume;IncludeAcquisition=-not [bool]$SkipAcquisition;Planning=[bool]$Plan
}
$result=Invoke-BenchmarkSuite -Path (Join-Path $PSScriptRoot 'bulk-stages.benchmark.ps1') -OutputRoot $OutputRoot -Variable $variables -Plan:$Plan
$result
if (-not $Plan -and @($result.Samples | Where-Object Status -eq 'Failed').Count) { throw 'Comparison has failed samples; preserve their scope and errors.' }
