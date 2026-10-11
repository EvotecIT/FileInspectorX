param([Parameter(Mandatory)] [string] $ModulePath, [string] $OutputPath)
$ErrorActionPreference = 'Stop'
Import-Module Pester -RequiredVersion 5.7.1
$configuration = New-PesterConfiguration
$configuration.Run.Container = @(
    New-PesterContainer -Path (Join-Path $PSScriptRoot 'Tests/Compatibility.Tests.ps1') -Data @{ ModulePath = $ModulePath }
    New-PesterContainer -Path (Join-Path $PSScriptRoot 'Tests/FileRecordParser.Tests.ps1') -Data @{ ModulePath = $ModulePath }
)
$configuration.Run.PassThru = $true
$configuration.Output.Verbosity = 'Detailed'
if ($OutputPath) {
    $configuration.TestResult.Enabled = $true
    $configuration.TestResult.OutputPath = $OutputPath
}
$result = Invoke-Pester -Configuration $configuration
$result | Select-Object PassedCount, FailedCount, SkippedCount, FailedContainersCount
if ($result.FailedCount -or $result.FailedContainersCount) { throw 'Prototype contract tests failed.' }
