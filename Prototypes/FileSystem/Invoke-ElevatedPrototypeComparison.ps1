param([Parameter(Mandatory)] [string] $RequestFile, [switch] $TimingsOnly, [switch] $LargeTree)
# Reviewable entrypoint for one explicitly approved elevated read-only volume comparison.
# It never writes a raw volume or changes services, caches, configuration, repositories or databases.
$ErrorActionPreference = 'Stop'
$scratch = $env:EVOTEC_SCRATCH_ROOT
if (-not $scratch -or -not (Test-Path -LiteralPath $scratch -PathType Container)) { throw 'Configured scratch volume must already be mounted.' }
$scratchPrefix = [IO.Path]::GetFullPath($scratch).TrimEnd('\') + '\'
. (Join-Path $PSScriptRoot 'Assert-PrototypeScratchPath.ps1')
. (Join-Path $PSScriptRoot 'Assert-PrototypeModulePayload.ps1')
$isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$isolation = @{ RequireElevatedIsolation = $isElevated }
Assert-PrototypeScratchPath -Path $RequestFile -ScratchPrefix $scratchPrefix @isolation
$request = Get-Content -LiteralPath $RequestFile -Raw | ConvertFrom-Json
$maximumMftBytes = if ($null -ne $request.MaximumMftBytes) { [long]$request.MaximumMftBytes } else { 536870912L }
if ($maximumMftBytes -le 0) { throw 'MaximumMftBytes must be positive.' }
foreach ($path in @($request.FixtureRoot, $request.CompatibilityRoot, $request.OutputRoot, $request.ModulePath)) {
    Assert-PrototypeScratchPath -Path $path -ScratchPrefix $scratchPrefix @isolation
}
$temporaryDirectory = Join-Path (Split-Path $RequestFile -Parent) 'temp'
Assert-PrototypeScratchPath -Path $temporaryDirectory -ScratchPrefix $scratchPrefix @isolation
$legacyModule = $null
if (-not $TimingsOnly) {
    $modernDirectory = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($request.ModulePath))
    $frameworkDirectory = [IO.Path]::GetFileName($modernDirectory)
    if ($frameworkDirectory -eq 'net8.0') { $legacyFrameworkDirectory = 'net472' }
    elseif ($frameworkDirectory -cmatch '_net8\.0$') { $legacyFrameworkDirectory = $frameworkDirectory -creplace '_net8\.0$', '_net472' }
    else { throw 'ModulePath must identify the net8.0 or *_net8.0 framework output directory.' }
    $legacyDirectory = Join-Path ([IO.Path]::GetDirectoryName($modernDirectory)) $legacyFrameworkDirectory
    $legacyModule = Join-Path $legacyDirectory ([IO.Path]::GetFileName($request.ModulePath))
    Assert-PrototypeScratchPath -Path $legacyModule -ScratchPrefix $scratchPrefix @isolation
}
if (Test-Path -LiteralPath $request.OutputRoot) { throw 'Choose a new task-owned comparison output directory.' }
if ($isElevated) {
    Assert-PrototypeModulePayload -ModulePath $request.ModulePath -ScratchPrefix $scratchPrefix
    if ($legacyModule) { Assert-PrototypeModulePayload -ModulePath $legacyModule -ScratchPrefix $scratchPrefix }
}
$null = New-Item -ItemType Directory -Path $request.OutputRoot
$previousTemp = $env:TEMP
$previousTmp = $env:TMP
$transcriptStarted = $false
try {
    $env:TEMP = $temporaryDirectory
    $env:TMP = $temporaryDirectory
    Start-Transcript -LiteralPath (Join-Path $request.OutputRoot 'driver.log') | Out-Null
    $transcriptStarted = $true
    if ($LargeTree) {
        $volumeRoot = [IO.Path]::GetPathRoot([IO.Path]::GetFullPath($request.FixtureRoot))
        if ($volumeRoot -ne [IO.Path]::GetPathRoot([IO.Path]::GetFullPath($scratch)) -or $volumeRoot -eq [IO.Path]::GetPathRoot($env:SystemRoot)) { throw 'Whole-drive comparison must use the configured scratch volume, distinct from the system volume.' }
        $timingError = $null
        try { & (Join-Path $PSScriptRoot 'Invoke-LargeTreeComparison.ps1') -ModulePath $request.ModulePath -FixtureRoot $request.FixtureRoot -CompatibilityRoot $request.CompatibilityRoot -VolumeRoot $volumeRoot -OutputRoot (Join-Path $request.OutputRoot 'timings') -MaximumMftBytes $maximumMftBytes }
        catch { $timingError = $_ }
        if (-not $TimingsOnly) {
            & powershell.exe -NoProfile -File (Join-Path $PSScriptRoot 'Tests/Measure-MftCompatibility.ps1') -ModulePath $legacyModule -FixtureRoot $request.CompatibilityRoot -OutputPath (Join-Path $request.OutputRoot 'compatibility-net472.json') -MaximumMftBytes $maximumMftBytes
            if ($LASTEXITCODE) { throw 'Legacy direct MFT compatibility diagnostic failed.' }
        }
        if ($timingError) { throw $timingError }
        'Completed' | Set-Content -LiteralPath (Join-Path $request.OutputRoot 'status.txt')
        return
    }
    if (-not $TimingsOnly) {
    # Fresh hosts exercise each supported runtime independently.
    & pwsh.exe -NoProfile -File (Join-Path $PSScriptRoot 'Tests/Test-ElevatedAutoRouting.ps1') -ModulePath $request.ModulePath -Root $request.FixtureRoot -OutputPath (Join-Path $request.OutputRoot 'net8-auto.json') -MaximumMftBytes $maximumMftBytes
    if ($LASTEXITCODE) { throw 'Modern-host automatic routing proof failed.' }
    $modern = Get-Content -LiteralPath (Join-Path $request.OutputRoot 'net8-auto.json') -Raw | ConvertFrom-Json
    # Auto deliberately walks until the experimental name index has complete path semantics.
        & pwsh.exe -NoProfile -File (Join-Path $PSScriptRoot 'Tests/Measure-MftCompatibility.ps1') -ModulePath $request.ModulePath -FixtureRoot $request.CompatibilityRoot -OutputPath (Join-Path $request.OutputRoot 'compatibility-net8.json') -MaximumMftBytes $maximumMftBytes
    if ($LASTEXITCODE) { throw 'Modern Windows MFT compatibility diagnostic failed.' }
    & powershell.exe -NoProfile -File (Join-Path $PSScriptRoot 'Tests/Measure-MftCompatibility.ps1') -ModulePath $legacyModule -FixtureRoot $request.CompatibilityRoot -OutputPath (Join-Path $request.OutputRoot 'compatibility-net472.json') -MaximumMftBytes $maximumMftBytes
    if ($LASTEXITCODE) { throw 'Legacy Windows MFT compatibility diagnostic failed.' }
    }
    & (Join-Path $PSScriptRoot 'Invoke-PrototypeComparison.ps1') -ModulePath $request.ModulePath -FixtureRoot $request.FixtureRoot -OutputRoot (Join-Path $request.OutputRoot 'timings') -RunMft -MaximumMftBytes $maximumMftBytes
    'Completed' | Set-Content -LiteralPath (Join-Path $request.OutputRoot 'status.txt')
} catch {
    $_.Exception.ToString() | Set-Content -LiteralPath (Join-Path $request.OutputRoot 'failure.txt')
    'Failed' | Set-Content -LiteralPath (Join-Path $request.OutputRoot 'status.txt')
    throw
} finally {
    try { if ($transcriptStarted) { Stop-Transcript | Out-Null } }
    finally { $env:TEMP = $previousTemp; $env:TMP = $previousTmp }
}
