param([Parameter(Mandatory)] [string] $RequestFile, [switch] $TimingsOnly)
# Reviewable entrypoint for one explicitly approved elevated read-only volume comparison.
# It never writes a raw volume or changes services, caches, configuration, repositories or databases.
$ErrorActionPreference = 'Stop'
$request = Get-Content -LiteralPath $RequestFile -Raw | ConvertFrom-Json
$scratch = $env:EVOTEC_SCRATCH_ROOT
if (-not $scratch -or -not (Test-Path -LiteralPath $scratch -PathType Container)) { throw 'Configured scratch volume must already be mounted.' }
$scratchPrefix = [IO.Path]::GetFullPath($scratch).TrimEnd('\') + '\'
foreach ($path in @($RequestFile, $request.FixtureRoot, $request.CompatibilityRoot, $request.OutputRoot, $request.ModulePath)) {
    if (-not [IO.Path]::IsPathRooted($path) -or -not [IO.Path]::GetFullPath($path).StartsWith($scratchPrefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'All inputs and outputs must be inside the mounted configured scratch root.' }
    for ($ancestor = $path; $ancestor; $ancestor = Split-Path $ancestor -Parent) {
        if ((Test-Path -LiteralPath $ancestor) -and ((Get-Item -LiteralPath $ancestor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Reparse paths are not accepted by the elevated driver.' }
    }
}
if (Test-Path -LiteralPath $request.OutputRoot) { throw 'Choose a new task-owned comparison output directory.' }
$null = New-Item -ItemType Directory -Path $request.OutputRoot
$env:TEMP = Join-Path (Split-Path $RequestFile -Parent) 'temp'
$env:TMP = $env:TEMP
Start-Transcript -LiteralPath (Join-Path $request.OutputRoot 'driver.log') | Out-Null
try {
    if (-not $TimingsOnly) {
    # Fresh hosts exercise each supported runtime independently.
    & pwsh -NoProfile -File (Join-Path $PSScriptRoot 'Tests/Test-ElevatedAutoRouting.ps1') -ModulePath $request.ModulePath -Root $request.FixtureRoot -OutputPath (Join-Path $request.OutputRoot 'net8-auto.json') -MaximumMftBytes $request.MaximumMftBytes
    if ($LASTEXITCODE) { throw 'Modern-host automatic routing proof failed.' }
    $modern = Get-Content -LiteralPath (Join-Path $request.OutputRoot 'net8-auto.json') -Raw | ConvertFrom-Json
    # Auto deliberately walks until the experimental name index has complete path semantics.
        & pwsh -NoProfile -File (Join-Path $PSScriptRoot 'Tests/Measure-MftCompatibility.ps1') -ModulePath $request.ModulePath -FixtureRoot $request.CompatibilityRoot -OutputPath (Join-Path $request.OutputRoot 'compatibility-net8.json') -MaximumMftBytes $request.MaximumMftBytes
    if ($LASTEXITCODE) { throw 'Modern Windows MFT compatibility diagnostic failed.' }
    $legacyModule = $request.ModulePath.Replace('debug_net8.0', 'debug_net472')
    & powershell.exe -NoProfile -File (Join-Path $PSScriptRoot 'Tests/Measure-MftCompatibility.ps1') -ModulePath $legacyModule -FixtureRoot $request.CompatibilityRoot -OutputPath (Join-Path $request.OutputRoot 'compatibility-net472.json') -MaximumMftBytes $request.MaximumMftBytes
    if ($LASTEXITCODE) { throw 'Legacy Windows MFT compatibility diagnostic failed.' }
    }
    & (Join-Path $PSScriptRoot 'Invoke-PrototypeComparison.ps1') -ModulePath $request.ModulePath -FixtureRoot $request.FixtureRoot -OutputRoot (Join-Path $request.OutputRoot 'timings') -RunMft -MaximumMftBytes $request.MaximumMftBytes
    'Completed' | Set-Content -LiteralPath (Join-Path $request.OutputRoot 'status.txt')
} catch {
    $_.Exception.ToString() | Set-Content -LiteralPath (Join-Path $request.OutputRoot 'failure.txt')
    'Failed' | Set-Content -LiteralPath (Join-Path $request.OutputRoot 'status.txt')
    throw
} finally { Stop-Transcript | Out-Null }
