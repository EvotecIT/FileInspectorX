param(
    [Parameter(Mandatory)]
    [string] $ModulePath,

    [ValidateSet('Auto', 'Magika', 'DeterministicOnly')]
    [string] $ExpectedDefault = 'Auto',

    [switch] $ExpectBundledProvider
)

$ErrorActionPreference = 'Stop'
$resolvedModulePath = (Resolve-Path -LiteralPath $ModulePath).Path
$fixturePath = Join-Path ([IO.Path]::GetTempPath()) "FileInspectorX-Magika-$PID.json"

try {
    [IO.File]::WriteAllText($fixturePath, '{"name":"FileInspectorX","enabled":true}')
    Import-Module $resolvedModulePath -Force

    if ($ExpectedDefault -eq 'Auto') {
        $architecture = [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture
        $runningOnMacOS = [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
            [Runtime.InteropServices.OSPlatform]::OSX)
        $runningOnWindowsOrLinux =
            [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
                [Runtime.InteropServices.OSPlatform]::Windows) -or
            [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
                [Runtime.InteropServices.OSPlatform]::Linux)
        $isSupportedArchitecture =
            $architecture -eq [Runtime.InteropServices.Architecture]::Arm64 -or
            $architecture -eq [Runtime.InteropServices.Architecture]::X64
        $ExpectedDefault = if (($runningOnMacOS -and
                $architecture -eq [Runtime.InteropServices.Architecture]::Arm64) -or
            ($runningOnWindowsOrLinux -and $isSupportedArchitecture)) {
            'Magika'
        } else {
            'DeterministicOnly'
        }
    }

    $parameters = (Get-Command Get-FileInsight -ErrorAction Stop).Parameters
    if ($parameters.ContainsKey('UseMagika')) {
        throw 'The removed UseMagika parameter is still exported.'
    }
    if (-not $parameters.ContainsKey('DisableMagika')) {
        throw 'The DisableMagika opt-out is not exported.'
    }

    $warnings = @()
    $assisted = Get-FileInsight -Path $fixturePath -WarningVariable warnings

    if ($warnings.Count -ne 0) {
        throw "Default Magika analysis emitted a warning: $($warnings -join '; ')"
    }
    if ($assisted.DetectedExtension -ne 'json') {
        throw "Expected deterministic JSON detection, found '$($assisted.DetectedExtension)'."
    }

    if ($ExpectedDefault -eq 'Magika') {
        $prediction = $assisted.Detection.LearnedClassification.Prediction
        if ($prediction.Provider -ne 'Magika') {
            throw "Expected the default learned provider to be Magika, found '$($prediction.Provider)'."
        }
    } elseif ($null -ne $assisted.Detection.LearnedClassification) {
        throw 'Expected default deterministic-only analysis without learned evidence.'
    }

    if ($ExpectBundledProvider -or $ExpectedDefault -eq 'Magika') {
        $moduleDirectory = Split-Path -Parent $resolvedModulePath
        $noticeRoot = $moduleDirectory
        for ($depth = 0; $depth -lt 3; $depth++) {
            if (Test-Path -LiteralPath (Join-Path $noticeRoot 'THIRD-PARTY-NOTICES.md') -PathType Leaf) {
                break
            }
            $noticeRoot = Split-Path -Parent $noticeRoot
        }
        $requiredNotices = @(
            (Join-Path $noticeRoot 'THIRD-PARTY-NOTICES.md')
            (Join-Path $noticeRoot 'THIRD-PARTY-LICENSES/Magika-Apache-2.0.txt')
            (Join-Path $noticeRoot 'THIRD-PARTY-LICENSES/ONNX-Runtime-MIT.txt')
        )
        foreach ($notice in $requiredNotices) {
            if (-not (Test-Path -LiteralPath $notice -PathType Leaf)) {
                throw "Bundled Magika provider is missing third-party notice '$notice'."
            }
        }
    }

    $deterministicOnly = Get-FileInsight -Path $fixturePath -DisableMagika
    if ($null -ne $deterministicOnly.Detection.LearnedClassification) {
        throw 'DisableMagika did not disable learned classification.'
    }

    $requiredFailedClosed = $false
    try {
        Get-FileInsight -Path $fixturePath -DisableMagika -LearnedClassificationMode Required -ErrorAction Stop
    } catch {
        $requiredFailedClosed = $true
    }
    if (-not $requiredFailedClosed) {
        throw 'Required learned-classification mode silently fell back after Magika was disabled.'
    }
} finally {
    if (Test-Path -LiteralPath $fixturePath) {
        Remove-Item -LiteralPath $fixturePath -Force
    }
}
