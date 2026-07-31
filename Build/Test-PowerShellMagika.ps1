param(
    [Parameter(Mandatory)]
    [string] $ModulePath
)

$ErrorActionPreference = 'Stop'
$resolvedModulePath = (Resolve-Path -LiteralPath $ModulePath).Path
$fixturePath = Join-Path ([IO.Path]::GetTempPath()) "FileInspectorX-Magika-$PID.json"

try {
    [IO.File]::WriteAllText($fixturePath, '{"name":"FileInspectorX","enabled":true}')
    Import-Module $resolvedModulePath -Force

    $warnings = @()
    $assisted = Get-FileInsight -Path $fixturePath -WarningVariable warnings
    $prediction = $assisted.Detection.LearnedClassification.Prediction

    if ($warnings.Count -ne 0) {
        throw "Default Magika analysis emitted a warning: $($warnings -join '; ')"
    }
    if ($prediction.Provider -ne 'Magika') {
        throw "Expected the default learned provider to be Magika, found '$($prediction.Provider)'."
    }
    if ($assisted.DetectedExtension -ne 'json') {
        throw "Expected deterministic JSON detection, found '$($assisted.DetectedExtension)'."
    }

    $deterministicOnly = Get-FileInsight -Path $fixturePath -DisableMagika
    if ($null -ne $deterministicOnly.Detection.LearnedClassification) {
        throw 'DisableMagika did not disable learned classification.'
    }
} finally {
    if (Test-Path -LiteralPath $fixturePath) {
        Remove-Item -LiteralPath $fixturePath -Force
    }
}
