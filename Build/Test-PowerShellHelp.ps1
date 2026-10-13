param(
    [Parameter(Mandatory)]
    [string] $ModulePath
)

$ErrorActionPreference = 'Stop'
$modulePathResolved = (Resolve-Path -LiteralPath $ModulePath).Path
$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) "FileInspectorX-Help-$PID"
$fixturePath = Join-Path $fixtureRoot 'sample.txt'
$literalFixturePath = Join-Path $fixtureRoot 'sample[1].txt'
$shadowFixturePath = Join-Path $fixtureRoot 'sample1.txt'

try {
    New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
    [IO.File]::WriteAllText($fixturePath, 'This sample file contains ordinary text.')
    Import-Module $modulePathResolved -Force
    $examples = @((Get-Help Get-FileInsight -Examples).Examples.Example)
    if ($examples.Count -eq 0) {
        throw 'Get-Help did not expose any command examples.'
    }

    foreach ($example in $examples) {
        $tokens = $null
        $parseErrors = $null
        [void][Management.Automation.Language.Parser]::ParseInput(
            [string]$example.Code, [ref]$tokens, [ref]$parseErrors)
        if ($parseErrors.Count -gt 0) {
            throw "A help example is not valid PowerShell: $($parseErrors.Message -join '; ')"
        }
    }

    # Execute the onboarding example as published; it must supply the mandatory file path.
    Push-Location $fixtureRoot
    try {
        $result = & ([scriptblock]::Create([string]$examples[0].Code))
        if ($result.DetectedExtension -ne 'txt' -or $result.InputStatus.ToString() -ne 'Recognized') {
            throw 'The first help example did not analyze the sample file.'
        }
    } finally {
        Pop-Location
    }

    # Exercise the documented FileInfo pipeline route independently of formatting.
    $detection = Get-ChildItem -LiteralPath $fixturePath -File |
        Get-FileInsight -View Detection -DisableMagika
    if ($detection.Path -ne $fixturePath -or $detection.Extension -ne 'txt') {
        throw 'FileInfo pipeline input did not detect the sample file.'
    }

    # FullName from FileInfo is a literal identity even when a matching wildcard path exists.
    [IO.File]::WriteAllText($literalFixturePath, '{"literal":true}')
    [IO.File]::WriteAllText($shadowFixturePath, 'This is the different wildcard-matched file.')
    $literalDetection = Get-FileInsight -LiteralPath $literalFixturePath -View Detection -DisableMagika
    $pipelineDetection = Get-Item -LiteralPath $literalFixturePath |
        Get-FileInsight -View Detection -DisableMagika
    foreach ($result in @($literalDetection, $pipelineDetection)) {
        if ($result.Path -ne $literalFixturePath -or $result.Extension -ne 'json') {
            throw 'A literal bracket path inspected a different file.'
        }
    }
    $propertyDetection = [pscustomobject]@{ FullName = $literalFixturePath } |
        Get-FileInsight -View Detection -DisableMagika
    if ($propertyDetection.Path -ne $literalFixturePath) {
        throw 'FullName property binding did not preserve a literal path.'
    }
    $report = Get-FileInsight -LiteralPath $literalFixturePath -View Report -ExcludePermissions -DisableMagika
    if ($report.SchemaVersion -ne 2 -or $report.File.Name -ne 'sample[1].txt' -or $report.File.Sha256.Length -ne 64) {
        throw 'The Report view did not return the versioned content report for the literal file.'
    }
    $wildcardDetection = Get-FileInsight -Path $literalFixturePath -View Detection -DisableMagika
    if ($wildcardDetection.Path -ne $shadowFixturePath -or $wildcardDetection.Extension -ne 'txt') {
        throw 'Explicit Path wildcard resolution did not retain its supported behavior.'
    }
    $pathPropertyDetection = [pscustomobject]@{ Path = $literalFixturePath } |
        Get-FileInsight -View Detection -DisableMagika
    if ($pathPropertyDetection.Path -ne $shadowFixturePath) {
        throw 'Path property binding did not retain wildcard resolution.'
    }
    $allFiles = @(Get-FileInsight -Path (Join-Path $fixtureRoot '*.txt') -View Detection -DisableMagika)
    if ($allFiles.Count -ne 3) {
        throw 'A Path glob did not inspect every matching file.'
    }
    $errors = @()
    $missing = Get-FileInsight -LiteralPath (Join-Path $fixtureRoot 'missing[1].txt') -DisableMagika `
        -ErrorAction SilentlyContinue -ErrorVariable errors
    if ($null -ne $missing -or $errors.Count -eq 0) {
        throw 'A missing literal path did not report a per-file error.'
    }
    Write-Output "Command help smoke passed ($($examples.Count) parsed examples)."
} finally {
    if (Test-Path -LiteralPath $literalFixturePath) {
        Remove-Item -LiteralPath $literalFixturePath -ErrorAction Stop
    }
    if (Test-Path -LiteralPath $shadowFixturePath) {
        Remove-Item -LiteralPath $shadowFixturePath -ErrorAction Stop
    }
    if (Test-Path -LiteralPath $fixturePath) {
        Remove-Item -LiteralPath $fixturePath -ErrorAction Stop
    }
    if (Test-Path -LiteralPath $fixtureRoot) {
        Remove-Item -LiteralPath $fixtureRoot -ErrorAction Stop
    }
}
