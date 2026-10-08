param(
    [Parameter(Mandatory)]
    [string] $ModulePath
)

$ErrorActionPreference = 'Stop'
$modulePathResolved = (Resolve-Path -LiteralPath $ModulePath).Path
$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) "FileInspectorX-Help-$PID"
$fixturePath = Join-Path $fixtureRoot 'sample.txt'

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
    Write-Output "Command help smoke passed ($($examples.Count) parsed examples)."
} finally {
    if (Test-Path -LiteralPath $fixturePath) {
        Remove-Item -LiteralPath $fixturePath -ErrorAction Stop
    }
    if (Test-Path -LiteralPath $fixtureRoot) {
        Remove-Item -LiteralPath $fixtureRoot -ErrorAction Stop
    }
}
