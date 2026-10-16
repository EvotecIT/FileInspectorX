param(
    [Parameter(Mandatory)]
    [string] $ModulePath,

    [string] $ScratchDirectory = (Join-Path ([IO.Path]::GetTempPath()) "FileInspectorX-Reports-$PID"),

    [switch] $BuiltinOnly
)

$ErrorActionPreference = 'Stop'
$moduleFile = (Resolve-Path -LiteralPath $ModulePath).Path
New-Item -Path $ScratchDirectory -ItemType Directory -ErrorAction Stop | Out-Null
$fixture = Join-Path $ScratchDirectory 'report.rtf'

try {
    [IO.File]::WriteAllText($fixture, '{\rtf1 Canonical report invoices and revenue.}', [Text.Encoding]::ASCII)
    Import-Module $moduleFile -Force -ErrorAction Stop
    $report = Get-FileInsight -LiteralPath $fixture -View Report -DisableMagika -ErrorAction Stop
    if ($report.SchemaVersion -ne 3 -or $report.File.SizeBytes -ne (Get-Item -LiteralPath $fixture).Length) {
        throw 'Report did not preserve schema 3 and exact source identity.'
    }
    if (-not $BuiltinOnly) {
        if ($report.Content.Reader -ne 'officeimo-rtf' -or $report.Content.Text -notmatch 'Canonical report invoices') {
            throw 'The enhanced module did not use the native OfficeIMO report reader.'
        }
        if ($report.Content.Extraction.TextBasis.ToString() -ne 'CanonicalDocumentText' -or $report.Content.DocumentUnits.Count -lt 1) {
            throw 'The native report did not retain its extraction profile and logical units.'
        }
    }
    $builtin = Get-FileInsight -LiteralPath $fixture -View Report -ReportReader Builtin -DisableMagika -ErrorAction Stop
    if ($builtin.Content.Reader -like 'officeimo-*') { throw 'ReportReader Builtin did not select the core profile.' }
    if ($BuiltinOnly) {
        $nativeAssemblies = @(Get-ChildItem -LiteralPath (Split-Path -Parent $moduleFile) -Filter 'FileInspectorX.OfficeIMO.dll' -File -Recurse)
        if ($nativeAssemblies.Count -ne 0) { throw 'The core-only module contains the optional OfficeIMO adapter.' }
        $rejected = $false
        try { Get-FileInsight -LiteralPath $fixture -View Report -ReportReader OfficeIMO -DisableMagika -ErrorAction Stop | Out-Null }
        catch { $rejected = $true }
        if (-not $rejected) { throw 'A provider-free build accepted the unavailable OfficeIMO profile.' }
    }
    'PowerShell report composition passed.'
}
finally {
    if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -ErrorAction Stop }
    if (Test-Path -LiteralPath $ScratchDirectory) { Remove-Item -LiteralPath $ScratchDirectory -ErrorAction Stop }
}
