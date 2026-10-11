param(
    [Parameter(Mandatory)] [string] $ModulePath,
    [Parameter(Mandatory)] [string] $FixtureRoot,
    [Parameter(Mandatory)] [string] $OutputPath,
    [long] $MaximumMftBytes = 536870912
)
$ErrorActionPreference = 'Stop'
Import-Module $ModulePath
$snapshot = [FileInspectorX.Prototypes.FileSystem.MftSnapshot]::CaptureAsync($FixtureRoot, [Threading.CancellationToken]::None, $MaximumMftBytes).GetAwaiter().GetResult()
$cases = @(
    @{ Name = 'Children'; Arguments = @{} },
    @{ Name = 'Recursive'; Arguments = @{ Recurse = $true } },
    @{ Name = 'Force'; Arguments = @{ Recurse = $true; Force = $true } },
    @{ Name = 'Files'; Arguments = @{ Recurse = $true; Force = $true; File = $true } },
    @{ Name = 'Directories'; Arguments = @{ Recurse = $true; Force = $true; Directory = $true } },
    @{ Name = 'Depth0'; Arguments = @{ Depth = 0 } },
    @{ Name = 'Depth1'; Arguments = @{ Depth = 1 } }
)
$report = foreach ($case in $cases) {
    $arguments = $case.Arguments
    $native = @(Get-ChildItem -LiteralPath $FixtureRoot @arguments)
    $actual = @(Get-FileSystemItem -LiteralPath $FixtureRoot @arguments -Backend Mft -Snapshot $snapshot)
    $index = @{}
    foreach ($item in $native) { $index[$item.FullName] = $item }
    $differences = @(
        Compare-Object @($native.FullName | Sort-Object) @($actual.FullName | Sort-Object) | ForEach-Object {
            [pscustomobject]@{ Path = $_.InputObject; Field = 'Path'; Expected = $(if ($_.SideIndicator -eq '<=') { 'present' } else { 'absent' }); Actual = $(if ($_.SideIndicator -eq '=>') { 'present' } else { 'absent' }) }
        }
        foreach ($entry in $actual) {
            $expected = $index[$entry.FullName]
            if (-not $expected) { continue }
            foreach ($field in @('Attributes', 'CreationTimeUtc', 'LastWriteTimeUtc', 'LastAccessTimeUtc')) {
                if ($entry.$field -ne $expected.$field) { [pscustomobject]@{ Path = $entry.FullName; Field = $field; Expected = [string]$expected.$field; Actual = [string]$entry.$field } }
            }
            if (-not $entry.PSIsContainer -and $entry.Length -ne $expected.Length) {
                [pscustomobject]@{ Path = $entry.FullName; Field = 'Length'; Expected = $expected.Length; Actual = $entry.Length }
            }
        }
    )
    [pscustomobject]@{ Case = $case.Name; NativeCount = $native.Count; MftCount = $actual.Count; DifferenceCount = $differences.Count; Differences = $differences }
}
[pscustomobject]@{ CapturedUtc = $snapshot.CapturedUtc; MftBytes = $snapshot.MftBytes; Reader = [Diagnostics.FileVersionInfo]::GetVersionInfo((Join-Path (Split-Path $ModulePath -Parent) 'NtfsReader.dll')).ProductVersion; Cases = @($report) } |
    ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding utf8
$report | Select-Object Case, NativeCount, MftCount, DifferenceCount
