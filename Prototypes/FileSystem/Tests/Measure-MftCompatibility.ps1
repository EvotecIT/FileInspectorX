param(
    [Parameter(Mandatory)] [string] $ModulePath,
    [Parameter(Mandatory)] [string] $FixtureRoot,
    [Parameter(Mandatory)] [string] $OutputPath,
    [long] $MaximumMftBytes = 536870912,
    $Snapshot
)
$ErrorActionPreference = 'Stop'
Import-Module $ModulePath
$watch = [Diagnostics.Stopwatch]::StartNew()
if (-not $Snapshot) { $Snapshot = [FileInspectorX.Prototypes.FileSystem.MftSnapshot]::CaptureAsync($FixtureRoot, [Threading.CancellationToken]::None, $MaximumMftBytes, 6000000, 4294967296, [TimeSpan]::FromMinutes(10)).GetAwaiter().GetResult() }
$watch.Stop()
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
$guards = @()
foreach ($guard in @('RecordBudget', 'MemoryBudget', 'CancellationDuringCapture')) {
    $source = [Threading.CancellationTokenSource]::new()
    try {
        $records = if ($guard -eq 'RecordBudget') { 1 } else { 4000000 }
        $bytes = if ($guard -eq 'MemoryBudget') { 1 } else { 1073741824 }
        if ($guard -eq 'CancellationDuringCapture') { $source.CancelAfter(10) }
        $null = [FileInspectorX.Prototypes.FileSystem.MftSnapshot]::CaptureAsync($FixtureRoot, $source.Token, $MaximumMftBytes, $records, $bytes).GetAwaiter().GetResult()
        throw "Capture guard did not trigger: $guard"
    } catch {
        $exception = $_.Exception
        while ($exception.InnerException) { $exception = $exception.InnerException }
        $passed = if ($guard -eq 'CancellationDuringCapture') { $exception -is [OperationCanceledException] } else { $exception -is [NotSupportedException] -and $exception.Message -like '*budget*' }
        $guards += [pscustomobject]@{ Guard = $guard; Passed = $passed; Exception = $exception.GetType().FullName }
    } finally { $source.Dispose() }
}
# Deferred queries must still honor cancellation after OpenAsync has returned.
$source = [Threading.CancellationTokenSource]::new()
try {
    $options = [FileInspectorX.Prototypes.FileSystem.QueryOptions]::new()
    $options.Root = $FixtureRoot; $options.Backend = 'Mft'; $options.Recurse = $true; $options.CancellationToken = $source.Token
    $query = [FileInspectorX.Prototypes.FileSystem.FileSystemQuery]::OpenAsync($options, $snapshot).GetAwaiter().GetResult()
    $source.Cancel()
    try { foreach ($entry in $query.Entries) { $null = $entry }; throw 'Cancellation not observed' }
    catch {
        $exception = $_.Exception
        while ($exception.InnerException) { $exception = $exception.InnerException }
        $guards += [pscustomobject]@{ Guard = 'CancellationDuringQuery'; Passed = ($exception -is [OperationCanceledException]); Exception = $exception.GetType().FullName }
    }
} finally { $source.Dispose() }
[pscustomobject]@{ CapturedUtc = $snapshot.CapturedUtc; SetupMs = $watch.Elapsed.TotalMilliseconds; MftBytes = $snapshot.MftBytes; Reader = $snapshot.MetadataSource; IndexRecords = $snapshot.RecordCount; Links = $snapshot.LinkCount; Extensions = $snapshot.ExtensionRecordCount; Incomplete = $snapshot.IncompleteRecordCount; Guards = $guards; Cases = @($report) } |
    ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding utf8
$report | Select-Object Case, NativeCount, MftCount, DifferenceCount
if (@($guards | Where-Object { -not $_.Passed }).Count) { throw 'One or more live capture/query guards failed.' }
