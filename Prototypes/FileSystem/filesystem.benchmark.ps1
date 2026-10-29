$modulePath = Get-BenchmarkInput ModulePath -Required
$fixtureRoot = Get-BenchmarkInput FixtureRoot -Required
$runMft = Get-BenchmarkInput RunMft -Bool -Default $false
$planning = Get-BenchmarkInput Planning -Bool -Default $false
$maximumMftBytes = [long](Get-BenchmarkInput MaximumMftBytes 536870912)
Import-Module $modulePath -ErrorAction Stop
$snapshot = $null
$captureMs = 0
$captureAllocated = 0
$retainedDelta = 0
if ($runMft -and -not $planning) {
    $retainedBefore = [GC]::GetTotalMemory($true)
    $allocatedBefore = [GC]::GetTotalAllocatedBytes($true)
    $captureWatch = [Diagnostics.Stopwatch]::StartNew()
    $snapshot = [FileInspectorX.Prototypes.FileSystem.MftSnapshot]::CaptureAsync($fixtureRoot, [Threading.CancellationToken]::None, $maximumMftBytes, 6000000, 4294967296, [TimeSpan]::FromMinutes(10)).GetAwaiter().GetResult()
    $captureWatch.Stop()
    $captureMs = $captureWatch.Elapsed.TotalMilliseconds
    $captureAllocated = [GC]::GetTotalAllocatedBytes($true) - $allocatedBefore
    $retainedDelta = [GC]::GetTotalMemory($true) - $retainedBefore
}
$roots = @($fixtureRoot, (Join-Path $fixtureRoot 'level-0'))
$expected = @{}
foreach ($root in $(if (-not $planning) { $roots })) {
    $items = @(Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction Stop)
    $expected[$root] = ($items | ForEach-Object {
        '{0}|{1}|{2}|{3}' -f $_.FullName, $(if ($_.PSIsContainer) { '' } else { $_.Length }), [int]$_.Attributes, $_.LastWriteTimeUtc.Ticks
    } | Sort-Object) -join "`n"
}
New-BenchmarkSuite 'fileinspectorx-filesystem-prototype' {
    Add-BenchmarkMetadata PrototypeSha256 (Get-FileHash ([IO.Path]::ChangeExtension($modulePath, '.dll'))).Hash
    Add-BenchmarkMetadata Reader $(if ($snapshot) { $snapshot.MetadataSource } elseif ($runMft) { 'BulkMftExtents (planned)' } else { 'Normal enumeration; MFT disabled' })
    Add-BenchmarkMetadata Scope 'Live local synthetic fixture; filesystem caches warm; no reboot/cold-cache claim'
    Add-BenchmarkMetadata SnapshotCaptureMs $captureMs
    Add-BenchmarkMetadata SnapshotCaptureAllocatedBytes $captureAllocated
    Add-BenchmarkMetadata SnapshotRetainedHeapDeltaBytes $retainedDelta
    Add-BenchmarkMetadata IndexRecords $(if ($snapshot) { $snapshot.RecordCount } else { 0 })
    Add-BenchmarkMetadata IndexEstimatedBytes $(if ($snapshot) { $snapshot.EstimatedIndexBytes } else { 0 })
    Add-BenchmarkMetadata NativeIndexBytesRead $(if ($snapshot) { $snapshot.NativeBytesRead } else { 0 })
    Add-BenchmarkMetadata MftBytes $(if ($snapshot) { $snapshot.MftBytes } else { 0 })
    Add-BenchmarkMetadata PowerShell $PSVersionTable.PSVersion.ToString()
    Add-BenchmarkMetadata Cpu (Get-CimInstance Win32_Processor | Select-Object -ExpandProperty Name)
    Add-BenchmarkMetadata Affinity ([Diagnostics.Process]::GetCurrentProcess().ProcessorAffinity.ToInt64().ToString('X'))
    Add-BenchmarkMetadata Priority ([Diagnostics.Process]::GetCurrentProcess().PriorityClass.ToString())
    Add-BenchmarkMetadata OsBuild ([Environment]::OSVersion.Version.ToString())
    Add-BenchmarkMetadata PowerPlan ((powercfg /GETACTIVESCHEME) -join '')
    Set-BenchmarkPolicy -Warmup 1 -Iteration 3 -Order Rotated -OutlierMode None
    Add-BenchmarkCaseSource @(
        [pscustomobject]@{ Name = 'Tree'; Root = $roots[0] }
        [pscustomobject]@{ Name = 'Subtree'; Root = $roots[1] }
    )
    Add-BenchmarkSkipRule {
        param($case)
        if (-not $runMft -and $case.Engine -like 'Mft*') { 'Raw-volume comparison not enabled; elevation required.' }
        if ($runMft -and $case.Engine -eq 'AutoFallback') { 'Actual permission fallback is measured separately in the non-elevated matrix.' }
    }
    foreach ($engine in @('GetChildItem', 'Walk', 'WalkNativeObjects', 'AutoFallback', 'MftFresh', 'MftSnapshot', 'MftSnapshotNativeObjects')) {
        Add-BenchmarkEngine $engine {
            Add-BenchmarkOperation Enumerate {
                param($case, $run)
                $allocated = [GC]::GetTotalAllocatedBytes($false)
                $watch = [Diagnostics.Stopwatch]::StartNew()
                $run.FirstResultMs = $null
                $arguments = @{ LiteralPath = $case.Root; Recurse = $true; Force = $true; ErrorAction = 'Stop' }
                $consume = { if ($null -eq $run.FirstResultMs) { $run.FirstResultMs = $watch.Elapsed.TotalMilliseconds }; $_ }
                $run.Items = switch ($case.Engine) {
                    'GetChildItem' { @(Get-ChildItem @arguments | ForEach-Object $consume) }
                    'Walk' { @(Get-FileSystemItem @arguments -Backend Walk | ForEach-Object $consume) }
                    'WalkNativeObjects' { @(Get-FileSystemItem @arguments -Backend Walk -AsFileSystemInfo | ForEach-Object $consume) }
                    'AutoFallback' { @(Get-FileSystemItem @arguments -AllowVolumeInventory -MaximumMftBytes $maximumMftBytes | ForEach-Object $consume) }
                    'MftFresh' { @(Get-FileSystemItem @arguments -Backend Mft -MaximumMftBytes $maximumMftBytes -MaximumIndexRecords 6000000 -MaximumIndexBytes 4294967296 -MaximumCaptureSeconds 600 | ForEach-Object $consume) }
                    'MftSnapshot' { @(Get-FileSystemItem @arguments -Backend Mft -Snapshot $snapshot | ForEach-Object $consume) }
                    'MftSnapshotNativeObjects' { @(Get-FileSystemItem @arguments -Backend Mft -Snapshot $snapshot -AsFileSystemInfo | ForEach-Object $consume) }
                }
                $run.AllocatedBytes = [GC]::GetTotalAllocatedBytes($false) - $allocated
            }
        }
    }
    Add-BenchmarkValidation {
        param($case, $run)
        $fingerprint = ($run.Items | ForEach-Object {
            '{0}|{1}|{2}|{3}' -f $_.FullName, $(if ($_.PSIsContainer) { '' } else { $_.Length }), [int]$_.Attributes, $_.LastWriteTimeUtc.Ticks
        } | Sort-Object) -join "`n"
        Assert-BenchmarkValue -Actual $fingerprint -Expected $expected[$case.Root] -Message 'Path, size, attributes and last-write metadata must agree.'
    }
    Add-BenchmarkMetric ProcessAllocatedBytes { param($case, $run) $run.AllocatedBytes }
    Add-BenchmarkMetric FirstResultMs { param($case, $run) $run.FirstResultMs }
    Add-BenchmarkMetric Items { param($case, $run) @($run.Items).Count }
    Add-BenchmarkComparison -Dimension Engine -Baseline GetChildItem -Metric MedianMs -TieTolerance 0.05
}
