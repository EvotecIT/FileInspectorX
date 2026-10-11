$modulePath = Get-BenchmarkInput ModulePath -Required
$fixtureRoot = Get-BenchmarkInput FixtureRoot -Required
$runMft = Get-BenchmarkInput RunMft -Bool -Default $false
$maximumMftBytes = [long](Get-BenchmarkInput MaximumMftBytes 536870912)
Import-Module $modulePath -ErrorAction Stop
$readerPath = Join-Path (Split-Path $modulePath -Parent) 'NtfsReader.dll'
$readerVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($readerPath).ProductVersion
$snapshot = $null
$captureMs = 0
if ($runMft) {
    $captureWatch = [Diagnostics.Stopwatch]::StartNew()
    $snapshot = [FileInspectorX.Prototypes.FileSystem.MftSnapshot]::CaptureAsync($fixtureRoot, [Threading.CancellationToken]::None, $maximumMftBytes).GetAwaiter().GetResult()
    $captureWatch.Stop()
    $captureMs = $captureWatch.Elapsed.TotalMilliseconds
}
$roots = @($fixtureRoot, (Join-Path $fixtureRoot 'level-0'))
$expected = @{}
foreach ($root in $roots) {
    $items = @(Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction Stop)
    $expected[$root] = ($items | ForEach-Object {
        '{0}|{1}|{2}|{3}' -f $_.FullName, $(if ($_.PSIsContainer) { '' } else { $_.Length }), [int]$_.Attributes, $_.LastWriteTimeUtc.Ticks
    } | Sort-Object) -join "`n"
}
New-BenchmarkSuite 'fileinspectorx-filesystem-prototype' {
    Add-BenchmarkMetadata PrototypeSha256 (Get-FileHash ([IO.Path]::ChangeExtension($modulePath, '.dll'))).Hash
    Add-BenchmarkMetadata Reader "itsWindows11.NtfsReader $readerVersion; LGPL-2.1-or-later; evaluation only"
    Add-BenchmarkMetadata ReaderSha256 (Get-FileHash $readerPath).Hash
    Add-BenchmarkMetadata Scope 'Live local synthetic fixture; filesystem caches warm; no reboot/cold-cache claim'
    Add-BenchmarkMetadata SnapshotCaptureMs $captureMs
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
    foreach ($engine in @('GetChildItem', 'Walk', 'WalkNativeObjects', 'AutoFallback', 'MftFresh', 'MftSnapshot')) {
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
                    'MftFresh' { @(Get-FileSystemItem @arguments -Backend Mft -MaximumMftBytes $maximumMftBytes | ForEach-Object $consume) }
                    'MftSnapshot' { @(Get-FileSystemItem @arguments -Backend Mft -Snapshot $snapshot | ForEach-Object $consume) }
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
