$modulePath = Get-BenchmarkInput ModulePath -Required
$fixtureRoot = Get-BenchmarkInput FixtureRoot -Required
$volumeRoot = Get-BenchmarkInput VolumeRoot -Required
$includeVolume = Get-BenchmarkInput IncludeVolume -Bool -Default $true
$evidencePath = Get-BenchmarkInput EvidencePath -Required
$compatibilityRoot = Get-BenchmarkInput CompatibilityRoot -Required
$planning = Get-BenchmarkInput Planning -Bool -Default $false
$runMft = Get-BenchmarkInput RunMft -Bool -Default $true
Import-Module $modulePath -ErrorAction Stop
$process = [Diagnostics.Process]::GetCurrentProcess()
$snapshot = [pscustomobject]@{RecordCount=0;LinkCount=0;ExtensionRecordCount=0;IncompleteRecordCount=0;EstimatedIndexBytes=0;NativeBytesRead=0;MftBytes=0;MetadataSource='NotCaptured'}
$captureMs = 0; $captureCpuMs = 0; $captureAllocation = 0; $retainedHeapDelta = 0
if ($runMft -and -not $planning) {
$beforeHeap = [GC]::GetTotalMemory($true)
$beforeAllocation = [GC]::GetTotalAllocatedBytes($true)
$beforeCpu = $process.TotalProcessorTime.TotalMilliseconds
$watch = [Diagnostics.Stopwatch]::StartNew()
$snapshot = [FileInspectorX.Prototypes.FileSystem.MftSnapshot]::CaptureAsync($volumeRoot, [Threading.CancellationToken]::None, 8589934592, 6000000, 4294967296, [TimeSpan]::FromMinutes(10)).GetAwaiter().GetResult()
$captureMs = $watch.Elapsed.TotalMilliseconds
$captureCpuMs = $process.TotalProcessorTime.TotalMilliseconds - $beforeCpu
$captureAllocation = [GC]::GetTotalAllocatedBytes($true) - $beforeAllocation
$retainedHeapDelta = [GC]::GetTotalMemory($true) - $beforeHeap
& (Join-Path $PSScriptRoot 'Tests/Measure-MftCompatibility.ps1') -ModulePath $modulePath -FixtureRoot $compatibilityRoot -Snapshot $snapshot -MaximumMftBytes 8589934592 -OutputPath (Join-Path (Split-Path $evidencePath -Parent) 'compatibility-net8.json') | Out-Null
}

# One shared consumer reads the same metadata from each engine inside the timed operation.
$cases = @(
    [pscustomobject]@{ Name = 'Tree500k'; Root = $fixtureRoot; WholeVolume = $false },
    [pscustomobject]@{ Name = 'Subtree50k'; Root = (Join-Path $fixtureRoot 'level-0'); WholeVolume = $false }
)
if ($includeVolume) { $cases += [pscustomobject]@{ Name = 'WholeDrive'; Root = $volumeRoot; WholeVolume = $true } }
$expected = @{}
if (-not $planning) { foreach ($case in $cases | Where-Object { -not $_.WholeVolume }) {
    $baselineSummary = [FileInspectorX.Prototypes.FileSystem.InventorySummary]::new()
    Get-ChildItem -LiteralPath $case.Root -Recurse -Force -ErrorAction Continue 2>&1 | ForEach-Object {
        if ($_ -is [Management.Automation.ErrorRecord]) { $baselineSummary.AddError(); return }
        $length = if ($_.PSIsContainer) { 0L } else { [long]$_.Length }
        $baselineSummary.Add($_.FullName, [int]$_.Attributes, $length, $_.CreationTimeUtc.Ticks, $_.LastWriteTimeUtc.Ticks)
    }
    $expected[$case.Root] = $baselineSummary
} }
$engines = @('GetChildItem', 'Walk')
if ($runMft) { $engines += 'MftSnapshot' }
New-BenchmarkSuite 'fileinspectorx-direct-mft-large-tree' {
    Add-BenchmarkMetadata PrototypeSha256 (Get-FileHash ([IO.Path]::ChangeExtension($modulePath, '.dll'))).Hash
    Add-BenchmarkMetadata Reader $snapshot.MetadataSource
    Add-BenchmarkMetadata Scope 'Warm local NTFS; streaming paths, lengths, attributes, creation and last-write metadata. Whole drive is live and non-atomic; no path list persisted.'
    Add-BenchmarkMetadata SnapshotCaptureMs $captureMs
    Add-BenchmarkMetadata SnapshotCaptureCpuMs $captureCpuMs
    Add-BenchmarkMetadata SnapshotCaptureAllocatedBytes $captureAllocation
    Add-BenchmarkMetadata SnapshotRetainedHeapDeltaBytes $retainedHeapDelta
    Add-BenchmarkMetadata IndexRecords $snapshot.RecordCount
    Add-BenchmarkMetadata IndexLinks $snapshot.LinkCount
    Add-BenchmarkMetadata ExtensionRecords $snapshot.ExtensionRecordCount
    Add-BenchmarkMetadata IncompleteRecords $snapshot.IncompleteRecordCount
    Add-BenchmarkMetadata IndexEstimatedBytes $snapshot.EstimatedIndexBytes
    Add-BenchmarkMetadata NativeIndexBytesRead $snapshot.NativeBytesRead
    Add-BenchmarkMetadata MftBytes $snapshot.MftBytes
    Add-BenchmarkMetadata PowerShell $PSVersionTable.PSVersion.ToString()
    Add-BenchmarkMetadata Runtime ([Runtime.InteropServices.RuntimeInformation]::FrameworkDescription)
    Add-BenchmarkMetadata Cpu (Get-CimInstance Win32_Processor | Select-Object -ExpandProperty Name)
    Add-BenchmarkMetadata Affinity $process.ProcessorAffinity.ToInt64().ToString('X')
    Add-BenchmarkMetadata Priority $process.PriorityClass.ToString()
    Add-BenchmarkMetadata PowerPlan ((powercfg /GETACTIVESCHEME) -join '')
    Set-BenchmarkPolicy -Warmup 0 -Iteration 2 -Order Rotated -OutlierMode None
    Add-BenchmarkCaseSource $cases
    foreach ($engine in $engines) {
        Add-BenchmarkEngine $engine {
            Add-BenchmarkOperation Inventory {
                param($case, $run)
                $run.Summary = [FileInspectorX.Prototypes.FileSystem.InventorySummary]::new()
                $run.FirstResultMs = $null
                $run.FirstError = $null
                $run.Watch = [Diagnostics.Stopwatch]::StartNew()
                # Define the consumer in this invocation scope; an outer script block loses $run in the runner's captured context.
                $consume = {
                    if ($_ -is [Management.Automation.ErrorRecord]) {
                        $failure = $_
                    } else {
                        if ($null -eq $run.FirstResultMs) { $run.FirstResultMs = $run.Watch.Elapsed.TotalMilliseconds }
                        try {
                            $length = if ($_.PSIsContainer) { 0L } else { [long]$_.Length }
                            $run.Summary.Add($_.FullName, [int]$_.Attributes, $length, $_.CreationTimeUtc.Ticks, $_.LastWriteTimeUtc.Ticks)
                            return
                        } catch { $failure = $_ }
                    }
                    $run.Summary.AddError(($failure.FullyQualifiedErrorId -match '^FileSystemPrototype(Query|Enumeration)Failed'))
                    if ($null -eq $run.FirstError) {
                        $message = [string]$failure.Exception.Message
                        $run.FirstError = [pscustomobject]@{
                            Id = $failure.FullyQualifiedErrorId
                            Category = [string]$failure.CategoryInfo.Category
                            Exception = $failure.Exception.GetType().FullName
                            Message = $message.Substring(0, [Math]::Min(2048, $message.Length))
                        }
                    }
                }
                $before = [GC]::GetTotalAllocatedBytes($false)
                $cpu = $process.TotalProcessorTime.TotalMilliseconds
                switch ($case.Engine) {
                    'GetChildItem' { Get-ChildItem -LiteralPath $case.Root -Recurse -Force -ErrorAction Continue 2>&1 | ForEach-Object $consume }
                    'Walk' { Get-FileSystemItem -LiteralPath $case.Root -Backend Walk -Recurse -Force -ErrorAction Continue 2>&1 | ForEach-Object $consume }
                    'MftSnapshot' { Get-FileSystemItem -LiteralPath $case.Root -Backend Mft -Snapshot $snapshot -Recurse -Force -ErrorAction Continue 2>&1 | ForEach-Object $consume }
                }
                $run.AllocatedBytes = [GC]::GetTotalAllocatedBytes($false) - $before
                $run.CpuMs = $process.TotalProcessorTime.TotalMilliseconds - $cpu
            }
        }
    }
    Add-BenchmarkValidation {
        param($case, $run)
        [pscustomobject]@{
            Case = $case.Scenario; Engine = $case.Engine; CapturedUtc = [datetime]::UtcNow.ToString('o')
            Files = $run.Summary.Files; Directories = $run.Summary.Directories; LogicalBytes = $run.Summary.LogicalBytes; Errors = $run.Summary.Errors
            Aborted = $run.Summary.Aborted
            FirstError = $run.FirstError
            PathXor = $run.Summary.PathXor.ToString('X16'); PathSum = $run.Summary.PathSum.ToString('X16')
            MetadataXor = $run.Summary.MetadataXor.ToString('X16'); MetadataSum = $run.Summary.MetadataSum.ToString('X16')
            ExpectedMetadataXor = $(if (-not $case.WholeVolume) { $expected[$case.Root].MetadataXor.ToString('X16') } else { $null })
        } | ConvertTo-Json -Compress | Add-Content -LiteralPath $evidencePath
        Assert-BenchmarkValue -Actual $run.Summary.Aborted -Expected $false -Message 'An aborted traversal is not a completed inventory sample.'
        if (-not $case.WholeVolume) {
            Assert-BenchmarkValue -Actual $run.Summary.Errors -Expected 0L -Message 'Synthetic inventory must complete without errors.'
            foreach ($field in @('Files','Directories','LogicalBytes','Errors','PathXor','PathSum','MetadataXor','MetadataSum')) {
                Assert-BenchmarkValue -Actual $run.Summary.$field -Expected $expected[$case.Root].$field -Message "Synthetic $field must match normal enumeration."
            }
        }
        # Whole-volume differences and errors are measurements, never declared compatibility passes.
    }
    foreach ($field in @('Files','Directories','LogicalBytes','Errors')) {
        $metricField = $field
        Add-BenchmarkMetric $field ({ param($case, $run) $run.Summary.$metricField }.GetNewClosure())
    }
    Add-BenchmarkMetric ProcessAllocatedBytes { param($case, $run) $run.AllocatedBytes }
    Add-BenchmarkMetric CpuMs { param($case, $run) $run.CpuMs }
    Add-BenchmarkMetric FirstResultMs { param($case, $run) $run.FirstResultMs }
    # Whole-volume visibility and concurrent-change differences preclude automatic throughput ratios.
    # Summary rows preserve measured durations and coverage; compare only complete equivalent synthetic workloads.
}
