$modulePath = Get-BenchmarkInput ModulePath -Required
$fixtureRoot = Get-BenchmarkInput FixtureRoot -Required
$volumeRoot = Get-BenchmarkInput VolumeRoot -Required
$evidencePath = Get-BenchmarkInput EvidencePath -Required
$includeVolume = Get-BenchmarkInput IncludeVolume -Bool -Default $true
$planning = Get-BenchmarkInput Planning -Bool -Default $false
$includeAcquisition = Get-BenchmarkInput IncludeAcquisition -Bool -Default $true
Import-Module $modulePath -ErrorAction Stop
$roots = @([pscustomobject]@{Name='Tree500k';Root=$fixtureRoot;Whole=$false},[pscustomobject]@{Name='Subtree50k';Root=(Join-Path $fixtureRoot 'level-0');Whole=$false})
if ($includeVolume) { $roots += [pscustomobject]@{Name='WholeDrive';Root=$volumeRoot;Whole=$true} }
$cases = @(
    if ($includeAcquisition) { [pscustomobject]@{Stage='Acquisition';Root=$volumeRoot;Whole=$true;Name='VolumeAcquisition'} }
    foreach ($root in $roots) {
        foreach ($stage in @('CSharpScan','FolderTotals','PowerShellOutput')) {
            [pscustomobject]@{Stage=$stage;Root=$root.Root;Whole=$root.Whole;Name=($root.Name+'-'+$stage)}
        }
    }
)
$snapshot=$null
$expected=@{}
if (-not $planning) {
    $snapshot=[FileInspectorX.Prototypes.FileSystem.MftSnapshot]::CaptureAsync($volumeRoot,[Threading.CancellationToken]::None,8589934592,6000000,4294967296,[TimeSpan]::FromMinutes(10)).GetAwaiter().GetResult()
    foreach ($root in $roots | Where-Object { -not $_.Whole }) {
        $options=[FileInspectorX.Prototypes.FileSystem.QueryOptions]::new()
        $options.Root=$root.Root; $options.Recurse=$true; $options.Force=$true; $options.Backend='Walk'
        $baseline=[FileInspectorX.Prototypes.FileSystem.InventoryScan]::MeasureAsync($options).GetAwaiter().GetResult()
        $values=@{}
        foreach($field in @('Files','Directories','LogicalBytes','PathXor','PathSum','MetadataXor','MetadataSum')) { $values[$field]=$baseline.$field.ToString() }
        $expected[$root.Root]=$values
        $expected[$root.Root+'Folders']=[FileInspectorX.Prototypes.FileSystem.FolderTotals]::MeasureAsync($options).GetAwaiter().GetResult() | Sort-Object Path | ConvertTo-Json -Depth 3 -Compress
    }
}
New-BenchmarkSuite -Name 'FileInspectorX-BulkStages' {
    Set-BenchmarkPolicy -Warmup 0 -Iteration 2 -Order Rotated -OutlierMode None
    Add-BenchmarkMetadata Scope 'Existing local NTFS; acquisition, C# scan, folder totals and PowerShell object delivery separated. Live volume is non-atomic and visibility differs.'
    Add-BenchmarkMetadata OutputConsumer 'PowerShellOutput uses Measure-Object count only; CSharpScan fingerprints paths/metadata inside clock; FolderTotals retains folders only.'
    Add-BenchmarkMetadata Runtime ([Runtime.InteropServices.RuntimeInformation]::FrameworkDescription)
    Add-BenchmarkMetadata PowerShell $PSVersionTable.PSVersion.ToString()
    Add-BenchmarkMetadata Affinity ([Diagnostics.Process]::GetCurrentProcess().ProcessorAffinity.ToInt64().ToString('X'))
    Add-BenchmarkMetadata Cpu (Get-CimInstance Win32_Processor | Select-Object -ExpandProperty Name)
    Add-BenchmarkMetadata Os ([Environment]::OSVersion.VersionString)
    Add-BenchmarkMetadata Priority ([Diagnostics.Process]::GetCurrentProcess().PriorityClass.ToString())
    Add-BenchmarkMetadata PowerPlan ((powercfg /GETACTIVESCHEME) -join '')
    Add-BenchmarkMetadata Source (git -C $PSScriptRoot rev-parse HEAD)
    Add-BenchmarkMetadata AssemblyHash (Get-FileHash -LiteralPath ([IO.Path]::ChangeExtension($modulePath,'.dll'))).Hash
    Add-BenchmarkCaseSource $cases
    Add-BenchmarkSkipRule {
        param($case)
        if ($case.Stage -eq 'Acquisition' -and $case.Engine -eq 'CachedMft') { return 'Acquisition measures fresh readers, not a cached query.' }
        if ($case.Stage -ne 'Acquisition' -and $case.Engine -in @('BulkMft','RecordApi')) { return 'Query stages use the same retained bulk index.' }
    }
    foreach ($engine in @('Normal','CachedMft','BulkMft','RecordApi')) {
        Add-BenchmarkEngine $engine {
            Add-BenchmarkOperation Measure {
                param($case,$run)
                $run.Errors=[FileInspectorX.Prototypes.FileSystem.InventoryErrors]::new()
                $run.Result=$null; $run.Snapshot=$null
                $options=[FileInspectorX.Prototypes.FileSystem.QueryOptions]::new()
                $options.Root=$case.Root; $options.Recurse=$true; $options.Force=$true
                $options.Backend=if($case.Engine -eq 'CachedMft'){'Mft'}else{'Walk'}
                $options.OnError=$run.Errors.Handler
                $process=[Diagnostics.Process]::GetCurrentProcess()
                $cpu=$process.TotalProcessorTime.TotalMilliseconds
                $allocated=[GC]::GetTotalAllocatedBytes($false)
                if ($case.Stage -eq 'Acquisition' -and $case.Engine -ne 'Normal') {
                    $mode=if($case.Engine -eq 'RecordApi'){'RecordApi'}else{'Bulk'}
                    $run.Snapshot=[FileInspectorX.Prototypes.FileSystem.MftSnapshot]::CaptureAsync($case.Root,[Threading.CancellationToken]::None,8589934592,6000000,4294967296,[TimeSpan]::FromMinutes(10),$mode).GetAwaiter().GetResult()
                } elseif ($case.Stage -eq 'FolderTotals') {
                    $run.Result=[FileInspectorX.Prototypes.FileSystem.FolderTotals]::MeasureAsync($options,$(if($case.Engine -eq 'CachedMft'){$snapshot}else{$null})).GetAwaiter().GetResult()
                } elseif ($case.Stage -eq 'PowerShellOutput') {
                    $errors=@()
                    if ($case.Engine -eq 'CachedMft') { $run.Result=Get-FileSystemItem -LiteralPath $case.Root -Backend Mft -Snapshot $snapshot -Recurse -Force -ErrorAction Continue -ErrorVariable errors | Measure-Object }
                    else { $run.Result=Get-ChildItem -LiteralPath $case.Root -Recurse -Force -ErrorAction Continue -ErrorVariable errors | Measure-Object }
                    $run.OutputErrors=$errors.Count
                } else {
                    $run.Result=[FileInspectorX.Prototypes.FileSystem.InventoryScan]::MeasureAsync($options,$(if($case.Engine -eq 'CachedMft'){$snapshot}else{$null})).GetAwaiter().GetResult()
                }
                $run.CpuMs=$process.TotalProcessorTime.TotalMilliseconds-$cpu
                $run.AllocatedBytes=[GC]::GetTotalAllocatedBytes($false)-$allocated
            }
        }
    }
    Add-BenchmarkValidation {
        param($case,$run)
        $compactResult=$run.Result
        if ($case.Stage -eq 'FolderTotals') {
            $rootTotal=@($run.Result | Where-Object Path -eq $case.Root)[0]
            $compactResult=[pscustomobject]@{FolderCount=$run.Result.Count;Files=$rootTotal.Files;Directories=$rootTotal.Directories;LogicalBytes=$rootTotal.LogicalBytes}
        }
        $checkpoint=[ordered]@{Stage=$case.Stage;Engine=$case.Engine;Root=$case.Root;Whole=$case.Whole;ErrorCount=$run.Errors.Count;OutputErrors=$run.OutputErrors;Result=$compactResult;Snapshot=$run.Snapshot;Expected=$(if(-not $case.Whole){$expected[$case.Root]}else{$null})}
        $checkpoint | ConvertTo-Json -Depth 4 -Compress | Add-Content -LiteralPath $evidencePath
        if ($run.Snapshot) { Assert-BenchmarkValue -Actual $run.Snapshot.IncompleteRecordCount -Expected 0 -Message 'Incomplete capture is not a passing acquisition.' }
        if (-not $case.Whole) {
            Assert-BenchmarkValue -Actual $run.Errors.Count -Expected 0L -Message 'Synthetic query must have no errors.'
            $baseline=$expected[$case.Root]
            if ($case.Stage -eq 'PowerShellOutput') { Assert-BenchmarkValue -Actual $run.OutputErrors -Expected 0 -Message 'PowerShell fixture output must have no errors.'; Assert-BenchmarkValue -Actual ([long]$run.Result.Count) -Expected ([long]$baseline.Files+[long]$baseline.Directories) -Message 'Output count must match.' }
            elseif ($case.Stage -eq 'FolderTotals') {
                $actual=$run.Result | Sort-Object Path | ConvertTo-Json -Depth 3 -Compress
                Assert-BenchmarkValue -Actual $actual -Expected $expected[$case.Root+'Folders'] -Message 'Every folder path and subtree total must match.'
            } else { foreach($field in @('Files','Directories','LogicalBytes','PathXor','PathSum','MetadataXor','MetadataSum')) { Assert-BenchmarkValue -Actual ($run.Result.$field.ToString()) -Expected $baseline.$field -Message "CSharp $field must match: actual=$($run.Result.$field), expected=$($baseline.$field)." } }
        }
        # Live whole-drive counts are evidence, never automatically equivalent or ranked.
    }
    Add-BenchmarkMetric CpuMs {param($case,$run) $run.CpuMs}
    Add-BenchmarkMetric ProcessAllocatedBytes {param($case,$run) $run.AllocatedBytes}
}
