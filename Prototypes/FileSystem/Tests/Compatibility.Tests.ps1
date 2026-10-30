param([Parameter(Mandatory)] [string] $ModulePath)

Describe 'Comparison planning' {
    It 'plans MFT lanes without reading a fixture or creating output' {
        $fixtureRoot = Join-Path $TestDrive 'absent-fixture'
        $outputRoot = Join-Path $TestDrive 'absent-output'
        $wrapper = Join-Path $PSScriptRoot '../Invoke-PrototypeComparison.ps1'
        $cases = @(& $wrapper -ModulePath $ModulePath -FixtureRoot $fixtureRoot -OutputRoot $outputRoot -Plan -RunMft)
        $cases.Count | Should -Be 14
        Test-Path -LiteralPath $fixtureRoot | Should -BeFalse
        Test-Path -LiteralPath $outputRoot | Should -BeFalse
    }
    It 'preserves existing large-tree evidence instead of appending another run' {
        $outputRoot = Join-Path $TestDrive 'existing-comparison'
        $null = New-Item -ItemType Directory -Path $outputRoot
        $evidence = Join-Path $outputRoot 'inventory-checkpoints.jsonl'
        [IO.File]::WriteAllText($evidence, 'previous-run')
        $wrapper = Join-Path $PSScriptRoot '../Invoke-LargeTreeComparison.ps1'
        { & $wrapper -ModulePath $ModulePath -FixtureRoot 'absent-fixture' -CompatibilityRoot 'absent-compatibility' -VolumeRoot 'absent-volume' -OutputRoot $outputRoot -NormalOnly -SkipVolume } |
            Should -Throw '*fresh result directory*'
        [IO.File]::ReadAllText($evidence) | Should -BeExactly 'previous-run'
    }
}

Describe 'Elevated comparison scratch boundary without elevation' {
    BeforeAll {
        . (Join-Path $PSScriptRoot '../Assert-PrototypeScratchPath.ps1')
    }
    It 'rejects case-variant siblings and parent traversal while accepting an exact child' {
        $scratch = Join-Path $TestDrive 'ScratchBoundary'
        $null = New-Item -ItemType Directory -Path $scratch
        $prefix = [IO.Path]::GetFullPath($scratch).TrimEnd('\') + '\'
        { Assert-PrototypeScratchPath -Path (Join-Path $scratch 'future-output') -ScratchPrefix $prefix } | Should -Not -Throw
        { Assert-PrototypeScratchPath -Path (Join-Path $TestDrive 'scratchboundary/future-output') -ScratchPrefix $prefix } | Should -Throw '*exact path spelling*'
        { Assert-PrototypeScratchPath -Path (Join-Path $scratch '../outside-output') -ScratchPrefix $prefix } | Should -Throw '*scratch root*'
    }
    It 'rejects an outside request before trying to read it or create output' {
        $scratch = Join-Path $TestDrive 'RequestBoundary'
        $null = New-Item -ItemType Directory -Path $scratch
        $previousScratch = $env:EVOTEC_SCRATCH_ROOT
        try {
            $env:EVOTEC_SCRATCH_ROOT = $scratch
            $outsideRequest = Join-Path $TestDrive 'absent-outside-request.json'
            { & (Join-Path $PSScriptRoot '../Invoke-ElevatedPrototypeComparison.ps1') -RequestFile $outsideRequest } | Should -Throw '*scratch root*'
            Test-Path -LiteralPath $outsideRequest | Should -BeFalse
        } finally { $env:EVOTEC_SCRATCH_ROOT = $previousScratch }
    }
    It 'rejects a derived <DerivedPath> junction before creating comparison output' -TestCases @(
        @{ DerivedPath = 'Legacy' },
        @{ DerivedPath = 'Temporary' }
    ) {
        param($DerivedPath)
        $scratch = Join-Path $TestDrive ($DerivedPath + '-derived-boundary')
        $outside = Join-Path $TestDrive ($DerivedPath + '-outside')
        $null = New-Item -ItemType Directory -Path $scratch, $outside
        $junction = if ($DerivedPath -eq 'Legacy') { Join-Path $scratch 'debug_net472' } else { Join-Path $scratch 'temp' }
        $null = New-Item -ItemType Junction -Path $junction -Value $outside
        $output = Join-Path $scratch 'comparison-output'
        $requestFile = Join-Path $scratch 'request.json'
        @{
            ModulePath = Join-Path $scratch 'debug_net8.0/Prototype.psd1'
            FixtureRoot = Join-Path $scratch 'fixture'
            CompatibilityRoot = Join-Path $scratch 'compatibility'
            OutputRoot = $output
        } | ConvertTo-Json | Set-Content -LiteralPath $requestFile
        $previousScratch = $env:EVOTEC_SCRATCH_ROOT
        try {
            $env:EVOTEC_SCRATCH_ROOT = $scratch
            { & (Join-Path $PSScriptRoot '../Invoke-ElevatedPrototypeComparison.ps1') -RequestFile $requestFile } | Should -Throw '*Reparse paths*'
            Test-Path -LiteralPath $output | Should -BeFalse
            @(Get-ChildItem -LiteralPath $outside -Force).Count | Should -Be 0
        } finally { $env:EVOTEC_SCRATCH_ROOT = $previousScratch }
    }
}

BeforeAll {
    Import-Module $ModulePath -ErrorAction Stop
    $root = Join-Path $TestDrive 'fixture [literal]'
    $null = New-Item -ItemType Directory -Path $root
    $unicodeName = -join ([char[]](90, 97, 380, 243, 322, 263))
    foreach ($relative in @('a.txt', 'z.bin', 'file[1].txt', ($unicodeName + '.txt'), 'sub/child.txt', 'sub/deep/end.txt', 'hidden/secret.txt')) {
        $path = Join-Path $root $relative
        $null = [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path))
        [IO.File]::WriteAllBytes($path, [byte[]](1, 2, 3, 4, 5))
    }
    [IO.File]::WriteAllBytes((Join-Path $root 'empty'), [byte[]]@())
    [IO.File]::SetAttributes((Join-Path $root 'hidden'), [IO.FileAttributes]::Directory -bor [IO.FileAttributes]::Hidden)
    [IO.File]::SetLastWriteTimeUtc((Join-Path $root 'a.txt'), [datetime]'2024-01-02T03:04:05Z')
    $isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    function Assert-Parity($arguments) {
        $actual = @(Get-FileSystemItem -LiteralPath $root -Backend Walk @arguments -ErrorAction Stop)
        $expected = @(Get-ChildItem -LiteralPath $root @arguments -ErrorAction Stop)
        @($actual.FullName | Sort-Object) -join "`n" | Should -BeExactly (@($expected.FullName | Sort-Object) -join "`n")
        foreach ($entry in $actual) {
            $native = Get-Item -LiteralPath $entry.FullName -Force
            $entry.Attributes | Should -Be $native.Attributes
            $entry.LastWriteTimeUtc | Should -Be $native.LastWriteTimeUtc
            if (-not $entry.PSIsContainer) { $entry.Length | Should -Be $native.Length }
        }
    }
}

Describe 'Normal enumeration filesystem subset' {
    It 'matches default child paths and metadata' { Assert-Parity @{} }
    It 'matches recursive paths without entering hidden directories' { Assert-Parity @{ Recurse = $true } }
    It 'matches forced recursive paths' { Assert-Parity @{ Recurse = $true; Force = $true } }
    It 'matches files only' { Assert-Parity @{ Recurse = $true; File = $true } }
    It 'matches directories only' { Assert-Parity @{ Recurse = $true; Directory = $true } }
    It 'matches depth zero with implicit recursion' { Assert-Parity @{ Depth = 0 } }
    It 'matches depth one with implicit recursion' { Assert-Parity @{ Depth = 1 } }
    It 'preserves provider-native filter semantics through nonmatching directories' { Assert-Parity @{ Recurse = $true; Filter = '*.txt' } }
    It 'treats bracket characters literally in a native filter' { Assert-Parity @{ Filter = 'file[1].txt' } }
    It 'emits relative names' {
        @(Get-FileSystemItem -LiteralPath $root -Recurse -Name | Sort-Object) -join "`n" |
            Should -BeExactly (@(Get-ChildItem -LiteralPath $root -Recurse -Name | Sort-Object) -join "`n")
    }
    It 'can return native FileInfo and DirectoryInfo objects' {
        $items = @(Get-FileSystemItem -LiteralPath $root -AsFileSystemInfo)
        @($items | Where-Object { $_ -isnot [IO.FileSystemInfo] }).Count | Should -Be 0
        @($items | Where-Object { $_ -is [IO.FileInfo] }).Count | Should -BeGreaterThan 0
        foreach ($item in $items) { $item.PSIsContainer | Should -Be ($item -is [IO.DirectoryInfo]) }
    }
    It 'processes multiple literal roots independently' {
        $paths = @($root, (Join-Path $root 'sub'))
        @(Get-FileSystemItem -LiteralPath $paths).Count | Should -Be @(Get-ChildItem -LiteralPath $paths).Count
    }
    It 'keeps valid roots after a path-resolution error for <InvalidPath>' -TestCases @(
        @{ InvalidPath = 'Env:\' },
        @{ InvalidPath = 'FileInspectorXMissingDrive:\' }
    ) {
        param($InvalidPath)
        $pathErrors = @()
        $actual = @(Get-FileSystemItem -LiteralPath @($InvalidPath, $root) -Backend Walk -ErrorAction SilentlyContinue -ErrorVariable pathErrors)
        @($actual.FullName | Sort-Object) -join "`n" | Should -BeExactly ((@(Get-ChildItem -LiteralPath $root).FullName | Sort-Object) -join "`n")
        $pathErrors.Count | Should -Be 1
        $pathErrors[0].FullyQualifiedErrorId | Should -Match 'FileSystemPrototypePathResolutionFailed'
    }
    It 'reports missing roots as errors' {
        { Get-FileSystemItem -LiteralPath (Join-Path $root 'missing') -ErrorAction Stop } | Should -Throw
    }
    It 'rejects other providers rather than treating them as filesystem paths' {
        { Get-FileSystemItem -LiteralPath 'Env:\' -ErrorAction Stop } | Should -Throw
    }
}

Describe 'Routing and cancellation' {
    It 'keeps handled access errors in the returned CSharp inventory summary' {
        $scanRoot=Join-Path $TestDrive 'partial-scan'
        $denied=Join-Path $scanRoot 'denied'
        $null=New-Item -ItemType Directory -Path $denied
        [IO.File]::WriteAllBytes((Join-Path $scanRoot 'visible.bin'),[byte[]](1,2,3,4))
        [IO.File]::WriteAllBytes((Join-Path $denied 'hidden-by-acl.bin'),[byte[]](5,6,7))
        $original=Get-Acl -LiteralPath $denied
        $restricted=Get-Acl -LiteralPath $denied
        $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
        $rule=[Security.AccessControl.FileSystemAccessRule]::new($sid,[Security.AccessControl.FileSystemRights]::ListDirectory,[Security.AccessControl.AccessControlType]::Deny)
        $restricted.AddAccessRule($rule)
        try {
            Set-Acl -LiteralPath $denied -AclObject $restricted
            $options=[FileInspectorX.Prototypes.FileSystem.QueryOptions]::new()
            $options.Root=$scanRoot;$options.Recurse=$true;$options.Force=$true
            $errors=[FileInspectorX.Prototypes.FileSystem.InventoryErrors]::new()
            $options.OnError=$errors.Handler
            $summary=[FileInspectorX.Prototypes.FileSystem.InventoryScan]::MeasureAsync($options).GetAwaiter().GetResult()
            $summary.Files | Should -Be 1
            $summary.LogicalBytes | Should -Be 4
            $errors.Count | Should -Be 1
            $summary.Errors | Should -Be 1
            $summary.Aborted | Should -BeFalse
            $options.OnError | Should -Be $errors.Handler
        } finally {Set-Acl -LiteralPath $denied -AclObject $original}
    }
    It 'reports a disappeared directory through the optional normal-enumeration error sink' {
        $gone=Join-Path $TestDrive 'disappeared'
        $null=New-Item -ItemType Directory -Path $gone
        $options=[FileInspectorX.Prototypes.FileSystem.QueryOptions]::new()
        $options.Root=$gone; $options.Backend='Walk'
        $errors=[FileInspectorX.Prototypes.FileSystem.InventoryErrors]::new()
        $options.OnError=$errors.Handler
        $query=[FileInspectorX.Prototypes.FileSystem.FileSystemQuery]::OpenAsync($options).GetAwaiter().GetResult()
        [IO.Directory]::Delete($gone)
        @($query.Entries).Count | Should -Be 0
        $errors.Count | Should -Be 1
        $errors.FirstException | Should -Be 'System.IO.DirectoryNotFoundException'
    }
    It 'aggregates logical folder totals in CSharp without a PowerShell entry consumer' {
        $options=[FileInspectorX.Prototypes.FileSystem.QueryOptions]::new()
        $options.Root=$root; $options.Recurse=$true; $options.Force=$true
        $totals=[FileInspectorX.Prototypes.FileSystem.FolderTotals]::MeasureAsync($options).GetAwaiter().GetResult()
        foreach ($total in $totals) {
            $expected=@(Get-ChildItem -LiteralPath $total.Path -Recurse -Force -File)
            $total.Files | Should -Be $expected.Count
            $total.LogicalBytes | Should -Be (($expected | Measure-Object Length -Sum).Sum)
        }
        { [FileInspectorX.Prototypes.FileSystem.FolderTotals]::MeasureAsync($options,$null,1).GetAwaiter().GetResult() } | Should -Throw
        $options.File=$true
        { [FileInspectorX.Prototypes.FileSystem.FolderTotals]::MeasureAsync($options).GetAwaiter().GetResult() } | Should -Throw
    }
    It 'keeps snapshot visibility and freshness out of automatic caller-visible routing' {
        $options = [FileInspectorX.Prototypes.FileSystem.QueryOptions]::new()
        $options.Root = $root
        $options.AllowVolumeInventory = $true
        $options.MaximumMftBytes = 4294967296
        $query = [FileInspectorX.Prototypes.FileSystem.FileSystemQuery]::OpenAsync($options).GetAwaiter().GetResult()
        $query.Backend | Should -Be 'Walk'
        $query.FallbackReason | Should -Match 'visibility and freshness'
        @($query.Entries).Count | Should -Be @(Get-ChildItem -LiteralPath $root).Count
    }
    It 'defaults to caller-visible normal enumeration' {
        @(Get-FileSystemItem -LiteralPath $root).Backend | Select-Object -Unique | Should -Be 'Walk'
    }
    It 'falls back for unsupported native wildcard filters before raw capture' {
        @(Get-FileSystemItem -LiteralPath $root -AllowVolumeInventory -Filter '*.txt').Backend | Select-Object -Unique | Should -Be 'Walk'
    }
    It 'uses ordinary enumeration without elevated raw-volume access' -Skip:$isElevated {
        @(Get-FileSystemItem -LiteralPath $root -AllowVolumeInventory -ErrorAction Stop).Backend | Select-Object -Unique | Should -Be 'Walk'
    }
    It 'keeps forced MFT failure visible without permission' -Skip:$isElevated {
        { Get-FileSystemItem -LiteralPath $root -Backend Mft -ErrorAction Stop } | Should -Throw
    }
    It 'does not turn cancellation into successful fallback' {
        $options = [FileInspectorX.Prototypes.FileSystem.QueryOptions]::new()
        $options.Root = $root
        $source = [Threading.CancellationTokenSource]::new()
        try {
            $source.Cancel()
            $options.CancellationToken = $source.Token
            { [FileInspectorX.Prototypes.FileSystem.FileSystemQuery]::OpenAsync($options).GetAwaiter().GetResult() } | Should -Throw
        } finally { $source.Dispose() }
    }
}
