param([Parameter(Mandatory)] [string] $ModulePath)

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
    It 'reports missing roots as errors' {
        { Get-FileSystemItem -LiteralPath (Join-Path $root 'missing') -ErrorAction Stop } | Should -Throw
    }
    It 'rejects other providers rather than treating them as filesystem paths' {
        { Get-FileSystemItem -LiteralPath 'Env:\' -ErrorAction Stop } | Should -Throw
    }
}

Describe 'Routing and cancellation' {
    It 'defaults to caller-visible normal enumeration' {
        @(Get-FileSystemItem -LiteralPath $root).Backend | Select-Object -Unique | Should -Be 'Walk'
    }
    It 'falls back for unsupported native wildcard filters before raw capture' {
        @(Get-FileSystemItem -LiteralPath $root -AllowVolumeInventory -Filter '*.txt').Backend | Select-Object -Unique | Should -Be 'Walk'
    }
    It 'uses ordinary enumeration after actual non-elevated raw-volume denial' -Skip:$isElevated {
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
