param([Parameter(Mandatory)] [string] $ModulePath, [Parameter(Mandatory)] [string] $Root, [Parameter(Mandatory)] [string] $OutputPath, [long] $MaximumMftBytes)
$ErrorActionPreference = 'Stop'
Import-Module $ModulePath
$options = [FileInspectorX.Prototypes.FileSystem.QueryOptions]::new()
$options.Root = $Root
$options.Recurse = $true
$options.Force = $true
$options.AllowVolumeInventory = $true
$options.MaximumMftBytes = $MaximumMftBytes
$result = [FileInspectorX.Prototypes.FileSystem.FileSystemQuery]::OpenAsync($options).GetAwaiter().GetResult()
$items = @($result.Entries)
$expected = @(Get-ChildItem -LiteralPath $Root -Recurse -Force)
$actualPaths = @($items.FullName | Sort-Object) -join "`n"
$expectedPaths = @($expected.FullName | Sort-Object) -join "`n"
if ($actualPaths -cne $expectedPaths) { throw 'Elevated automatic routing changed visible synthetic fixture paths.' }
[pscustomobject]@{ Backend = $result.Backend; FallbackReason = $result.FallbackReason; ItemCount = $items.Count; PathsMatch = $true; Framework = [Runtime.InteropServices.RuntimeInformation]::FrameworkDescription } |
    ConvertTo-Json | Set-Content -LiteralPath $OutputPath
