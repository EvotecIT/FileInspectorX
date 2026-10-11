param([Parameter(Mandatory)] [string] $RequestFile)
# Requires separate approval: creates, formats and mounts ONLY a new task-owned virtual disk.
$ErrorActionPreference = 'Stop'
$request = Get-Content -LiteralPath $RequestFile -Raw | ConvertFrom-Json
$scratch = $env:EVOTEC_SCRATCH_ROOT
if (-not $scratch -or -not (Test-Path -LiteralPath $scratch -PathType Container)) { throw 'Configured scratch volume must already be mounted.' }
$prefix = [IO.Path]::GetFullPath($scratch).TrimEnd('\') + '\'
foreach ($path in @($RequestFile, $request.OutputRoot, $request.ModulePath)) {
    if (-not [IO.Path]::IsPathRooted($path) -or -not [IO.Path]::GetFullPath($path).StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'Every host path must be inside configured scratch.' }
    for ($ancestor = $path; $ancestor; $ancestor = Split-Path $ancestor -Parent) {
        if ((Test-Path -LiteralPath $ancestor) -and ((Get-Item -LiteralPath $ancestor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Reparse ancestors are not accepted.' }
    }
}
if (Test-Path -LiteralPath $request.OutputRoot) { throw 'Output directory must be new.' }
$null = New-Item -ItemType Directory -Path $request.OutputRoot
$imagePath = Join-Path $request.OutputRoot 'synthetic-ntfs.vhd'
$diskpartPath = Join-Path $request.OutputRoot 'create-image.txt'
$env:TEMP = Join-Path (Split-Path $RequestFile -Parent) 'temp'
$env:TMP = $env:TEMP
$attached = $false
$status = 'Failed'
$receipt = [ordered]@{ ImagePath = $imagePath; CreatedUtc = [datetime]::UtcNow.ToString('o'); DiskNumber = $null; VolumeRoot = $null; SyntheticOnly = $true; Detached = $false; Status = $status }
Start-Transcript -LiteralPath (Join-Path $request.OutputRoot 'driver.log') | Out-Null
try {
    # DiskPart creates a file only. It receives no select-disk, attach, partition or format commands.
    @("create vdisk file=`"$imagePath`" maximum=512 type=expandable", 'exit') | Set-Content -LiteralPath $diskpartPath -Encoding ascii
    diskpart.exe /s $diskpartPath | Set-Content -LiteralPath (Join-Path $request.OutputRoot 'create-image.log')
    if ($LASTEXITCODE -or -not (Test-Path -LiteralPath $imagePath -PathType Leaf)) { throw 'Virtual disk file creation failed.' }
    $null = Mount-DiskImage -ImagePath $imagePath -NoDriveLetter -PassThru
    $attached = $true
    $disk = Get-DiskImage -ImagePath $imagePath | Get-Disk
    if (@($disk).Count -ne 1 -or $disk.IsBoot -or $disk.IsSystem -or [string]$disk.BusType -notin @('File Backed Virtual', 'FileBackedVirtual') -or $disk.PartitionStyle -ne 'RAW' -or $disk.Size -gt 536870912) { throw 'Refusing initialization: disk does not match a new blank file-backed virtual disk of at most 512 MiB.' }
    $receipt.DiskNumber = $disk.Number
    # Reacquire disk identity from the exact attached image before destructive fixture initialization.
    $verified = Get-DiskImage -ImagePath $imagePath | Get-Disk
    if ($verified.Number -ne $disk.Number -or $verified.UniqueId -ne $disk.UniqueId -or $verified.IsBoot -or $verified.IsSystem) { throw 'Virtual disk identity changed.' }
    $initialized = $verified | Initialize-Disk -PartitionStyle MBR -PassThru
    $partition = $initialized | New-Partition -UseMaximumSize -AssignDriveLetter
    if ($partition.DiskNumber -ne $disk.Number -or -not $partition.DriveLetter) { throw 'Unexpected virtual partition identity.' }
    $beforeFormat = Get-DiskImage -ImagePath $imagePath | Get-Disk
    if ($beforeFormat.Number -ne $disk.Number -or $beforeFormat.UniqueId -ne $initialized.UniqueId -or $beforeFormat.IsBoot -or $beforeFormat.IsSystem) { throw 'Virtual disk identity changed before format.' }
    $null = $partition | Format-Volume -FileSystem NTFS -NewFileSystemLabel 'FIX-PROTOTYPE' -Confirm:$false
    $volumeRoot = [string]$partition.DriveLetter + ':\'
    $receipt.VolumeRoot = $volumeRoot
    $fixture = Join-Path $volumeRoot 'fixture'
    & (Join-Path (Split-Path $PSScriptRoot -Parent) 'New-PrototypeFixture.ps1') -Root $fixture -Files 10000
    $compatibility = Join-Path $volumeRoot 'compatibility'
    foreach ($relative in @('a.txt', 'sub/child.txt', 'sub/deep/end.txt', 'hidden/secret.txt', 'outside/prefix.txt')) {
        $path = Join-Path $compatibility $relative
        $null = [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path))
        [IO.File]::WriteAllBytes($path, [byte[]](1,2,3,4,5))
        [IO.File]::SetLastWriteTimeUtc($path, [datetime]'2024-01-02T03:04:05Z')
        [IO.File]::SetLastAccessTimeUtc($path, [datetime]'2024-02-03T04:05:06Z')
    }
    $null = New-Item -ItemType HardLink -Path (Join-Path $compatibility 'alias.txt') -Target (Join-Path $compatibility 'a.txt')
    $null = New-Item -ItemType Junction -Path (Join-Path $compatibility 'linked') -Target (Join-Path $compatibility 'outside')
    [IO.File]::SetAttributes((Join-Path $compatibility 'hidden'), [IO.FileAttributes]::Directory -bor [IO.FileAttributes]::Hidden)
    & pwsh -NoProfile -File (Join-Path $PSScriptRoot 'Test-ElevatedAutoRouting.ps1') -ModulePath $request.ModulePath -Root $fixture -OutputPath (Join-Path $request.OutputRoot 'auto.json') -MaximumMftBytes 536870912
    if ($LASTEXITCODE) { throw 'Isolated automatic routing check failed.' }
    $routing = Get-Content -LiteralPath (Join-Path $request.OutputRoot 'auto.json') -Raw | ConvertFrom-Json
    if ($routing.Backend -ne 'Mft') { throw ('Isolated volume MFT unavailable: ' + $routing.FallbackReason) }
    & pwsh -NoProfile -File (Join-Path $PSScriptRoot 'Measure-MftCompatibility.ps1') -ModulePath $request.ModulePath -FixtureRoot $compatibility -OutputPath (Join-Path $request.OutputRoot 'compatibility.json') -MaximumMftBytes 536870912
    if ($LASTEXITCODE) { throw 'Isolated compatibility diagnostic failed.' }
    & (Join-Path (Split-Path $PSScriptRoot -Parent) 'Invoke-PrototypeComparison.ps1') -ModulePath $request.ModulePath -FixtureRoot $fixture -OutputRoot (Join-Path $request.OutputRoot 'timings') -RunMft
    $status = 'Completed'
} catch {
    $_.Exception.ToString() | Set-Content -LiteralPath (Join-Path $request.OutputRoot 'failure.txt')
    throw
} finally {
    if ($attached) {
        try { Dismount-DiskImage -ImagePath $imagePath; $receipt.Detached = -not (Get-DiskImage -ImagePath $imagePath).Attached }
        catch { $_.Exception.Message | Set-Content -LiteralPath (Join-Path $request.OutputRoot 'detach-failure.txt') }
    }
    $receipt.Status = $status
    $receipt | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $request.OutputRoot 'fixture-receipt.json')
    $status | Set-Content -LiteralPath (Join-Path $request.OutputRoot 'status.txt')
    Stop-Transcript | Out-Null
}
