param([Parameter(Mandatory)] [string] $Root, [ValidateRange(1, 50000)] [int] $Files = 10000)
$ErrorActionPreference = 'Stop'
$full = [IO.Path]::GetFullPath($Root)
if (-not [IO.Path]::IsPathRooted($Root) -or (Test-Path -LiteralPath $full)) { throw 'Choose a new absolute task-owned fixture directory.' }
if (-not (Test-Path -LiteralPath (Split-Path $full -Parent) -PathType Container)) { throw 'Fixture parent must already exist on the intended mounted volume.' }
$null = [IO.Directory]::CreateDirectory($full)
$bytes = [byte[]](1,2,3,4,5,6,7,8)
for ($i = 0; $i -lt $Files; $i++) {
    $directory = Join-Path $full ('level-' + ($i % 10) + '/group-' + ($i % 100))
    $null = [IO.Directory]::CreateDirectory($directory)
    [IO.File]::WriteAllBytes((Join-Path $directory ("file-{0:D6}.txt" -f $i)), $bytes)
}
$full
