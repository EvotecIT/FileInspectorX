param([Parameter(Mandatory)] [string] $OutputRoot)
$ErrorActionPreference = 'Stop'
$commit = '1ec8aeb2950c082d31593791dcced249b2d201df'
$version = '0.1.0-mft-prototype.2'
$full = [IO.Path]::GetFullPath($OutputRoot)
if (-not [IO.Path]::IsPathRooted($OutputRoot) -or (Test-Path -LiteralPath $full)) { throw 'Use a new absolute task-owned evaluation directory.' }
if (-not (Test-Path -LiteralPath (Split-Path $full -Parent) -PathType Container)) { throw 'The intended mounted scratch parent must already exist.' }
$null = New-Item -ItemType Directory -Path $full
$archive = Join-Path $full 'reader-source.zip'
Invoke-WebRequest "https://codeload.github.com/itsWindows11/NtfsReader/zip/$commit" -OutFile $archive
Expand-Archive -LiteralPath $archive -DestinationPath (Join-Path $full 'source')
$source = Join-Path $full "source/NtfsReader-$commit"
git -C $source apply --check (Join-Path $PSScriptRoot 'reader-generic-read.patch')
if ($LASTEXITCODE) { throw 'Pinned source does not match the reviewed patch.' }
git -C $source apply (Join-Path $PSScriptRoot 'reader-generic-read.patch')
if ($LASTEXITCODE) { throw 'Reader evaluation patch failed.' }
$packages = Join-Path $full 'packages'
$feed = Join-Path $full 'feed'
$project = Join-Path $source 'src/NtfsReader/NtfsReader.csproj'
$projectText = Get-Content -LiteralPath $project -Raw
$frameworks = '<TargetFrameworks>netstandard2.0;net8.0;net9.0;net10.0</TargetFrameworks>'
if (-not $projectText.Contains($frameworks)) { throw 'Unexpected source target frameworks.' }
$projectText.Replace($frameworks, '<TargetFrameworks>netstandard2.0;net8.0</TargetFrameworks>') | Set-Content -LiteralPath $project -Encoding utf8
dotnet pack $project --output $feed --artifacts-path (Join-Path $full 'reader-artifacts') --source https://api.nuget.org/v3/index.json "-p:Version=$version" "-p:RestorePackagesPath=$packages" --nologo
if ($LASTEXITCODE) { throw 'Patched evaluation reader build failed.' }
$config = Join-Path $full 'NuGet.Config'
$feedXml = [Security.SecurityElement]::Escape($feed)
"<configuration><packageSources><clear/><add key='evaluation' value='$feedXml'/><add key='nuget.org' value='https://api.nuget.org/v3/index.json'/></packageSources></configuration>" | Set-Content -LiteralPath $config -Encoding utf8
dotnet build (Join-Path $PSScriptRoot 'FileInspectorX.FileSystem.Prototype.csproj') --artifacts-path (Join-Path $full 'prototype-artifacts') "-p:RestoreConfigFile=$config" "-p:PrototypeReaderVersion=$version" "-p:RestorePackagesPath=$packages" --nologo
if ($LASTEXITCODE) { throw 'Prototype build against isolated evaluation package failed.' }
[pscustomobject]@{ SourceCommit = $commit; PackageVersion = $version; License = 'LGPL-2.1-or-later'; ArchiveSha256 = (Get-FileHash $archive).Hash; PatchSha256 = (Get-FileHash (Join-Path $PSScriptRoot 'reader-generic-read.patch')).Hash } |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $full 'provenance.json')
