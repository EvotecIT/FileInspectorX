param(
    [string] $ConfigPath = "$PSScriptRoot\project.build.json",
    [Nullable[bool]] $UpdateVersions = $false,
    [Nullable[bool]] $Build = $true,
    [Nullable[bool]] $PublishNuget = $true,
    [Nullable[bool]] $PublishGitHub = $false,
    [Nullable[bool]] $Plan,
    [string] $PlanPath
)

& "$PSScriptRoot\Build-Project.ps1" `
    -ConfigPath $ConfigPath `
    -UpdateVersions:$UpdateVersions `
    -Build:$Build `
    -PublishNuget:$PublishNuget `
    -PublishGitHub:$PublishGitHub `
    -Plan:$Plan `
    -PlanPath $PlanPath
