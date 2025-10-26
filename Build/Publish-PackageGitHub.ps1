$GitHubAccessToken = Get-Content -Raw 'C:\Support\Important\GithubAPI.txt'

$publishGitHubReleaseAssetSplat = @{
    ProjectPath          = "$PSScriptRoot\..\FileInspectorX"
    GitHubAccessToken    = $GitHubAccessToken
    GitHubUsername       = "EvotecIT"
    GitHubRepositoryName = "FileInspectorX"
    IsPreRelease         = $false
}

Publish-GitHubReleaseAsset @publishGitHubReleaseAssetSplat
