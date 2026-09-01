param(
    [ValidateSet('Manifest', 'Documentation', 'Build', 'Publish')]
    [string] $ConfigurationGateMode = 'Build',

    [bool] $SignModule = $true,

    [string] $ProjectBuildConfigPath = '..\Build\project.build.json',

    [string] $PowerShellGalleryApiKeyPath = 'C:\Support\Important\PowerShellGalleryAPI.txt',

    [string] $GitHubApiKeyPath = 'C:\Support\Important\GitHubAPI.txt'
)

Import-Module PSPublishModule -MinimumVersion '3.0.98' -Force -ErrorAction Stop

Build-Module -ModuleName 'FileInspectorX' {
    # Usual defaults as per standard module
    $Manifest = [ordered] @{
        ModuleVersion        = '1.1.X'
        CompatiblePSEditions = @('Desktop', 'Core')
        GUID                 = 'bb5de776-1f68-4af0-8d68-5c0fa2ab3cf9'
        Author               = 'Przemyslaw Klys'
        CompanyName          = 'Evotec'
        Copyright            = "(c) 2011 - $((Get-Date).Year) Przemyslaw Klys @ Evotec. All rights reserved."
        Description          = 'FileInspectorX is PowerShell module that allows you to query files and folders for information. It supports multiple types of file queries and can be used to query local file systems, network shares.'
        Tags                 = @('Windows', 'MacOS', 'Linux')
        #IconUri              = ''
        ProjectUri           = 'https://github.com/EvotecIT/FileInspectorX'
        PowerShellVersion    = '5.1'
    }
    New-ConfigurationManifest @Manifest


    $ConfigurationFormat = [ordered] @{
        RemoveComments                              = $false

        PlaceOpenBraceEnable                        = $true
        PlaceOpenBraceOnSameLine                    = $true
        PlaceOpenBraceNewLineAfter                  = $true
        PlaceOpenBraceIgnoreOneLineBlock            = $false

        PlaceCloseBraceEnable                       = $true
        PlaceCloseBraceNewLineAfter                 = $false
        PlaceCloseBraceIgnoreOneLineBlock           = $false
        PlaceCloseBraceNoEmptyLineBefore            = $true

        UseConsistentIndentationEnable              = $true
        UseConsistentIndentationKind                = 'space'
        UseConsistentIndentationPipelineIndentation = 'IncreaseIndentationAfterEveryPipeline'
        UseConsistentIndentationIndentationSize     = 4

        UseConsistentWhitespaceEnable               = $true
        UseConsistentWhitespaceCheckInnerBrace      = $true
        UseConsistentWhitespaceCheckOpenBrace       = $true
        UseConsistentWhitespaceCheckOpenParen       = $true
        UseConsistentWhitespaceCheckOperator        = $true
        UseConsistentWhitespaceCheckPipe            = $true
        UseConsistentWhitespaceCheckSeparator       = $true

        AlignAssignmentStatementEnable              = $true
        AlignAssignmentStatementCheckHashtable      = $true

        UseCorrectCasingEnable                      = $true
    }
    # format PSD1 and PSM1 files when merging into a single file
    # enable formatting is not required as Configuration is provided
    New-ConfigurationFormat -ApplyTo 'OnMergePSM1', 'OnMergePSD1' -Sort None @ConfigurationFormat
    # format PSD1 and PSM1 files within the module
    # enable formatting is required to make sure that formatting is applied (with default settings)
    New-ConfigurationFormat -ApplyTo 'DefaultPSD1', 'DefaultPSM1' -EnableFormatting -Sort None
    # when creating PSD1 use special style without comments and with only required parameters
    New-ConfigurationFormat -ApplyTo 'DefaultPSD1', 'OnMergePSD1' -PSD1Style 'Minimal'

    # configuration for documentation, at the same time it enables documentation processing
    New-ConfigurationDocumentation -Enable -PathReadme 'Docs\Readme.md' -Path 'Docs' -SyncExternalHelpToProjectRoot

    New-ConfigurationImportModule -ImportSelf -ImportRequiredModules

    New-ConfigurationInformation `
        -IncludeRoot '*.psm1', '*.psd1', '*.Libraries.ps1', 'License*', 'THIRD-PARTY-NOTICES.md' `
        -IncludeAll 'Images', 'Resources', 'Templates', 'Bin', 'Lib', 'en-US', 'THIRD-PARTY-LICENSES'

    $newConfigurationBuildSplat = @{
        Enable                            = $true
        SignModule                        = $SignModule
        MergeModuleOnBuild                = $true
        MergeFunctionsFromApprovedModules = $true
        CertificateThumbprint             = '92E95FB58EFFA6A4A75E77A33CDD6BFE6DD30F1A'
        NETProjectPath                    = '..\FileInspectorX.PowerShell\FileInspectorX.PowerShell.csproj'
        ResolveBinaryConflicts            = $true
        ResolveBinaryConflictsName        = 'FileInspectorX.PowerShell'
        NETProjectName                    = 'FileInspectorX.PowerShell'
        NETBinaryModule                   = 'FileInspectorX.PowerShell.dll'
        NETConfiguration                  = 'Release'
        NETFramework                      = 'net472', 'net8.0'
        NETHandleRuntimes                 = $true
        DotSourceLibraries                = $true
        NETSearchClass                    = 'FileInspectorX.PowerShell.CmdletGetFileInsight'
        NETBinaryModuleDocumentation      = $true
        RefreshPSD1Only                   = if ([string]::IsNullOrWhiteSpace($Env:RefreshPSD1Only)) { $false } else { [bool]::Parse($Env:RefreshPSD1Only) }
    }

    New-ConfigurationBuild @newConfigurationBuildSplat

    New-ConfigurationProjectBuild -Name 'FileInspectorX' -ConfigPath $ProjectBuildConfigPath -Enabled -BuildBeforeModule -UseAsReleaseVersionSource -ProvideLocalNuGetFeed -PublishNuget
    New-ConfigurationRelease -StageRoot '..\Artefacts\UploadReady' -VersionSource ProjectBuild -PrimaryProject 'FileInspectorX' -SynchronizeModuleVersion -BuildOrder 'Packages', 'Module' -PublishOrder 'NuGet', 'PowerShellGallery', 'GitHub'

    New-ConfigurationArtefact -Type Unpacked -Enable -Path '..\Artefacts\Unpacked' -ModulesPath '..\Artefacts\Unpacked\Modules' -RequiredModulesPath '..\Artefacts\Unpacked\Modules'
    New-ConfigurationArtefact -Type Packed -Enable -Path '..\Artefacts\Packed' -ModulesPath '..\Artefacts\Packed\Modules' -IncludeTagName -ArtefactName 'FileInspectorX-PowerShellModule.<TagModuleVersionWithPreRelease>.zip' -ID 'ToGitHub'

    New-ConfigurationPublish -Type PowerShellGallery -FilePath $PowerShellGalleryApiKeyPath -Enabled:$false
    New-ConfigurationPublish -Type GitHub -FilePath $GitHubApiKeyPath -UserName 'EvotecIT' -RepositoryName 'FileInspectorX' -Enabled:$false -GenerateReleaseNotes -OverwriteTagName 'FileInspectorX-PowerShellModule.<TagModuleVersionWithPreRelease>'

    New-ConfigurationGate -Mode $ConfigurationGateMode
} -ExitCode
