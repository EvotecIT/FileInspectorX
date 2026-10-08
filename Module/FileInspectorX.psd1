@{
    AliasesToExport      = @()
    Author               = 'Przemyslaw Klys'
    CmdletsToExport      = @('Get-FileInsight')
    CompanyName          = 'Evotec'
    CompatiblePSEditions = @('Desktop', 'Core')
    Copyright            = '(c) 2011 - 2026 Przemyslaw Klys @ Evotec. All rights reserved.'
    Description          = 'Detects file types from content and analyzes files, signatures, permissions, containers and installer metadata. Accepts file paths and pipeline input from Get-ChildItem.'
    FunctionsToExport    = @()
    GUID                 = 'bb5de776-1f68-4af0-8d68-5c0fa2ab3cf9'
    ModuleVersion        = '1.1.2'
    PowerShellVersion    = '5.1'
    PrivateData          = @{
        PSData = @{
            ProjectUri                 = 'https://github.com/EvotecIT/FileInspectorX'
            RequireLicenseAcceptance   = $false
            Tags                       = @('Windows', 'MacOS', 'Linux')
            ExternalModuleDependencies = @()
        }
    }
    RootModule           = 'FileInspectorX.psm1'
    RequiredModules      = @()
    ScriptsToProcess     = @()
}
