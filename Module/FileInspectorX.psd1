@{
    AliasesToExport      = @()
    Author               = 'Przemyslaw Klys'
    CmdletsToExport      = @('Get-FileInsight')
    CompanyName          = 'Evotec'
    CompatiblePSEditions = @('Desktop', 'Core')
    Copyright            = '(c) 2011 - 2026 Przemyslaw Klys @ Evotec. All rights reserved.'
    Description          = 'FileInspectorX is PowerShell module that allows you to query files and folders for information. It supports multiple types of file queries and can be used to query local file systems, network shares.'
    FunctionsToExport    = @()
    GUID                 = 'bb5de776-1f68-4af0-8d68-5c0fa2ab3cf9'
    ModuleVersion        = '1.0.7'
    PowerShellVersion    = '5.1'
    PrivateData          = @{
        PSData = @{
            ProjectUri               = 'https://github.com/EvotecIT/FileInspectorX'
            RequireLicenseAcceptance = $false
            Tags                     = @('Windows', 'MacOS', 'Linux')
        }
    }
    RootModule           = 'FileInspectorX.psm1'
}