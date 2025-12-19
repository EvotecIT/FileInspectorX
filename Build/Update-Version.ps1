Import-Module PSPublishModule -Force

Get-ProjectVersion -Path "C:\Support\GitHub\FileInspectorX" -ExcludeFolders @('C:\Support\GitHub\FileInspectorX\Module\Artefacts') | Format-Table

Set-ProjectVersion -Path "C:\Support\GitHub\FileInspectorX" -NewVersion "1.0.4" -Verbose -ExcludeFolders @('C:\Support\GitHub\FileInspectorX\Module\Artefacts') #-WhatIf
