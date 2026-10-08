Import-Module FileInspectorX

# Analyze a single file
Get-FileInsight -Path .\sample.txt | Format-List

Get-FileInsight -Path .\sample.txt -View Permissions | Format-List

# Detect only (skip analysis) for all EXE files in current folder
Get-ChildItem -Filter *.exe -File -Recurse | Get-FileInsight -View Detection | Format-Table -AutoSize

# Read MSI product metadata on Windows
Get-FileInsight -Path .\package.msi -View Installer -EnableInstaller | Format-List
