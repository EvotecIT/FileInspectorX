Import-Module $PSScriptRoot\..\FileInspectorX.psd1 -Force

# Analyze a single file
Get-FileInsight -Path "$PSScriptRoot/../../README.MD" | Format-List

Get-FileInsight -Path "README.MD" -View Permissions | Format-List

# Detect only (skip analysis) for all EXE files in current folder
Get-ChildItem -Filter *.exe -File -Recurse | ForEach-Object { Get-FileInsight -Path $_.FullName -DetectOnly } | Format-Table *

#Get-FileInsight