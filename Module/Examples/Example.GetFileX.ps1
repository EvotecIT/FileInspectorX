# Example usages of FileInspectorX PowerShell wrapper

# Analyze a single file
Get-FileInsight -Path "$PSScriptRoot/../../README.MD" -ErrorAction SilentlyContinue

# Detect only (skip analysis) for all EXE files in current folder
Get-ChildItem -Filter *.exe -File -Recurse -ErrorAction SilentlyContinue |
    ForEach-Object { Get-FileInsight -Path $_.FullName -DetectOnly }

