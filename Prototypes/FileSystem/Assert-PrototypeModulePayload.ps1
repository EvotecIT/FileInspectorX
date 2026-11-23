function Assert-PrototypeModulePayload {
    <#
    .SYNOPSIS
    Validates the known prototype manifest and every staged payload file before elevated import.
    .PARAMETER ModulePath
    Full path to the evaluation module manifest.
    .PARAMETER ScratchPrefix
    Exact configured scratch path with its trailing separator.
    #>
    param([Parameter(Mandatory)] [string] $ModulePath, [Parameter(Mandatory)] [string] $ScratchPrefix)

    Assert-PrototypeScratchPath -Path $ModulePath -ScratchPrefix $ScratchPrefix -RequireElevatedIsolation
    $stem = 'FileInspectorX.FileSystem.Prototype'
    if ([IO.Path]::GetFileName($ModulePath) -cne ($stem + '.psd1')) { throw 'Use the known prototype module manifest.' }
    $manifest = Import-PowerShellDataFile -LiteralPath $ModulePath -ErrorAction Stop
    if ($manifest.RootModule -cne ($stem + '.dll')) { throw 'The prototype manifest must name its local prototype DLL.' }
    foreach ($key in @('NestedModules', 'RequiredModules', 'RequiredAssemblies', 'ScriptsToProcess', 'TypesToProcess', 'FormatsToProcess')) {
        if ($manifest[$key]) { throw "Additional executable module payload is not permitted: $key" }
    }
    $directory = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($ModulePath))
    $allowed = @("$stem.psd1", "$stem.dll", "$stem.pdb", "$stem.deps.json")
    foreach ($entry in Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop) {
        if ($entry.PSIsContainer -or $entry.Name -cnotin $allowed) { throw 'Only the known prototype payload files may be staged together.' }
        Assert-PrototypeScratchPath -Path $entry.FullName -ScratchPrefix $ScratchPrefix -RequireElevatedIsolation
    }
    if (-not (Test-Path -LiteralPath (Join-Path $directory ($stem + '.dll')) -PathType Leaf)) { throw 'The staged prototype DLL is missing.' }
}
