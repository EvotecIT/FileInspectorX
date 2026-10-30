function Assert-PrototypeScratchPath {
    <#
    .SYNOPSIS
    Rejects prototype inputs outside the exact configured scratch path or through reparse points.
    .PARAMETER Path
    Absolute input or output path to check before accessing it.
    .PARAMETER ScratchPrefix
    Full configured scratch directory path, including its trailing separator.
    #>
    param([Parameter(Mandatory)] [string] $Path, [Parameter(Mandatory)] [string] $ScratchPrefix)

    # Exact spelling deliberately rejects case variants, including distinct siblings on case-sensitive NTFS.
    if (-not [IO.Path]::IsPathRooted($Path) -or -not [IO.Path]::GetFullPath($Path).StartsWith($ScratchPrefix, [StringComparison]::Ordinal)) {
        throw 'All inputs and outputs must be inside the mounted configured scratch root, with its exact path spelling.'
    }
    for ($ancestor = [IO.Path]::GetFullPath($Path); $ancestor; $ancestor = Split-Path $ancestor -Parent) {
        if ((Test-Path -LiteralPath $ancestor) -and ((Get-Item -LiteralPath $ancestor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Reparse paths are not accepted by the elevated driver.'
        }
    }
}
