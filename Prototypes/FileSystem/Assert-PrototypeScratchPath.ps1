function Assert-PrototypeScratchPath {
    <#
    .SYNOPSIS
    Rejects prototype inputs outside the exact configured scratch path or through reparse points.
    .PARAMETER Path
    Absolute input or output path to check before accessing it.
    .PARAMETER ScratchPrefix
    Full configured scratch directory path, including its trailing separator.
    .PARAMETER RequireElevatedIsolation
    Requires existing paths and ancestors to be owned and writable only by SYSTEM or Administrators.
    #>
    param([Parameter(Mandatory)] [string] $Path, [Parameter(Mandatory)] [string] $ScratchPrefix,
        [switch] $RequireElevatedIsolation)

    # Exact spelling deliberately rejects case variants, including distinct siblings on case-sensitive NTFS.
    if (-not [IO.Path]::IsPathRooted($Path) -or -not [IO.Path]::GetFullPath($Path).StartsWith($ScratchPrefix, [StringComparison]::Ordinal)) {
        throw 'All inputs and outputs must be inside the mounted configured scratch root, with its exact path spelling.'
    }
    for ($ancestor = [IO.Path]::GetFullPath($Path); $ancestor; $ancestor = Split-Path $ancestor -Parent) {
        if ((Test-Path -LiteralPath $ancestor) -and ((Get-Item -LiteralPath $ancestor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Reparse paths are not accepted by the elevated driver.'
        }
    }
    if ($RequireElevatedIsolation) {
        # Check from the volume down: a protected child is not safe below a replaceable parent.
        $ancestors = [Collections.Generic.List[string]]::new()
        for ($ancestor = [IO.Path]::GetFullPath($Path); $ancestor; $ancestor = Split-Path $ancestor -Parent) {
            if (Test-Path -LiteralPath $ancestor) { $ancestors.Insert(0, $ancestor) }
        }
        $trusted = @('S-1-5-18', 'S-1-5-32-544') # SYSTEM and the elevated Administrators group.
        $writes = [Security.AccessControl.FileSystemRights]'Write,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'
        foreach ($ancestor in $ancestors) {
            if ((Get-Item -LiteralPath $ancestor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw 'Reparse paths are not accepted by the elevated driver.'
            }
            $acl = Get-Acl -LiteralPath $ancestor -ErrorAction Stop
            $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All))
            if ($null -eq $descriptor.DiscretionaryAcl) {
                throw 'Elevated comparisons require an explicit restrictive staging DACL.'
            }
            if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) {
                throw 'Elevated comparisons require SYSTEM/Administrators-owned staging paths and ancestors.'
            }
            foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
                # Include inheritable entries: newly created output/temp children must also stay protected.
                if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
                    ($rule.FileSystemRights -band $writes) -and $rule.IdentityReference.Value -notin $trusted) {
                    throw 'Elevated comparisons require staging paths and ancestors writable only by SYSTEM/Administrators.'
                }
            }
        }
    }
}
