using System.Runtime.InteropServices;

namespace FileInspectorX;

/// <summary>
/// Cross-platform permission and ownership snapshot helpers (Unix modes; Windows ACL summaries).
/// </summary>
public static partial class FileInspector
{
    private static FileSecurity BuildFileSecurity(string path)
    {
        var info = new FileSecurity();
        try {
            var attrs = File.GetAttributes(path);
            info.IsHidden = (attrs & FileAttributes.Hidden) != 0;
            info.IsReadOnly = (attrs & FileAttributes.ReadOnly) != 0;
            info.IsSymlink = (attrs & FileAttributes.ReparsePoint) != 0;
        } catch { }

#if NET8_0_OR_GREATER
        try {
            if (!info.IsSymlink.HasValue || info.IsSymlink == false) {
                var fi = new FileInfo(path);
                if (fi.LinkTarget is not null) info.IsSymlink = true;
            }
        } catch { }
#endif

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) {
            PopulateWindowsAcl(path, info);
        } else {
            PopulateUnixMode(path, info);
            TryPopulateUnixOwnerGroupWithStat(path, info);
        }
        return info;
    }

    private static void PopulateUnixMode(string path, FileSecurity info)
    {
#if NET8_0_OR_GREATER
        try {
            var mode = File.GetUnixFileMode(path);
            info.ModeOctal = ToOctal(mode);
            info.ModeSymbolic = ToSymbolic(mode);
            info.IsExecutable = (mode & (UnixFileMode.UserExecute | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute)) != 0;
            info.IsWorldWritable = (mode & UnixFileMode.OtherWrite) != 0;
        } catch { }
#endif
    }

    private static void PopulateWindowsAcl(string path, FileSecurity info)
    {
#if NET8_0_OR_GREATER || NET472
        try {
            var fi = new FileInfo(path);
            var fs = fi.GetAccessControl();
            // Owner
            try {
                var ownerRef = fs.GetOwner(typeof(System.Security.Principal.SecurityIdentifier));
                if (ownerRef is System.Security.Principal.SecurityIdentifier ownerSid) {
                    info.OwnerId = ownerSid.Value;
                    try {
                        var nt = (System.Security.Principal.NTAccount?)ownerSid.Translate(typeof(System.Security.Principal.NTAccount));
                        if (nt != null) info.Owner = nt.Value;
                    } catch { }
                }
            } catch { }

            // Group (primary group)
            try {
                var grpRef = fs.GetGroup(typeof(System.Security.Principal.SecurityIdentifier));
                if (grpRef is System.Security.Principal.SecurityIdentifier grpSid) {
                    info.GroupId = grpSid.Value;
                    try {
                        var ntg = (System.Security.Principal.NTAccount?)grpSid.Translate(typeof(System.Security.Principal.NTAccount));
                        if (ntg != null) info.Group = ntg.Value;
                    } catch { }
                }
            } catch { }

            // Quick ACL checks: Everyone/Authenticated Users write allowed
            try {
                var rules = fs.GetAccessRules(includeExplicit: true, includeInherited: true, targetType: typeof(System.Security.Principal.SecurityIdentifier));
                bool everyoneWrite = false, authUsersWrite = false, everyoneRead = false;
                bool usersWrite = false, usersRead = false, adminsWrite = false, adminsRead = false;
                bool hasDeny = false;
                int allow = 0, deny = 0, expAllow = 0, expDeny = 0;
                var sidUsers = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinUsersSid, null);
                var sidAdmins = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null);
                var entries = new List<FileAce>(16);
                foreach (System.Security.AccessControl.FileSystemAccessRule r in rules) {
                    var sid = (System.Security.Principal.SecurityIdentifier)r.IdentityReference;
                    var rights = r.FileSystemRights;
                    bool isAllow = r.AccessControlType == System.Security.AccessControl.AccessControlType.Allow;
                    bool isInherited = r.IsInherited;
                    if (isAllow) { allow++; if (!isInherited) expAllow++; } else { deny++; if (!isInherited) expDeny++; hasDeny = true; }

                    bool grantsWrite = (rights & (System.Security.AccessControl.FileSystemRights.Write | System.Security.AccessControl.FileSystemRights.Modify | System.Security.AccessControl.FileSystemRights.FullControl | System.Security.AccessControl.FileSystemRights.WriteData)) != 0;
                    bool grantsRead = (rights & (System.Security.AccessControl.FileSystemRights.Read | System.Security.AccessControl.FileSystemRights.ReadAndExecute | System.Security.AccessControl.FileSystemRights.ListDirectory | System.Security.AccessControl.FileSystemRights.ReadAttributes)) != 0;
                    bool grantsExec = (rights & (System.Security.AccessControl.FileSystemRights.ExecuteFile | System.Security.AccessControl.FileSystemRights.ReadAndExecute)) != 0;
                    bool grantsFull = (rights & System.Security.AccessControl.FileSystemRights.FullControl) != 0;

                    if (sid.IsWellKnown(System.Security.Principal.WellKnownSidType.WorldSid)) { if (grantsWrite && isAllow) everyoneWrite = true; if (grantsRead && isAllow) everyoneRead = true; }
                    if (sid.IsWellKnown(System.Security.Principal.WellKnownSidType.AuthenticatedUserSid)) { if (grantsWrite && isAllow) authUsersWrite = true; }
                    if (sid == sidUsers) { if (grantsWrite && isAllow) usersWrite = true; if (grantsRead && isAllow) usersRead = true; }
                    if (sid == sidAdmins) { if (grantsWrite && isAllow) adminsWrite = true; if (grantsRead && isAllow) adminsRead = true; }

                    // Build simplified ACE entry
                    var parts = new System.Collections.Generic.List<string>(4);
                    if (grantsRead) parts.Add("Read");
                    if (grantsWrite) parts.Add("Write");
                    if (grantsExec) parts.Add("Execute");
                    if (!grantsFull && (rights & System.Security.AccessControl.FileSystemRights.Modify) != 0) parts.Add("Modify");
                    string rightsLabel = grantsFull ? "FullControl" : string.Join(",", parts);
                    string principalName = sid.Translate(typeof(System.Security.Principal.NTAccount)) is System.Security.Principal.NTAccount nt ? nt.Value : sid.Value;
                    entries.Add(new FileAce {
                        AccessControlType = isAllow ? "Allow" : "Deny",
                        Principal = principalName,
                        PrincipalSid = sid.Value,
                        Rights = rightsLabel,
                        RawRights = rights.ToString(),
                        IsInherited = isInherited
                    });
                }
                info.EveryoneWriteAllowed = everyoneWrite;
                info.AuthenticatedUsersWriteAllowed = authUsersWrite;
                info.EveryoneReadAllowed = everyoneRead;
                info.BuiltinUsersWriteAllowed = usersWrite;
                info.BuiltinUsersReadAllowed = usersRead;
                info.AdministratorsWriteAllowed = adminsWrite;
                info.AdministratorsReadAllowed = adminsRead;
                info.HasDenyEntries = hasDeny;
                info.TotalAllowCount = allow;
                info.TotalDenyCount = deny;
                info.ExplicitAllowCount = expAllow;
                info.ExplicitDenyCount = expDeny;
                info.AclEntries = entries;
            } catch { }
        } catch { }
#endif
    }

#if NET8_0_OR_GREATER
    private static string ToOctal(UnixFileMode mode)
    {
        int bits = 0;
        if ((mode & UnixFileMode.UserRead) != 0) bits |= 0b100_000_000;
        if ((mode & UnixFileMode.UserWrite) != 0) bits |= 0b010_000_000;
        if ((mode & UnixFileMode.UserExecute) != 0) bits |= 0b001_000_000;
        if ((mode & UnixFileMode.GroupRead) != 0) bits |= 0b000_100_000;
        if ((mode & UnixFileMode.GroupWrite) != 0) bits |= 0b000_010_000;
        if ((mode & UnixFileMode.GroupExecute) != 0) bits |= 0b000_001_000;
        if ((mode & UnixFileMode.OtherRead) != 0) bits |= 0b000_000_100;
        if ((mode & UnixFileMode.OtherWrite) != 0) bits |= 0b000_000_010;
        if ((mode & UnixFileMode.OtherExecute) != 0) bits |= 0b000_000_001;
        // Convert permissions to octal (ignore special bits for simplicity)
        int u = (bits >> 6) & 0x7, g = (bits >> 3) & 0x7, o = bits & 0x7;
        return $"0{u}{g}{o}";
    }

    private static string ToSymbolic(UnixFileMode mode)
    {
        char[] c = new char[9];
        c[0] = (mode & UnixFileMode.UserRead) != 0 ? 'r' : '-';
        c[1] = (mode & UnixFileMode.UserWrite) != 0 ? 'w' : '-';
        c[2] = (mode & UnixFileMode.UserExecute) != 0 ? 'x' : '-';
        c[3] = (mode & UnixFileMode.GroupRead) != 0 ? 'r' : '-';
        c[4] = (mode & UnixFileMode.GroupWrite) != 0 ? 'w' : '-';
        c[5] = (mode & UnixFileMode.GroupExecute) != 0 ? 'x' : '-';
        c[6] = (mode & UnixFileMode.OtherRead) != 0 ? 'r' : '-';
        c[7] = (mode & UnixFileMode.OtherWrite) != 0 ? 'w' : '-';
        c[8] = (mode & UnixFileMode.OtherExecute) != 0 ? 'x' : '-';
        return new string(c);
    }
#endif
    
    private static void TryPopulateUnixOwnerGroupWithStat(string path, FileSecurity info)
    {
#if NET8_0_OR_GREATER
        try {
            // Linux: stat -c "%u %g %U %G" path
            // macOS: stat -f "%u %g %Su %Sg" path
            bool isOsx = RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
            string fileName = "/usr/bin/stat";
            if (!File.Exists(fileName)) fileName = "stat"; // fallback in PATH
            var psi = new System.Diagnostics.ProcessStartInfo {
                FileName = fileName,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            psi.ArgumentList.Add(isOsx ? "-f" : "-c");
            psi.ArgumentList.Add(isOsx ? "%u %g %Su %Sg" : "%u %g %U %G");
            psi.ArgumentList.Add(path);
            using var p = System.Diagnostics.Process.Start(psi)!;
            string output = p.StandardOutput.ReadToEnd();
            p.WaitForExit(1500);
            var parts = output.Trim().Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 4) {
                info.OwnerId = parts[0];
                info.GroupId = parts[1];
                info.Owner = parts[2] == "?" || parts[2] == "-" ? info.Owner : parts[2];
                info.Group = parts[3] == "?" || parts[3] == "-" ? info.Group : parts[3];
            }
        } catch { }
#endif
    }

}
