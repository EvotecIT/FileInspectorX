using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;

namespace FileInspectorX;

/// <summary>Distinguishes filesystem links from storage and cloud reparse points.</summary>
internal static class FileSystemLinks
{
    internal static bool? IsLink(string path, FileAttributes attributes)
    {
        if ((attributes & FileAttributes.ReparsePoint) == 0) return false;
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return true;

        // Windows reparse points also represent cloud placeholders and storage filters.
        // FindFirstFile reports the tag without opening the target or hydrating its content.
        string fullPath = Path.GetFullPath(path);
        string root = Path.GetPathRoot(fullPath)!;
        if (fullPath.Length > root.Length) fullPath = fullPath.TrimEnd('\\', '/');
        if (!fullPath.StartsWith("\\\\?\\", StringComparison.Ordinal))
            fullPath = fullPath.StartsWith("\\\\", StringComparison.Ordinal)
                ? "\\\\?\\UNC\\" + fullPath.Substring(2) : "\\\\?\\" + fullPath;
        using var handle = FindFirstFile(fullPath, out var data);
        if (handle.IsInvalid) return null;
        if ((data.Attributes & (uint)FileAttributes.ReparsePoint) == 0) return false;
        return IsNameSurrogate(data.ReparseTag);
    }

    internal static bool IsNameSurrogate(uint reparseTag) => (reparseTag & 0x20000000u) != 0;

    [DllImport("kernel32.dll", EntryPoint = "FindFirstFileW", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern FindHandle FindFirstFile(string path, out FindData data);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FindClose(IntPtr handle);

    private sealed class FindHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private FindHandle() : base(true) { }
        protected override bool ReleaseHandle() => FindClose(handle);
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct FindData
    {
        internal uint Attributes;
        internal System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        internal System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        internal System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        internal uint FileSizeHigh;
        internal uint FileSizeLow;
        internal uint ReparseTag;
        internal uint Reserved;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] internal string FileName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)] internal string AlternateFileName;
    }
}
