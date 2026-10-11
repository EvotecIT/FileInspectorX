using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace FileInspectorX.Prototypes.FileSystem;

/// <summary>Read-only raw-volume access and metadata budget check, with preserved Win32 error codes.</summary>
internal static class VolumePreflight
{
    internal static long Check(string volumeRoot, long maximumMftBytes)
    {
        if (maximumMftBytes <= 0) throw new ArgumentOutOfRangeException(nameof(maximumMftBytes));
        using var handle = CreateFileW(@"\\.\" + volumeRoot.TrimEnd('\\'), 0x80000000, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
        if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
        var metadata = new byte[96]; // NTFS_VOLUME_DATA_BUFFER: five LARGE_INTEGERs, four DWORDs, five LARGE_INTEGERs.
        if (!DeviceIoControl(handle, 0x90064, IntPtr.Zero, 0, metadata, metadata.Length, out int returned, IntPtr.Zero))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        if (returned < 64) throw new IOException("Truncated NTFS_VOLUME_DATA_BUFFER.");
        long bytes = BitConverter.ToInt64(metadata, 56);
        if (bytes < 0) throw new IOException("Invalid MFT length.");
        if (bytes > maximumMftBytes)
            throw new NotSupportedException("MFT metadata length " + bytes + " exceeds the explicit capture budget " + maximumMftBytes + ".");
        return bytes;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security,
        uint creation, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(SafeFileHandle handle, uint code, IntPtr input, int inputSize,
        [Out] byte[] output, int outputSize, out int returned, IntPtr overlapped);
}
