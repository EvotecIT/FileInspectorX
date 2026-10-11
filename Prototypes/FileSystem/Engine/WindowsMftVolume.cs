using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace FileInspectorX.Prototypes.FileSystem;

/// <summary>Read-only Windows volume control calls. No sector reads, journal creation or filesystem mutation.</summary>
internal sealed class WindowsMftVolume : IDisposable
{
    private readonly SafeFileHandle _handle;
    internal long MftBytes { get; }
    internal long BytesRead { get; private set; }

    internal WindowsMftVolume(string volumeRoot, long maximumMftBytes)
    {
        if (maximumMftBytes <= 0) throw new ArgumentOutOfRangeException(nameof(maximumMftBytes));
        _handle = CreateFileW(@"\\.\" + volumeRoot.TrimEnd('\\'), 0x80000000, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
        if (_handle.IsInvalid) { int error = Marshal.GetLastWin32Error(); _handle.Dispose(); throw new Win32Exception(error); }
        try
        {
            var metadata = new byte[128];
            if (!DeviceIoControl(_handle, 0x90064, null, 0, metadata, metadata.Length, out int returned, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            if (returned < 96) throw new IOException("Truncated NTFS_VOLUME_DATA_BUFFER.");
            MftBytes = BitConverter.ToInt64(metadata, 56);
            if (MftBytes < 0) throw new IOException("Invalid MFT length.");
            if (MftBytes > maximumMftBytes) throw new NotSupportedException("MFT metadata length " + MftBytes + " exceeds the explicit volume-size guard " + maximumMftBytes + ".");
        }
        catch { _handle.Dispose(); throw; }
    }

    internal IEnumerable<UsnNode> Enumerate(CancellationToken cancellationToken)
    {
        var input = new byte[24]; // MFT_ENUM_DATA_V0: StartFileReferenceNumber, LowUsn, HighUsn.
        Buffer.BlockCopy(BitConverter.GetBytes(long.MaxValue), 0, input, 16, 8);
        var output = new byte[1024 * 1024];
        ulong start = 0;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Buffer.BlockCopy(BitConverter.GetBytes(start), 0, input, 0, 8);
            if (!DeviceIoControl(_handle, 0x900B3, input, input.Length, output, output.Length, out int returned, IntPtr.Zero))
            {
                int error = Marshal.GetLastWin32Error();
                if (error == 38) yield break; // ERROR_HANDLE_EOF.
                throw new Win32Exception(error);
            }
            if (returned < 8 || returned > output.Length) throw new IOException("Invalid MFT enumeration response length.");
            ulong next = BitConverter.ToUInt64(output, 0);
            if (next <= start) throw new IOException("MFT enumeration made no forward progress.");
            BytesRead = checked(BytesRead + returned);
            foreach (var node in UsnRecordParser.Parse(output, returned, cancellationToken)) yield return node;
            start = next;
        }
    }

    internal static ulong GetDirectoryId(string path)
    {
        using var handle = CreateFileW(path, 0, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero);
        if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
        var information = new byte[52];
        if (!GetFileInformationByHandle(handle, information)) throw new Win32Exception(Marshal.GetLastWin32Error());
        return ((ulong)BitConverter.ToUInt32(information, 44) << 32) | BitConverter.ToUInt32(information, 48);
    }

    public void Dispose() => _handle.Dispose();
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(SafeFileHandle handle, uint code, byte[]? input, int inputSize,
        [Out] byte[] output, int outputSize, out int returned, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, [Out] byte[] information);
}
