using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace FileInspectorX.Prototypes.FileSystem;

/// <summary>Read-only Windows volume control calls. No sector reads, journal creation or filesystem mutation.</summary>
internal sealed partial class WindowsMftVolume : IDisposable
{
    private readonly SafeFileHandle _handle;
    internal long MftBytes { get; }
    internal long BytesRead { get; private set; }
    internal int RecordBytes { get; }
    internal int SectorBytes { get; }
    internal int ClusterBytes { get; }
    internal long SerialNumber { get; }
    internal long MftStartCluster { get; }

    internal WindowsMftVolume(string volumeRoot, long maximumMftBytes, Action checkBudget)
    {
        if (maximumMftBytes <= 0) throw new ArgumentOutOfRangeException(nameof(maximumMftBytes));
        checkBudget();
        _handle = CreateFileW(@"\\.\" + volumeRoot.TrimEnd('\\'), 0x80000000, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
        if (_handle.IsInvalid) { int error = Marshal.GetLastWin32Error(); _handle.Dispose(); throw new Win32Exception(error); }
        try
        {
            var metadata = new byte[128];
            checkBudget();
            if (!DeviceIoControl(_handle, 0x90064, null, 0, metadata, metadata.Length, out int returned, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            if (returned < 96) throw new IOException("Truncated NTFS_VOLUME_DATA_BUFFER.");
            MftBytes = BitConverter.ToInt64(metadata, 56);
            RecordBytes = checked((int)BitConverter.ToUInt32(metadata, 48));
            SectorBytes = checked((int)BitConverter.ToUInt32(metadata, 40));
            ClusterBytes = checked((int)BitConverter.ToUInt32(metadata, 44));
            SerialNumber = BitConverter.ToInt64(metadata, 0);
            MftStartCluster = BitConverter.ToInt64(metadata, 64);
            if (ClusterBytes < SectorBytes || ClusterBytes % SectorBytes != 0)
                throw new NotSupportedException("Unsupported NTFS cluster geometry.");
            if (RecordBytes < 512 || RecordBytes > 65536 || RecordBytes % 512 != 0 || SectorBytes < 512 || SectorBytes > 65536 || (SectorBytes & (SectorBytes - 1)) != 0)
                throw new NotSupportedException("Unsupported NTFS file-record geometry.");
            if (returned < 104 || BitConverter.ToUInt16(metadata, 100) != 3 || BitConverter.ToUInt16(metadata, 102) > 1)
                throw new NotSupportedException("File-record decoder requires NTFS 3.0 or 3.1.");
            if (MftBytes < 0) throw new IOException("Invalid MFT length.");
            if (MftBytes > maximumMftBytes) throw new NotSupportedException("MFT metadata length " + MftBytes + " exceeds the explicit volume-size guard " + maximumMftBytes + ".");
        }
        catch { _handle.Dispose(); throw; }
    }

    internal IEnumerable<NtfsFileRecord> EnumerateFileRecords(CancellationToken cancellationToken)
    {
        if (MftBytes < RecordBytes || MftBytes % RecordBytes != 0) throw new IOException("Invalid MFT record count.");
        var input = new byte[8];
        var output = new byte[RecordBytes + 16];
        ulong requested = (ulong)(MftBytes / RecordBytes - 1);
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Buffer.BlockCopy(BitConverter.GetBytes(requested), 0, input, 0, 8);
            if (!DeviceIoControl(_handle, 0x90068, input, 8, output, output.Length, out int returned, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            if (returned < 12 || returned > output.Length) throw new IOException("Invalid file-record control response.");
            ulong slot = BitConverter.ToUInt64(output, 0) & NtfsFileRecordParser.SlotMask;
            if (slot > requested) throw new IOException("Descending file-record enumeration made no progress.");
            BytesRead = checked(BytesRead + returned);
            yield return NtfsFileRecordParser.Parse(output, returned, SectorBytes);
            if (slot == 0) yield break;
            requested = slot - 1;
        }
    }

    internal byte[] ReadLogicalRecord(ulong id)
    {
        byte[] output = new byte[RecordBytes + 16];
        if (!DeviceIoControl(_handle, 0x90068, BitConverter.GetBytes(id), 8, output, output.Length, out int returned, IntPtr.Zero))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        if (returned < 12 || BitConverter.ToUInt32(output, 8) != RecordBytes ||
            (BitConverter.ToUInt64(output, 0) & NtfsFileRecordParser.SlotMask) != (id & NtfsFileRecordParser.SlotMask))
            throw new IOException("MFT layout identity disappeared during acquisition.");
        return output;
    }

    internal static ulong GetDirectoryId(string path)
    {
        using var handle = CreateFileW(path, 0, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero);
        if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
        var information = new byte[52];
        if (!GetFileInformationByHandle(handle, information)) throw new Win32Exception(Marshal.GetLastWin32Error());
        return ((ulong)BitConverter.ToUInt32(information, 44) << 32) | BitConverter.ToUInt32(information, 48);
    }

    // The file-record header reference field is not a reliable live hardlink count on every volume.
    // Probe only contradictory records; metadata access is zero and no file contents are read.
    internal bool TryGetLinkCount(ulong id, out uint linkCount, out string? failure)
    {
        linkCount = 0;
        var descriptor = new FileIdDescriptor { Size = 24, Type = 0, Id = unchecked((long)id) };
        using var file = OpenFileById(_handle, ref descriptor, 0, 7, IntPtr.Zero, 0x02200000);
        if (file.IsInvalid) { failure = "OpenFileById failed with Win32 error " + Marshal.GetLastWin32Error() + "."; return false; }
        var information = new byte[52];
        if (!GetFileInformationByHandle(file, information))
        { failure = "Link metadata failed with Win32 error " + Marshal.GetLastWin32Error() + "."; return false; }
        ulong actualId = ((ulong)BitConverter.ToUInt32(information, 44) << 32) | BitConverter.ToUInt32(information, 48);
        if (actualId != id) { failure = "File identity changed during link validation."; return false; }
        linkCount = BitConverter.ToUInt32(information, 40);
        failure = null;
        return true;
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
    [StructLayout(LayoutKind.Explicit, Size = 24)]
    private struct FileIdDescriptor
    {
        [FieldOffset(0)] internal uint Size;
        [FieldOffset(4)] internal uint Type;
        [FieldOffset(8)] internal long Id;
    }
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeFileHandle OpenFileById(SafeFileHandle volume, ref FileIdDescriptor id,
        uint access, uint share, IntPtr security, uint flags);
}
