using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace FileInspectorX.Prototypes.FileSystem;

/// <summary>Read-only aligned metadata I/O. Physical access requires an unambiguous verified NTFS partition.</summary>
internal sealed class WindowsRawMftSource : IDisposable
{
    private readonly SafeFileHandle _handle;
    private readonly IntPtr _allocation, _buffer;
    private readonly long _baseOffset, _volumeBytes;
    private readonly int _sectorBytes;
    internal const int BufferBytes = 4 * 1024 * 1024;
    internal string Route { get; }
    internal int VolumeReadError { get; }
    internal long ReadCalls { get; private set; }
    internal long BytesRead { get; private set; }

    internal WindowsRawMftSource(SafeFileHandle volume, string volumeRoot, WindowsMftVolume geometry)
    {
        _sectorBytes = geometry.SectorBytes;
        _allocation = Marshal.AllocHGlobal(BufferBytes + 65536);
        _buffer = new IntPtr((_allocation.ToInt64() + 65535) & ~65535L);
        SafeFileHandle? opened = null;
        try
        {
            byte[] extents = new byte[64];
            if (!WindowsMftVolume.Control(volume, 0x560000, null, extents, out int returned))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot establish volume-to-disk mapping.");
            if (returned < 32 || BitConverter.ToUInt32(extents, 0) != 1)
                throw new NotSupportedException("Bulk reading requires a single physical partition extent.");
            int disk = BitConverter.ToInt32(extents, 8);
            long partition = BitConverter.ToInt64(extents, 16);
            _volumeBytes = BitConverter.ToInt64(extents, 24);
            if (disk < 0 || partition < 0 || _volumeBytes <= 0 || partition % _sectorBytes != 0 || _volumeBytes % _sectorBytes != 0)
                throw new IOException("Invalid partition mapping.");
            opened = Open(@"\\.\" + volumeRoot.TrimEnd('\\'));
            int error = Read(opened, 0, _sectorBytes);
            if (error == 0) { Route = "Volume"; _baseOffset = 0; }
            else
            {
                VolumeReadError = error;
                if (error != 50) throw new Win32Exception(error, "Volume metadata read failed.");
                opened.Dispose();
                opened = Open(@"\\.\PhysicalDrive" + disk);
                byte[] length = new byte[8];
                if (!WindowsMftVolume.Control(opened, 0x7405C, null, length, out returned) || returned < 8)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot establish physical-disk bounds.");
                if (checked(partition + _volumeBytes) > BitConverter.ToInt64(length, 0)) throw new IOException("Partition escapes its disk.");
                _baseOffset = partition; Route = "VerifiedPhysicalPartition";
                error = Read(opened, _baseOffset, _sectorBytes);
                if (error != 0) throw new Win32Exception(error, "Mapped NTFS boot read failed.");
            }
            var boot = new byte[_sectorBytes];
            Marshal.Copy(_buffer, boot, 0, boot.Length);
            if (System.Text.Encoding.ASCII.GetString(boot, 3, 8) != "NTFS    " ||
                BitConverter.ToInt64(boot, 72) != geometry.SerialNumber ||
                BitConverter.ToUInt16(boot, 11) != geometry.SectorBytes ||
                checked((int)boot[13] * geometry.SectorBytes) != geometry.ClusterBytes ||
                BitConverter.ToInt64(boot, 48) != geometry.MftStartCluster)
                throw new IOException("Raw partition metadata does not match the opened NTFS volume.");
            _handle = opened;
        }
        catch { opened?.Dispose(); Marshal.FreeHGlobal(_allocation); throw; }
    }

    internal void ReadVolume(long offset, byte[] target, int destination, int count)
    {
        if (offset < 0 || count <= 0 || destination < 0 || destination > target.Length - count || checked(offset + count) > _volumeBytes)
            throw new IOException("Metadata read escapes its verified partition or buffer.");
        long aligned = offset - offset % _sectorBytes;
        int prefix = checked((int)(offset - aligned));
        int length = checked((prefix + count + _sectorBytes - 1) / _sectorBytes * _sectorBytes);
        if (length > BufferBytes || checked(aligned + length) > _volumeBytes) throw new IOException("Invalid aligned metadata read size.");
        int error = Read(_handle, checked(_baseOffset + aligned), length);
        if (error != 0) throw new Win32Exception(error, "Bulk MFT read failed.");
        Marshal.Copy(IntPtr.Add(_buffer, prefix), target, destination, count);
        ReadCalls++; BytesRead = checked(BytesRead + length);
    }

    private static SafeFileHandle Open(string path)
    {
        var handle = CreateFileW(path, 0x80000000, 7, IntPtr.Zero, 3, 0x20000000, IntPtr.Zero);
        if (handle.IsInvalid) { int error = Marshal.GetLastWin32Error(); handle.Dispose(); throw new Win32Exception(error); }
        return handle;
    }

    private int Read(SafeFileHandle handle, long offset, int length)
    {
        if (!SetFilePointerEx(handle, offset, out long positioned, 0)) return Marshal.GetLastWin32Error();
        if (positioned != offset) throw new IOException("Metadata seek position mismatch.");
        if (!ReadFile(handle, _buffer, length, out int returned, IntPtr.Zero)) return Marshal.GetLastWin32Error();
        if (returned != length) throw new IOException("Short raw metadata read.");
        return 0;
    }

    public void Dispose() { _handle.Dispose(); Marshal.FreeHGlobal(_allocation); }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool ReadFile(SafeFileHandle handle, IntPtr buffer, int count, out int returned, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetFilePointerEx(SafeFileHandle handle, long offset, out long positioned, uint method);
}
