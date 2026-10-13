using System.Security.Cryptography;

namespace FileInspectorX;

/// <summary>One exact, hash-bound snapshot; larger inputs use a private delete-on-close file.</summary>
internal sealed class ReportSnapshot : IDisposable
{
    internal Stream Stream { get; private set; } = new MemoryStream();
    internal string Sha256 { get; private set; } = string.Empty;
    internal long Length => Stream.Length;

    internal static ReportSnapshot Capture(Stream input, InspectionReportOptions options, CancellationToken token)
    {
        var snapshot = new ReportSnapshot();
        try
        {
            using var hash = SHA256.Create();
            var buffer = new byte[8192];
            while (true)
            {
                token.ThrowIfCancellationRequested();
                var count = input.Read(buffer, 0, (int)Math.Min(buffer.Length, (long)options.MaxInputBytes - snapshot.Length + 1));
                if (count == 0) break;
                if (snapshot.Length + count > options.MaxInputBytes) throw new InvalidDataException("report:input-size-limit");
                if (snapshot.Stream is MemoryStream memory && memory.Length + count > options.MaxMemorySnapshotBytes)
                {
                    var disk = OpenPrivateFile(options.SnapshotDirectory);
                    try { memory.Position = 0; memory.CopyTo(disk); }
                    catch { disk.Dispose(); throw; }
                    snapshot.Stream = disk; memory.Dispose();
                }
                snapshot.Stream.Write(buffer, 0, count);
                hash.TransformBlock(buffer, 0, count, buffer, 0);
            }
            token.ThrowIfCancellationRequested();
            hash.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            snapshot.Sha256 = BitConverter.ToString(hash.Hash!).Replace("-", string.Empty).ToLowerInvariant();
            snapshot.Stream.Position = 0;
            return snapshot;
        }
        catch { snapshot.Dispose(); throw; }
    }

    private static FileStream OpenPrivateFile(string? directory)
    {
        var root = directory ?? Path.GetTempPath();
        if (!Directory.Exists(root)) throw new DirectoryNotFoundException("The report snapshot directory does not exist.");
        var path = Path.Combine(root, "FileInspectorX-" + Guid.NewGuid().ToString("N") + ".snapshot");
#if NET8_0_OR_GREATER
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.ReadWrite, Share = FileShare.None,
            BufferSize = 8192, Options = FileOptions.DeleteOnClose | FileOptions.RandomAccess };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        return new FileStream(path, options);
#else
        if (Environment.OSVersion.Platform != PlatformID.Win32NT)
            throw new PlatformNotSupportedException("Private disk snapshots require .NET 8 or Windows. Keep the input within the memory snapshot budget on this runtime.");
        // Windows uses the configured user temporary-directory ACL plus exclusive ownership.
        return new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 8192,
            FileOptions.DeleteOnClose | FileOptions.RandomAccess);
#endif
    }

    public void Dispose() => Stream.Dispose();
}
