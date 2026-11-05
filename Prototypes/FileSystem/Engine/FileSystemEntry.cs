namespace FileInspectorX.Prototypes.FileSystem;

/// <summary>Metadata snapshot with familiar filesystem properties, without FileInfo mutation methods.</summary>
public sealed class FileSystemEntry
{
    public string FullName { get; internal set; } = "";
    public string Name => Path.GetFileName(FullName.TrimEnd(Path.DirectorySeparatorChar));
    public string Extension => Path.GetExtension(FullName);
    public bool PSIsContainer => (Attributes & FileAttributes.Directory) != 0;
    public long? Length { get; internal set; }
    public FileAttributes Attributes { get; internal set; }
    public DateTime CreationTimeUtc { get; internal set; }
    public DateTime LastWriteTimeUtc { get; internal set; }
    public DateTime LastAccessTimeUtc { get; internal set; }
    public DateTime CreationTime => CreationTimeUtc.ToLocalTime();
    public DateTime LastWriteTime => LastWriteTimeUtc.ToLocalTime();
    public DateTime LastAccessTime => LastAccessTimeUtc.ToLocalTime();
    public string Backend { get; internal set; } = "";

    /// <summary>Constructs a live native object. Reading its properties may perform additional filesystem I/O.</summary>
    public FileSystemInfo ToFileSystemInfo() => PSIsContainer ? (FileSystemInfo)new DirectoryInfo(FullName) : new FileInfo(FullName);

    internal static FileSystemEntry FromInfo(FileSystemInfo info) => new()
    {
        FullName = info.FullName, Attributes = info.Attributes,
        Length = info is FileInfo file ? file.Length : (long?)null,
        CreationTimeUtc = info.CreationTimeUtc, LastWriteTimeUtc = info.LastWriteTimeUtc,
        LastAccessTimeUtc = info.LastAccessTimeUtc, Backend = "Walk"
    };
}
