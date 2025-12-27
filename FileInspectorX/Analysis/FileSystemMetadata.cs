namespace FileInspectorX;

/// <summary>
/// Basic file system metadata captured alongside analysis results.
/// </summary>
public sealed class FileSystemMetadata
{
    /// <summary>True when the file exists at the time of capture.</summary>
    public bool Exists { get; set; }
    /// <summary>Full path to the file, when requested.</summary>
    public string? Path { get; set; }
    /// <summary>File size in bytes, when available.</summary>
    public long? Size { get; set; }
    /// <summary>Creation time in UTC, when available.</summary>
    public DateTime? CreatedUtc { get; set; }
    /// <summary>Last write time in UTC, when available.</summary>
    public DateTime? ModifiedUtc { get; set; }
    /// <summary>Last access time in UTC, when available.</summary>
    public DateTime? AccessedUtc { get; set; }
    /// <summary>File attributes (e.g., ReadOnly, Hidden), when requested.</summary>
    public string? Attributes { get; set; }
    /// <summary>Magic header bytes as hex, when requested. Note: may expose sensitive content.</summary>
    public string? MagicHeaderHex { get; set; }
}

/// <summary>
/// Options controlling which file system metadata fields are captured.
/// </summary>
public sealed class FileMetadataOptions
{
    /// <summary>Include the file path. Default false. Note: may expose sensitive path information.</summary>
    public bool IncludePath { get; set; } = false;
    /// <summary>Include the file size. Default true.</summary>
    public bool IncludeSize { get; set; } = true;
    /// <summary>Include created/modified timestamps. Default true.</summary>
    public bool IncludeTimestamps { get; set; } = true;
    /// <summary>Include last access timestamp. Default false.</summary>
    public bool IncludeAccessedUtc { get; set; } = false;
    /// <summary>Include file attributes. Default false.</summary>
    public bool IncludeAttributes { get; set; } = false;
    /// <summary>Include magic header bytes in hex. Default false. Note: may expose sensitive content.</summary>
    public bool IncludeMagicHeader { get; set; } = false;
    /// <summary>Number of bytes to capture for the magic header. Default 16.</summary>
    public int MagicHeaderBytes { get; set; } = 16;
}
