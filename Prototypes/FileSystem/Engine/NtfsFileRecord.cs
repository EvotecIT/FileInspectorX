namespace FileInspectorX.Prototypes.FileSystem;

internal sealed class NtfsLink
{
    internal ulong ParentId;
    internal string Name = "";
    internal NtfsFileRecord Owner = null!;
}

/// <summary>Retains inventory metadata only. Raw MFT buffers can contain resident data, which is neither inspected nor retained.</summary>
internal sealed class NtfsFileRecord
{
    internal ulong Id, BaseId;
    // Header reference-count hint; contradictory values require supported live metadata validation.
    internal ushort LinkCount;
    internal int NameAttributeCount;
    internal bool Directory, HasStandardInformation, HasData;
    internal FileAttributes Attributes;
    internal long Length;
    internal DateTime Created, Written, Accessed;
    internal readonly List<NtfsLink> Links = new();
    internal string? Incomplete;

    internal FileSystemEntry Entry(string path) => new()
    {
        FullName = path, Attributes = Attributes, Length = Directory ? (long?)null : Length,
        CreationTimeUtc = Created, LastWriteTimeUtc = Written, LastAccessTimeUtc = Accessed, Backend = "Mft"
    };

    internal void Merge(NtfsFileRecord extension)
    {
        if (extension.BaseId != Id) throw new IOException("Extension record refers to a different base identity.");
        if (extension.HasStandardInformation)
        {
            if (HasStandardInformation) throw new IOException("Duplicate standard information across file records.");
            HasStandardInformation = true; Attributes = extension.Attributes;
            Created = extension.Created; Written = extension.Written; Accessed = extension.Accessed;
        }
        if (extension.HasData)
        {
            if (HasData) throw new IOException("Duplicate unnamed data origin across file records.");
            HasData = true; Length = extension.Length;
        }
        Links.AddRange(extension.Links);
        NameAttributeCount = checked(NameAttributeCount + extension.NameAttributeCount);
    }
}
