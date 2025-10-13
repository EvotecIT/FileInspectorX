namespace FileInspectorX;

/// <summary>
/// Basic Portable Executable (PE) layout information extracted from headers and section table.
/// Used by the lightweight PE reader to locate resources, security directory and report hardening flags.
/// </summary>
internal sealed class PeInfo {
    /// <summary>True if PE signature (PE\0\0) was validated.</summary>
    public bool IsPE;
    /// <summary>True if PE is PE32+ (64‑bit) rather than PE32 (32‑bit).</summary>
    public bool IsPEPlus;
    /// <summary>File offset of the start of the Optional Header.</summary>
    public long OptionalHeaderStart;
    /// <summary>File offset of the CheckSum field within the Optional Header.</summary>
    public long ChecksumFileOffset;
    /// <summary>Number of section headers.</summary>
    public ushort NumberOfSections;
    /// <summary>Parsed section headers used for RVA to file offset mapping.</summary>
    public Section[] Sections = Array.Empty<Section>();
    /// <summary>RVA of the root of the resource directory (IMAGE_DIRECTORY_ENTRY_RESOURCE).</summary>
    public uint ResourceRva;
    /// <summary>Size of the resource directory.</summary>
    public uint ResourceSize;
    /// <summary>Security directory file offset (IMAGE_DIRECTORY_ENTRY_SECURITY uses file offset, not RVA).</summary>
    public uint SecurityOffset;
    /// <summary>Size of the certificate table (WIN_CERTIFICATE).</summary>
    public uint SecuritySize;
    /// <summary>DllCharacteristics bitmask from the Optional Header (ASLR/NX/CFG/etc.).</summary>
    public ushort DllCharacteristics;
    /// <summary>Subsystem value from the Optional Header (GUI/CUI/etc.).</summary>
    public ushort Subsystem;
}
