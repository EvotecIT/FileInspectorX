namespace FileInspectorX;

/// <summary>
/// Simplified PE section descriptor used for RVA-to-file offset resolution.
/// </summary>
internal sealed class Section {
    /// <summary>Name of the section (e.g., .text, .rdata).</summary>
    public string Name { get; set; } = string.Empty;
    /// <summary>RVA where the section is loaded in memory.</summary>
    public uint VirtualAddress;
    /// <summary>Virtual size in memory.</summary>
    public uint VirtualSize;
    /// <summary>File offset of the section raw data.</summary>
    public uint PointerToRawData;
    /// <summary>Size of the raw data on disk.</summary>
    public uint SizeOfRawData;
}
