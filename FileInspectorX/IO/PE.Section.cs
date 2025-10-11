namespace FileInspectorX;

/// <summary>
/// Simplified PE section descriptor used for RVA-to-file offset resolution.
/// </summary>
internal sealed class Section {
    public string Name { get; set; } = string.Empty;
    public uint VirtualAddress;
    public uint VirtualSize;
    public uint PointerToRawData;
    public uint SizeOfRawData;
}
