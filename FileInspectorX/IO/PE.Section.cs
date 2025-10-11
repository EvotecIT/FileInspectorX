namespace FileInspectorX;

/// <summary>
/// Simplified PE section descriptor used for RVA-to-file offset resolution.
/// </summary>
internal sealed class Section {
    public uint VirtualAddress;
    public uint VirtualSize;
    public uint PointerToRawData;
    public uint SizeOfRawData;
}

