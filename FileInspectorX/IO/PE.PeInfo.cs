namespace FileInspectorX;

/// <summary>
/// Basic PE layout information extracted from headers and section table.
/// </summary>
internal sealed class PeInfo {
    public bool IsPE;
    public bool IsPEPlus;
    public long OptionalHeaderStart;
    public long ChecksumFileOffset;
    public ushort NumberOfSections;
    public Section[] Sections = Array.Empty<Section>();
    public uint ResourceRva;
    public uint ResourceSize;
    /// <summary>Security directory uses file offset, not RVA.</summary>
    public uint SecurityOffset;
    public uint SecuritySize;
    public ushort DllCharacteristics;
    public ushort Subsystem;
}
