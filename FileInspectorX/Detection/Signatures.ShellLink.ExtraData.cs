namespace FileInspectorX;

/// <summary>
/// Type-specific Shell Link ExtraData block validation.
/// </summary>
internal static partial class Signatures
{
    private static bool TryValidateShellLinkExtraData(ReadOnlySpan<byte> block, out bool recognized)
    {
        recognized = true;
        if (block.Length < 8 || ReadUInt32LittleEndian(block, 0) != block.Length) return false;
        uint signature = ReadUInt32LittleEndian(block, 4);
        switch (signature)
        {
            case 0xA0000001: // EnvironmentVariableDataBlock
            case 0xA0000006: // DarwinDataBlock
            case 0xA0000007: // IconEnvironmentDataBlock
                return block.Length == 0x314;
            case 0xA0000002: // ConsoleDataBlock
                return block.Length == 0xCC;
            case 0xA0000003: // TrackerDataBlock
                return block.Length == 0x60 && ReadUInt32LittleEndian(block, 8) == 0x58 &&
                       ReadUInt32LittleEndian(block, 12) == 0;
            case 0xA0000004: // ConsoleFEDataBlock
                return block.Length == 0x0C;
            case 0xA0000005: // SpecialFolderDataBlock
                return block.Length == 0x10;
            case 0xA0000008: // ShimDataBlock
                return block.Length >= 0x88;
            case 0xA0000009: // PropertyStoreDataBlock
                return block.Length >= 0x0C;
            case 0xA000000B: // KnownFolderDataBlock
                return block.Length == 0x1C;
            case 0xA000000C: // VistaAndAboveIDListDataBlock
                return block.Length >= 10 && TryValidateShellLinkIdList(block.Slice(8));
            default:
                recognized = false;
                return true;
        }
    }
}
