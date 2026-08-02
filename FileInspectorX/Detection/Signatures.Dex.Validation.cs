namespace FileInspectorX;

/// <summary>
/// Complete DEX container validation shared by byte and seekable-stream detection.
/// </summary>
internal static partial class Signatures
{
    private static bool TryValidateDex041Container(ReadOnlySpan<byte> container, uint declaredContainerSize)
    {
        if (declaredContainerSize != container.Length) return false;
        int cursor = 0;
        while (cursor < container.Length)
        {
            if (container.Length - cursor < 0x78) return false;
            ReadOnlySpan<byte> header = container.Slice(cursor, 0x78);
            if (!header.Slice(0, 8).SequenceEqual("dex\n041\0"u8)) return false;

            uint endianTag = ReadUInt32(header, 40, littleEndian: true);
            bool littleEndian;
            if (endianTag == 0x12345678) littleEndian = true;
            else if (endianTag == 0x78563412) littleEndian = false;
            else return false;

            uint fileSize = ReadUInt32(header, 32, littleEndian);
            if (ReadUInt32(header, 36, littleEndian) != 0x78 ||
                ReadUInt32(header, 112, littleEndian) != declaredContainerSize ||
                ReadUInt32(header, 116, littleEndian) != (uint)cursor ||
                fileSize < 0x78 || fileSize > int.MaxValue || fileSize > container.Length - cursor ||
                fileSize < container.Length - cursor && (fileSize & 3) != 0) return false;

            ReadOnlySpan<byte> dex = container.Slice(cursor, (int)fileSize);
            if (!TryValidateDexSectionsAndMap(dex, littleEndian, 0x78)) return false;
            using var sha1 = System.Security.Cryptography.SHA1.Create();
            byte[] calculatedSignature = sha1.ComputeHash(dex.Slice(32).ToArray());
            if (!dex.Slice(12, 20).SequenceEqual(calculatedSignature) ||
                ReadUInt32(dex, 8, littleEndian) != ComputeAdler32(dex.Slice(12))) return false;
            cursor += (int)fileSize;
        }
        return cursor == container.Length;
    }
}
