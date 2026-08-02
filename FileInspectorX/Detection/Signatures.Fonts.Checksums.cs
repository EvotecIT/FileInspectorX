namespace FileInspectorX;

/// <summary>
/// OpenType table checksum validation shared by standalone fonts and collections.
/// </summary>
internal static partial class Signatures
{
    private enum FontChecksumStatus { Invalid, Sampled, AggregateMismatch, Complete }

    private static FontChecksumStatus ValidateSfntTableChecksums(
        ReadOnlySpan<byte> file, ReadOnlySpan<byte> directory, bool validateAggregateChecksum)
    {
        if (directory.Length < 12) return FontChecksumStatus.Invalid;
        ushort tableCount = ReadUInt16BigEndian(directory, 4);
        if (directory.Length < 12L + tableCount * 16L) return FontChecksumStatus.Invalid;
        bool sampled = false;
        for (int table = 0; table < tableCount; table++)
        {
            int record = 12 + table * 16;
            uint tag = ReadUInt32BigEndian(directory, record);
            uint expectedChecksum = ReadUInt32BigEndian(directory, record + 4);
            uint tableOffset = ReadUInt32BigEndian(directory, record + 8);
            uint tableLength = ReadUInt32BigEndian(directory, record + 12);
            if (tableOffset > int.MaxValue || tableLength > int.MaxValue ||
                (ulong)tableOffset + tableLength > (ulong)file.Length)
            {
                sampled = true;
                continue;
            }
            if (ComputeSfntTableChecksum(file.Slice((int)tableOffset, (int)tableLength), tag) != expectedChecksum)
                return FontChecksumStatus.Invalid;
        }
        if (sampled) return FontChecksumStatus.Sampled;
        if (validateAggregateChecksum && ComputeSfntFileChecksum(file) != 0xB1B0AFBAu)
            return FontChecksumStatus.AggregateMismatch;
        return FontChecksumStatus.Complete;
    }

    private static uint ComputeSfntTableChecksum(ReadOnlySpan<byte> table, uint tag)
    {
        uint sum = 0;
        for (int offset = 0; offset < table.Length; offset += 4)
        {
            uint word = 0;
            for (int index = 0; index < 4; index++)
            {
                int position = offset + index;
                byte value = position < table.Length ? table[position] : (byte)0;
                if (tag == 0x68656164u && position is >= 8 and < 12) value = 0;
                word = (word << 8) | value;
            }
            unchecked { sum += word; }
        }
        return sum;
    }

    private static uint ComputeSfntFileChecksum(ReadOnlySpan<byte> file)
    {
        uint sum = 0;
        for (int offset = 0; offset < file.Length; offset += 4)
        {
            uint word = 0;
            for (int index = 0; index < 4; index++)
            {
                int position = offset + index;
                word = word << 8 | (position < file.Length ? file[position] : 0u);
            }
            unchecked { sum += word; }
        }
        return sum;
    }
}
