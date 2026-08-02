namespace FileInspectorX;

/// <summary>
/// Structural validation helpers for dynamic and differencing VHD block allocation tables.
/// </summary>
internal static partial class Signatures
{
    private readonly struct VhdBatInfo
    {
        internal VhdBatInfo(ulong tableOffset, ulong tableLength, uint entries, uint blockSize)
        { TableOffset = tableOffset; TableLength = tableLength; Entries = entries; BlockSize = blockSize; }
        internal ulong TableOffset { get; }
        internal ulong TableLength { get; }
        internal uint Entries { get; }
        internal uint BlockSize { get; }
    }

    private static bool TryValidateVhdBat(ReadOnlySpan<byte> table, long fileLength, VhdBatInfo bat)
    {
        if ((ulong)table.Length != bat.TableLength || bat.Entries > (uint)(table.Length / 4) || fileLength < 512) return false;
        return TryValidateVhdBatEntries(table, bat.Entries, fileLength, bat);
    }

    private static StructuredValidationStatus TryValidateVhdBat(Stream stream, VhdBatInfo bat)
    {
        int budget = Math.Max(4096, Settings.DetectionReadBudgetBytes);
        if (bat.TableLength <= (ulong)budget)
        {
            if (!TryReadAt(stream, checked((long)bat.TableOffset), checked((int)bat.TableLength), out var table))
                return StructuredValidationStatus.Invalid;
            return TryValidateVhdBat(new ReadOnlySpan<byte>(table), stream.Length, bat)
                ? StructuredValidationStatus.Complete
                : StructuredValidationStatus.Invalid;
        }

        int sampleLength = budget & ~3;
        if (sampleLength < 4 || !TryReadAt(stream, checked((long)bat.TableOffset), sampleLength, out var sample) ||
            !TryValidateVhdBatEntries(new ReadOnlySpan<byte>(sample), (uint)(sampleLength / 4), stream.Length, bat))
            return StructuredValidationStatus.Invalid;
        return StructuredValidationStatus.Sampled;
    }

    private static bool TryValidateVhdBatEntries(ReadOnlySpan<byte> table, uint entries, long fileLength, VhdBatInfo bat)
    {
        if (entries > (uint)(table.Length / 4) || fileLength < 512) return false;
        ulong bitmapLength = (((ulong)bat.BlockSize / 512 + 7) / 8 + 511) & ~511UL;
        ulong tableEnd = bat.TableOffset + bat.TableLength;
        ulong dataEnd = (ulong)fileLength - 512;
        var ranges = new System.Collections.Generic.List<(ulong Start, ulong End)>();
        for (uint index = 0; index < entries; index++)
        {
            uint sector = ReadUInt32BigEndian(table, checked((int)index * 4));
            if (sector == uint.MaxValue) continue;
            ulong start = (ulong)sector * 512;
            ulong length = bitmapLength + bat.BlockSize;
            if (start < tableEnd || length > dataEnd - Math.Min(start, dataEnd)) return false;
            ulong end = start + length;
            ranges.Add((start, end));
        }
        ranges.Sort((left, right) => left.Start.CompareTo(right.Start));
        for (int index = 1; index < ranges.Count; index++)
            if (ranges[index].Start < ranges[index - 1].End) return false;
        return true;
    }
}
