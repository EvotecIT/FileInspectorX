namespace FileInspectorX;

/// <summary>
/// Compact-protocol validation for Parquet row-group and column-chunk metadata.
/// </summary>
internal static partial class Signatures
{
    private static bool TryValidateParquetRowGroups(ReadOnlySpan<byte> src, ref int cursor,
        out int count, out long totalRows)
    {
        count = 0;
        totalRows = 0;
        if (!TryReadCompactStructListHeader(src, ref cursor, allowEmpty: true, out count)) return false;
        for (int index = 0; index < count; index++)
        {
            if (!TryValidateParquetRowGroup(src, ref cursor, out long rows) || rows > long.MaxValue - totalRows)
                return false;
            totalRows += rows;
        }
        return true;
    }

    private static bool TryValidateParquetRowGroup(ReadOnlySpan<byte> src, ref int cursor, out long rows)
    {
        rows = 0;
        bool columns = false, totalByteSize = false, rowCount = false;
        short previous = 0;
        var fields = new System.Collections.Generic.HashSet<short>();
        while (cursor < src.Length)
        {
            byte header = src[cursor++];
            if (header == 0) return columns && totalByteSize && rowCount;
            int delta = header >> 4;
            int decodedField = delta == 0 ? ReadCompactFieldId(src, ref cursor) : previous + delta;
            if (decodedField is <= 0 or > short.MaxValue) return false;
            short field = (short)decodedField;
            int type = header & 0x0F;
            if (!fields.Add(field)) return false;
            if (field == 1)
            {
                if (type != 9 || !TryValidateNonEmptyParquetColumnChunks(src, ref cursor)) return false;
                columns = true;
            }
            else if (field == 2)
            {
                if (type != 6 || !TryReadCompactInt64(src, ref cursor, out long size) || size < 0) return false;
                totalByteSize = true;
            }
            else if (field == 3)
            {
                if (type != 6 || !TryReadCompactInt64(src, ref cursor, out rows) || rows < 0) return false;
                rowCount = true;
            }
            else if (!SkipCompactValue(src, ref cursor, type, 1)) return false;
            previous = field;
        }
        return false;
    }

    private static bool TryValidateNonEmptyParquetColumnChunks(ReadOnlySpan<byte> src, ref int cursor)
    {
        if (!TryReadCompactStructListHeader(src, ref cursor, allowEmpty: false, out int count)) return false;
        for (int index = 0; index < count; index++)
        {
            bool sawField = false;
            bool stopped = false;
            short previous = 0;
            var fields = new System.Collections.Generic.HashSet<short>();
            while (cursor < src.Length)
            {
                byte header = src[cursor++];
                if (header == 0)
                {
                    if (!sawField) return false;
                    stopped = true;
                    break;
                }
                int delta = header >> 4;
                int decodedField = delta == 0 ? ReadCompactFieldId(src, ref cursor) : previous + delta;
                if (decodedField is <= 0 or > short.MaxValue) return false;
                short field = (short)decodedField;
                if (!fields.Add(field) || !SkipCompactValue(src, ref cursor, header & 0x0F, 2)) return false;
                sawField = true;
                previous = field;
            }
            if (!sawField || !stopped) return false;
        }
        return true;
    }

    private static bool TryReadCompactStructListHeader(ReadOnlySpan<byte> src, ref int cursor, bool allowEmpty, out int count)
    {
        count = 0;
        if (cursor >= src.Length) return false;
        byte header = src[cursor++];
        count = header >> 4;
        if ((header & 0x0F) != 12) return false;
        if (count == 15)
        {
            if (!TryReadCompactVarint(src, ref cursor, out ulong longCount) || longCount > int.MaxValue) return false;
            count = (int)longCount;
        }
        return (allowEmpty || count > 0) && count <= src.Length - cursor;
    }
}
