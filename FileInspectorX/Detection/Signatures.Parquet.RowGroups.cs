namespace FileInspectorX;

/// <summary>
/// Compact-protocol validation for Parquet row-group and column-chunk metadata.
/// </summary>
internal static partial class Signatures
{
    private static bool TryValidateParquetRowGroups(ReadOnlySpan<byte> src, ref int cursor, long dataEnd,
        out int count, out long totalRows, out int columnCount, out bool encryptedColumns)
    {
        count = 0;
        totalRows = 0;
        columnCount = -1;
        encryptedColumns = false;
        if (!TryReadCompactStructListHeader(src, ref cursor, allowEmpty: true, out count)) return false;
        for (int index = 0; index < count; index++)
        {
            if (!TryValidateParquetRowGroup(src, ref cursor, dataEnd, out long rows, out int currentColumnCount,
                    out bool currentEncryptedColumns) ||
                columnCount >= 0 && currentColumnCount != columnCount || rows > long.MaxValue - totalRows)
                return false;
            encryptedColumns |= currentEncryptedColumns;
            columnCount = currentColumnCount;
            totalRows += rows;
        }
        return true;
    }

    private static bool TryValidateParquetRowGroup(ReadOnlySpan<byte> src, ref int cursor, long dataEnd,
        out long rows, out int columnCount, out bool encryptedColumns)
    {
        rows = 0;
        columnCount = 0;
        encryptedColumns = false;
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
                if (type != 9 || !TryValidateNonEmptyParquetColumnChunks(src, ref cursor, dataEnd, out columnCount,
                        out encryptedColumns)) return false;
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

    private static bool TryValidateNonEmptyParquetColumnChunks(ReadOnlySpan<byte> src, ref int cursor, long dataEnd,
        out int count, out bool encryptedColumns)
    {
        encryptedColumns = false;
        if (!TryReadCompactStructListHeader(src, ref cursor, allowEmpty: false, out count)) return false;
        for (int index = 0; index < count; index++)
        {
            bool fileOffset = false, plaintextMetadata = false, cryptoMetadata = false, encryptedMetadata = false;
            long chunkFileOffset = 0;
            long columnDataStart = 0;
            long columnCompressedSize = 0;
            bool stopped = false;
            short previous = 0;
            var fields = new System.Collections.Generic.HashSet<short>();
            while (cursor < src.Length)
            {
                byte header = src[cursor++];
                if (header == 0)
                {
                    bool validRepresentation = plaintextMetadata
                        ? !cryptoMetadata && !encryptedMetadata
                        : cryptoMetadata && encryptedMetadata;
                    if (!fileOffset || !validRepresentation) return false;
                    stopped = true;
                    break;
                }
                int delta = header >> 4;
                int decodedField = delta == 0 ? ReadCompactFieldId(src, ref cursor) : previous + delta;
                if (decodedField is <= 0 or > short.MaxValue) return false;
                short field = (short)decodedField;
                int type = header & 0x0F;
                if (!fields.Add(field)) return false;
                if (field == 2)
                {
                    if (type != 6 || !TryReadCompactInt64(src, ref cursor, out long offset) ||
                        offset < 4 || offset >= dataEnd) return false;
                    chunkFileOffset = offset;
                    fileOffset = true;
                }
                else if (field == 3)
                {
                    if (type != 12 || !TryValidateParquetColumnMetadata(src, ref cursor, dataEnd,
                            out columnDataStart, out columnCompressedSize)) return false;
                    plaintextMetadata = true;
                }
                else if (field == 8)
                {
                    if (type != 12 || !TryValidateParquetColumnCryptoMetadata(src, ref cursor)) return false;
                    cryptoMetadata = true;
                }
                else if (field == 9)
                {
                    if (type != 8 || !TryReadNonEmptyCompactBinary(src, ref cursor)) return false;
                    encryptedMetadata = true;
                }
                else if (!SkipCompactValue(src, ref cursor, type, 2)) return false;
                previous = field;
            }
            bool hasValidRepresentation = plaintextMetadata
                ? !cryptoMetadata && !encryptedMetadata
                : cryptoMetadata && encryptedMetadata;
            if (!fileOffset || !stopped || !hasValidRepresentation ||
                plaintextMetadata && (chunkFileOffset > columnDataStart ||
                    columnCompressedSize > dataEnd - columnDataStart)) return false;
            encryptedColumns |= cryptoMetadata;
        }
        return true;
    }

    private static bool TryValidateParquetColumnMetadata(ReadOnlySpan<byte> src, ref int cursor, long dataEnd,
        out long dataStart, out long totalCompressedSize)
    {
        dataStart = long.MaxValue;
        totalCompressedSize = 0;
        bool physicalType = false, encodings = false, path = false, codec = false;
        bool values = false, uncompressedSize = false, compressedSize = false, dataPageOffset = false;
        short previous = 0;
        var fields = new System.Collections.Generic.HashSet<short>();
        while (cursor < src.Length)
        {
            byte header = src[cursor++];
            if (header == 0)
                return physicalType && encodings && path && codec && values && uncompressedSize && compressedSize &&
                       dataPageOffset && dataStart < dataEnd && totalCompressedSize <= dataEnd - dataStart;
            int delta = header >> 4;
            int decodedField = delta == 0 ? ReadCompactFieldId(src, ref cursor) : previous + delta;
            if (decodedField is <= 0 or > short.MaxValue) return false;
            short field = (short)decodedField;
            int type = header & 0x0F;
            if (!fields.Add(field)) return false;
            if (field == 1)
            {
                if (type != 5 || !TryReadCompactInt32(src, ref cursor, out int value) || value is < 0 or > 7) return false;
                physicalType = true;
            }
            else if (field == 2)
            {
                if (type != 9 || !TryValidateParquetEnumList(src, ref cursor, 9)) return false;
                encodings = true;
            }
            else if (field == 3)
            {
                if (type != 9 || !TryValidateParquetPath(src, ref cursor)) return false;
                path = true;
            }
            else if (field == 4)
            {
                if (type != 5 || !TryReadCompactInt32(src, ref cursor, out int value) || value is < 0 or > 7) return false;
                codec = true;
            }
            else if (field is 5 or 6 or 7)
            {
                if (type != 6 || !TryReadCompactInt64(src, ref cursor, out long value) || value < 0) return false;
                if (field == 5) values = true;
                else if (field == 6) uncompressedSize = true;
                else
                {
                    totalCompressedSize = value;
                    compressedSize = true;
                }
            }
            else if (field == 9)
            {
                if (type != 6 || !TryReadCompactInt64(src, ref cursor, out long offset) || offset < 4 || offset >= dataEnd) return false;
                dataPageOffset = true;
                if (offset < dataStart) dataStart = offset;
            }
            else if (field is 10 or 11)
            {
                if (type != 6 || !TryReadCompactInt64(src, ref cursor, out long offset) || offset < 4 || offset >= dataEnd) return false;
                if (field == 11 && offset < dataStart) dataStart = offset;
            }
            else if (!SkipCompactValue(src, ref cursor, type, 3)) return false;
            previous = field;
        }
        return false;
    }

    private static bool TryValidateParquetColumnCryptoMetadata(ReadOnlySpan<byte> src, ref int cursor)
    {
        bool footerKey = false, columnKey = false;
        short previous = 0;
        var fields = new System.Collections.Generic.HashSet<short>();
        while (cursor < src.Length)
        {
            byte header = src[cursor++];
            if (header == 0) return footerKey != columnKey;
            int delta = header >> 4;
            int decodedField = delta == 0 ? ReadCompactFieldId(src, ref cursor) : previous + delta;
            if (decodedField is not (1 or 2) || !fields.Add((short)decodedField) || (header & 0x0F) != 12) return false;
            if (decodedField == 1)
            {
                if (cursor >= src.Length || src[cursor++] != 0) return false;
                footerKey = true;
            }
            else
            {
                if (!TryValidateParquetColumnKeyMetadata(src, ref cursor)) return false;
                columnKey = true;
            }
            previous = (short)decodedField;
        }
        return false;
    }

    private static bool TryValidateParquetColumnKeyMetadata(ReadOnlySpan<byte> src, ref int cursor)
    {
        bool path = false;
        short previous = 0;
        var fields = new System.Collections.Generic.HashSet<short>();
        while (cursor < src.Length)
        {
            byte header = src[cursor++];
            if (header == 0) return path;
            int delta = header >> 4;
            int decodedField = delta == 0 ? ReadCompactFieldId(src, ref cursor) : previous + delta;
            if (decodedField is not (1 or 2) || !fields.Add((short)decodedField)) return false;
            int type = header & 0x0F;
            if (decodedField == 1)
            {
                if (type != 9 || !TryValidateParquetPath(src, ref cursor)) return false;
                path = true;
            }
            else if (type != 8 || !TryReadNonEmptyCompactBinary(src, ref cursor)) return false;
            previous = (short)decodedField;
        }
        return false;
    }

    private static bool TryValidateParquetEnumList(ReadOnlySpan<byte> src, ref int cursor, int maximum)
    {
        if (cursor >= src.Length) return false;
        byte header = src[cursor++];
        int count = header >> 4;
        if ((header & 0x0F) != 5) return false;
        if (count == 15)
        {
            if (!TryReadCompactVarint(src, ref cursor, out ulong longCount) || longCount > int.MaxValue) return false;
            count = (int)longCount;
        }
        if (count == 0 || count > src.Length - cursor) return false;
        for (int index = 0; index < count; index++)
            if (!TryReadCompactInt32(src, ref cursor, out int value) || value < 0 || value > maximum) return false;
        return true;
    }

    private static bool TryValidateParquetPath(ReadOnlySpan<byte> src, ref int cursor)
    {
        if (cursor >= src.Length) return false;
        byte header = src[cursor++];
        int count = header >> 4;
        if ((header & 0x0F) != 8) return false;
        if (count == 15)
        {
            if (!TryReadCompactVarint(src, ref cursor, out ulong longCount) || longCount > int.MaxValue) return false;
            count = (int)longCount;
        }
        if (count == 0 || count > src.Length - cursor) return false;
        for (int index = 0; index < count; index++)
            if (!TryReadNonEmptyCompactBinary(src, ref cursor)) return false;
        return true;
    }

    private static bool TryReadNonEmptyCompactBinary(ReadOnlySpan<byte> src, ref int cursor)
    {
        if (!TryReadCompactVarint(src, ref cursor, out ulong length) || length == 0 || length > (ulong)(src.Length - cursor)) return false;
        cursor += (int)length;
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
