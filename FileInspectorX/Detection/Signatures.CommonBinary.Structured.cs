namespace FileInspectorX;

/// <summary>
/// Complete and budgeted structural walks for framed common binary formats.
/// </summary>
internal static partial class Signatures
{
    private enum StructuredValidationStatus
    {
        Invalid,
        Sampled,
        Complete
    }

    private static StructuredValidationStatus TryValidateZipCentralDirectory(ReadOnlySpan<byte> src)
    {
        if (!TryFindStandardZipDirectory(src, 0, src.Length, out long directoryOffset,
                out uint directorySize, out ushort entryCount)) return StructuredValidationStatus.Invalid;
        long directoryEnd = directoryOffset + directorySize;
        if (directoryOffset < 0 || directoryEnd > src.Length || directoryEnd > int.MaxValue) return StructuredValidationStatus.Invalid;
        int cursor = (int)directoryOffset;
        for (int entry = 0; entry < entryCount; entry++)
        {
            if (cursor > directoryEnd - 46 || ReadUInt32LittleEndian(src, cursor) != 0x02014B50) return StructuredValidationStatus.Invalid;
            ushort versionNeeded = ReadUInt16LittleEndian(src, cursor + 6);
            ushort flags = ReadUInt16LittleEndian(src, cursor + 8);
            ushort method = ReadUInt16LittleEndian(src, cursor + 10);
            uint crc32 = ReadUInt32LittleEndian(src, cursor + 16);
            uint compressedSize = ReadUInt32LittleEndian(src, cursor + 20);
            uint uncompressedSize = ReadUInt32LittleEndian(src, cursor + 24);
            ushort nameLength = ReadUInt16LittleEndian(src, cursor + 28);
            ushort extraLength = ReadUInt16LittleEndian(src, cursor + 30);
            ushort commentLength = ReadUInt16LittleEndian(src, cursor + 32);
            ushort diskStart = ReadUInt16LittleEndian(src, cursor + 34);
            uint localOffset = ReadUInt32LittleEndian(src, cursor + 42);
            long recordEnd = (long)cursor + 46 + nameLength + extraLength + commentLength;
            if (versionNeeded is < 10 or > 100 || (flags & 0xC000) != 0 || !IsKnownZipMethod(method) ||
                nameLength == 0 || diskStart != 0 || compressedSize == uint.MaxValue ||
                uncompressedSize == uint.MaxValue || localOffset == uint.MaxValue ||
                recordEnd > directoryEnd) return StructuredValidationStatus.Invalid;
            ReadOnlySpan<byte> centralName = src.Slice(cursor + 46, nameLength);
            if (!TryValidateCentralZipLocalHeader(src, localOffset, directoryOffset,
                    method, flags, crc32, compressedSize, uncompressedSize, centralName))
                return StructuredValidationStatus.Invalid;
            cursor = (int)recordEnd;
        }
        return cursor == directoryEnd ? StructuredValidationStatus.Complete : StructuredValidationStatus.Invalid;
    }

    private static StructuredValidationStatus TryValidateZipCentralDirectory(Stream stream)
        => TryValidateZipCentralDirectory(stream, 0, stream.Length);

    private static StructuredValidationStatus TryValidateZipCentralDirectory(Stream stream, long archiveOffset, long archiveLength)
    {
        if (archiveOffset < 0 || archiveLength < 22 || archiveOffset > stream.Length - archiveLength)
            return StructuredValidationStatus.Invalid;
        int tailLength = (int)Math.Min(archiveLength, 65557L);
        if (!TryReadAt(stream, archiveOffset + archiveLength - tailLength, tailLength, out var tailBytes) ||
            !TryFindStandardZipDirectory(new ReadOnlySpan<byte>(tailBytes), archiveLength - tailLength, archiveLength,
                out long directoryOffset, out uint directorySize, out ushort entryCount)) return StructuredValidationStatus.Invalid;
        long directoryEnd = directoryOffset + directorySize;
        long cursor = directoryOffset;
        int remainingBudget = Math.Max(256, Settings.DetectionReadBudgetBytes);
        for (int entry = 0; entry < entryCount; entry++)
        {
            if (remainingBudget < 76) return StructuredValidationStatus.Sampled;
            if (cursor > directoryEnd - 46 || !TryReadAt(stream, archiveOffset + cursor, 46, out var centralBytes)) return StructuredValidationStatus.Invalid;
            remainingBudget -= 46;
            var central = new ReadOnlySpan<byte>(centralBytes);
            if (ReadUInt32LittleEndian(central, 0) != 0x02014B50) return StructuredValidationStatus.Invalid;
            ushort versionNeeded = ReadUInt16LittleEndian(central, 6);
            ushort flags = ReadUInt16LittleEndian(central, 8);
            ushort method = ReadUInt16LittleEndian(central, 10);
            uint crc32 = ReadUInt32LittleEndian(central, 16);
            uint compressedSize = ReadUInt32LittleEndian(central, 20);
            uint uncompressedSize = ReadUInt32LittleEndian(central, 24);
            ushort nameLength = ReadUInt16LittleEndian(central, 28);
            ushort extraLength = ReadUInt16LittleEndian(central, 30);
            ushort commentLength = ReadUInt16LittleEndian(central, 32);
            ushort diskStart = ReadUInt16LittleEndian(central, 34);
            uint localOffset = ReadUInt32LittleEndian(central, 42);
            long recordEnd = cursor + 46L + nameLength + extraLength + commentLength;
            if (versionNeeded is < 10 or > 100 || (flags & 0xC000) != 0 || !IsKnownZipMethod(method) ||
                nameLength == 0 || diskStart != 0 || compressedSize == uint.MaxValue ||
                uncompressedSize == uint.MaxValue || localOffset == uint.MaxValue ||
                recordEnd > directoryEnd || remainingBudget < nameLength ||
                !TryReadAt(stream, archiveOffset + cursor + 46, nameLength, out var centralNameBytes) ||
                !TryReadAt(stream, archiveOffset + localOffset, 30, out var localBytes) ||
                !TryValidateCentralZipLocalHeaderFields(new ReadOnlySpan<byte>(localBytes), localOffset, directoryOffset,
                    method, flags, crc32, compressedSize, uncompressedSize,
                    out ushort localNameLength, out long dataOffset)) return StructuredValidationStatus.Invalid;
            remainingBudget -= nameLength + 30;
            if (localNameLength != nameLength) return StructuredValidationStatus.Invalid;
            if (remainingBudget < localNameLength) return StructuredValidationStatus.Sampled;
            if (!TryReadAt(stream, archiveOffset + localOffset + 30, localNameLength, out var localNameBytes) ||
                !new ReadOnlySpan<byte>(localNameBytes).SequenceEqual(new ReadOnlySpan<byte>(centralNameBytes)))
                return StructuredValidationStatus.Invalid;
            remainingBudget -= localNameLength;
            if ((flags & 0x0008) != 0)
            {
                long descriptorOffset = dataOffset + compressedSize;
                int descriptorLength = (int)Math.Min(16, directoryOffset - descriptorOffset);
                if (descriptorLength < 12) return StructuredValidationStatus.Invalid;
                if (remainingBudget < descriptorLength) return StructuredValidationStatus.Sampled;
                if (!TryReadAt(stream, archiveOffset + descriptorOffset, descriptorLength, out var descriptor) ||
                    !TryValidateZipDataDescriptor(new ReadOnlySpan<byte>(descriptor), crc32, compressedSize, uncompressedSize))
                    return StructuredValidationStatus.Invalid;
                remainingBudget -= descriptorLength;
            }
            cursor = recordEnd;
        }
        return cursor == directoryEnd ? StructuredValidationStatus.Complete : StructuredValidationStatus.Invalid;
    }

    private static bool TryFindStandardZipDirectory(ReadOnlySpan<byte> tail, long tailOffset, long fileLength,
        out long directoryOffset, out uint directorySize, out ushort entryCount)
    {
        directoryOffset = 0;
        directorySize = 0;
        entryCount = 0;
        for (int offset = tail.Length - 22; offset >= 0; offset--)
        {
            if (ReadUInt32LittleEndian(tail, offset) != 0x06054B50) continue;
            ushort commentLength = ReadUInt16LittleEndian(tail, offset + 20);
            long eocdOffset = tailOffset + offset;
            if (eocdOffset + 22L + commentLength != fileLength) continue;
            ushort disk = ReadUInt16LittleEndian(tail, offset + 4);
            ushort centralDisk = ReadUInt16LittleEndian(tail, offset + 6);
            ushort entriesOnDisk = ReadUInt16LittleEndian(tail, offset + 8);
            ushort entriesTotal = ReadUInt16LittleEndian(tail, offset + 10);
            uint size = ReadUInt32LittleEndian(tail, offset + 12);
            uint start = ReadUInt32LittleEndian(tail, offset + 16);
            if (disk != 0 || centralDisk != 0 || entriesOnDisk != entriesTotal || entriesTotal == ushort.MaxValue ||
                size == uint.MaxValue || start == uint.MaxValue || (long)start + size != eocdOffset) continue;
            directoryOffset = start;
            directorySize = size;
            entryCount = entriesTotal;
            return entriesTotal != 0;
        }
        return false;
    }

    private static bool TryValidateCentralZipLocalHeader(ReadOnlySpan<byte> src, uint localOffset, long directoryOffset,
        ushort method, ushort flags, uint crc32, uint compressedSize, uint uncompressedSize,
        ReadOnlySpan<byte> centralName)
    {
        if (localOffset > int.MaxValue || localOffset + 30L > directoryOffset || localOffset + 30L > src.Length) return false;
        if (!TryValidateCentralZipLocalHeaderFields(src.Slice((int)localOffset, 30), localOffset, directoryOffset,
                method, flags, crc32, compressedSize, uncompressedSize,
                out ushort localNameLength, out long dataOffset) || localNameLength != centralName.Length ||
            localOffset + 30L + localNameLength > directoryOffset || localOffset + 30L + localNameLength > src.Length) return false;
        if (!src.Slice((int)localOffset + 30, localNameLength).SequenceEqual(centralName)) return false;
        if ((flags & 0x0008) == 0) return true;
        long descriptorOffset = dataOffset + compressedSize;
        int descriptorLength = (int)Math.Min(16, directoryOffset - descriptorOffset);
        return descriptorLength >= 12 && descriptorOffset <= src.Length - descriptorLength &&
               TryValidateZipDataDescriptor(src.Slice((int)descriptorOffset, descriptorLength),
                   crc32, compressedSize, uncompressedSize);
    }

    private static bool TryValidateCentralZipLocalHeaderFields(ReadOnlySpan<byte> local, long localOffset, long directoryOffset,
        ushort method, ushort flags, uint crc32, uint compressedSize, uint uncompressedSize,
        out ushort nameLength, out long dataOffset)
    {
        nameLength = 0;
        dataOffset = 0;
        if (local.Length < 30 || ReadUInt32LittleEndian(local, 0) != 0x04034B50 ||
            ReadUInt16LittleEndian(local, 8) != method || ReadUInt16LittleEndian(local, 6) != flags) return false;
        nameLength = ReadUInt16LittleEndian(local, 26);
        ushort extraLength = ReadUInt16LittleEndian(local, 28);
        dataOffset = localOffset + 30L + nameLength + extraLength;
        long descriptorLength = (flags & 0x0008) != 0 ? 12 : 0;
        if (nameLength == 0 || dataOffset > directoryOffset - descriptorLength ||
            compressedSize > directoryOffset - descriptorLength - dataOffset) return false;
        return (flags & 0x0008) != 0 ||
               ReadUInt32LittleEndian(local, 14) == crc32 &&
               ReadUInt32LittleEndian(local, 18) == compressedSize &&
               ReadUInt32LittleEndian(local, 22) == uncompressedSize;
    }

    private static bool TryValidateZipDataDescriptor(ReadOnlySpan<byte> descriptor,
        uint crc32, uint compressedSize, uint uncompressedSize)
    {
        if (descriptor.Length >= 12 && ReadUInt32LittleEndian(descriptor, 0) == crc32 &&
            ReadUInt32LittleEndian(descriptor, 4) == compressedSize &&
            ReadUInt32LittleEndian(descriptor, 8) == uncompressedSize) return true;
        return descriptor.Length >= 16 && ReadUInt32LittleEndian(descriptor, 0) == 0x08074B50 &&
               ReadUInt32LittleEndian(descriptor, 4) == crc32 &&
               ReadUInt32LittleEndian(descriptor, 8) == compressedSize &&
               ReadUInt32LittleEndian(descriptor, 12) == uncompressedSize;
    }

    private static StructuredValidationStatus TryValidateWasmSections(ReadOnlySpan<byte> src, long? completeLength)
    {
        int cursor = 8;
        int lastRank = 0;
        uint seenSections = 0;
        while (cursor < src.Length)
        {
            byte sectionId = src[cursor++];
            int rank = GetWasmSectionRank(sectionId);
            if (rank < 0 || sectionId != 0 && (rank <= lastRank || (seenSections & 1u << sectionId) != 0))
                return StructuredValidationStatus.Invalid;
            if (sectionId != 0)
            {
                lastRank = rank;
                seenSections |= 1u << sectionId;
            }
            if (!TryReadCanonicalWasmLength(src, ref cursor, out uint sectionLength, out bool needsMore))
                return needsMore && (!completeLength.HasValue || completeLength.Value > src.Length)
                    ? StructuredValidationStatus.Sampled
                    : StructuredValidationStatus.Invalid;
            if (sectionLength == 0) return StructuredValidationStatus.Invalid;
            long sectionEnd = (long)cursor + sectionLength;
            if (completeLength.HasValue && sectionEnd > completeLength.Value) return StructuredValidationStatus.Invalid;
            if (sectionEnd > src.Length)
                return !completeLength.HasValue || completeLength.Value > src.Length
                    ? StructuredValidationStatus.Sampled
                    : StructuredValidationStatus.Invalid;
            cursor = (int)sectionEnd;
        }
        return completeLength.HasValue && completeLength.Value == cursor
            ? StructuredValidationStatus.Complete
            : StructuredValidationStatus.Sampled;
    }

    private static int GetWasmSectionRank(byte sectionId) => sectionId switch
    {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 3,
        4 => 4,
        5 => 5,
        13 => 6,
        6 => 7,
        7 => 8,
        8 => 9,
        9 => 10,
        12 => 11,
        10 => 12,
        11 => 13,
        _ => -1
    };

    private static bool TryReadCanonicalWasmLength(ReadOnlySpan<byte> src, ref int cursor, out uint value, out bool needsMore)
    {
        value = 0;
        needsMore = false;
        int start = cursor;
        for (int index = 0; index < 5; index++)
        {
            if (cursor >= src.Length)
            {
                needsMore = true;
                return false;
            }
            byte current = src[cursor++];
            if (index == 4 && (current & 0xF0) != 0) return false;
            value |= (uint)(current & 0x7F) << (index * 7);
            if ((current & 0x80) != 0) continue;
            int required = value < 1u << 7 ? 1 : value < 1u << 14 ? 2 : value < 1u << 21 ? 3 : value < 1u << 28 ? 4 : 5;
            return cursor - start == required;
        }
        return false;
    }

    private static StructuredValidationStatus TryValidatePcapNgBlocks(ReadOnlySpan<byte> src, long? completeLength)
    {
        if (src.Length < 28 || ReadUInt32BigEndian(src, 0) != 0x0A0D0D0A) return StructuredValidationStatus.Invalid;
        long cursor = 0;
        long sectionEnd = -1;
        bool littleEndian = false;
        while (cursor < src.Length)
        {
            if (src.Length - cursor < 12)
                return !completeLength.HasValue || completeLength.Value > src.Length
                    ? StructuredValidationStatus.Sampled
                    : StructuredValidationStatus.Invalid;
            int offset = (int)cursor;
            bool sectionHeader = ReadUInt32BigEndian(src, offset) == 0x0A0D0D0A;
            if (sectionHeader)
            {
                if (sectionEnd >= 0 && cursor != sectionEnd) return StructuredValidationStatus.Invalid;
                if (src.Length - cursor < 28)
                    return !completeLength.HasValue || completeLength.Value > src.Length
                        ? StructuredValidationStatus.Sampled
                        : StructuredValidationStatus.Invalid;
                uint byteOrder = ReadUInt32BigEndian(src, offset + 8);
                if (byteOrder == 0x4D3C2B1A) littleEndian = true;
                else if (byteOrder == 0x1A2B3C4D) littleEndian = false;
                else return StructuredValidationStatus.Invalid;
            }
            uint blockLength = ReadUInt32(src, offset + 4, littleEndian);
            uint minimumLength = sectionHeader ? 28u : 12u;
            long blockEnd = cursor + blockLength;
            if (blockLength < minimumLength || (blockLength & 3) != 0 || blockEnd < cursor ||
                (completeLength.HasValue && blockEnd > completeLength.Value) ||
                (!sectionHeader && sectionEnd >= 0 && blockEnd > sectionEnd)) return StructuredValidationStatus.Invalid;
            if (sectionHeader)
            {
                if (ReadUInt16(src, offset + 12, littleEndian) != 1 || ReadUInt16(src, offset + 14, littleEndian) != 0)
                    return StructuredValidationStatus.Invalid;
                long sectionLength = unchecked((long)ReadUInt64(src, offset + 16, littleEndian));
                if (sectionLength < -1) return StructuredValidationStatus.Invalid;
                sectionEnd = sectionLength < 0 ? -1 : blockEnd + sectionLength;
                if (sectionEnd >= 0 && (sectionEnd < blockEnd || completeLength.HasValue && sectionEnd > completeLength.Value))
                    return StructuredValidationStatus.Invalid;
            }
            if (blockEnd > src.Length)
                return !completeLength.HasValue || completeLength.Value > src.Length
                    ? StructuredValidationStatus.Sampled
                    : StructuredValidationStatus.Invalid;
            if (ReadUInt32(src, (int)blockEnd - 4, littleEndian) != blockLength) return StructuredValidationStatus.Invalid;
            cursor = blockEnd;
        }
        if (sectionEnd >= 0 && cursor != sectionEnd) return StructuredValidationStatus.Invalid;
        return completeLength.HasValue && completeLength.Value == cursor
            ? StructuredValidationStatus.Complete
            : StructuredValidationStatus.Sampled;
    }

    private static StructuredValidationStatus TryValidatePcapNgBlocks(Stream stream)
    {
        if (stream.Length < 28) return StructuredValidationStatus.Invalid;
        long cursor = 0;
        long sectionEnd = -1;
        bool littleEndian = false;
        int remainingBudget = Math.Max(256, Settings.DetectionReadBudgetBytes);
        while (cursor < stream.Length)
        {
            if (remainingBudget < 32) return StructuredValidationStatus.Sampled;
            if (stream.Length - cursor < 12 || !TryReadAt(stream, cursor, 12, out var prefixBytes))
                return StructuredValidationStatus.Invalid;
            remainingBudget -= 12;
            var prefix = new ReadOnlySpan<byte>(prefixBytes);
            bool sectionHeader = ReadUInt32BigEndian(prefix, 0) == 0x0A0D0D0A;
            if (cursor == 0 && !sectionHeader) return StructuredValidationStatus.Invalid;
            ReadOnlySpan<byte> header = prefix;
            if (sectionHeader)
            {
                if (sectionEnd >= 0 && cursor != sectionEnd || stream.Length - cursor < 28 ||
                    !TryReadAt(stream, cursor, 28, out var sectionBytes)) return StructuredValidationStatus.Invalid;
                remainingBudget -= 16;
                header = new ReadOnlySpan<byte>(sectionBytes);
                uint byteOrder = ReadUInt32BigEndian(header, 8);
                if (byteOrder == 0x4D3C2B1A) littleEndian = true;
                else if (byteOrder == 0x1A2B3C4D) littleEndian = false;
                else return StructuredValidationStatus.Invalid;
            }
            uint blockLength = ReadUInt32(header, 4, littleEndian);
            uint minimumLength = sectionHeader ? 28u : 12u;
            long blockEnd = cursor + blockLength;
            if (blockLength < minimumLength || (blockLength & 3) != 0 || blockEnd < cursor || blockEnd > stream.Length ||
                !sectionHeader && sectionEnd >= 0 && blockEnd > sectionEnd ||
                !TryReadAt(stream, blockEnd - 4, 4, out var trailerBytes) ||
                ReadUInt32(new ReadOnlySpan<byte>(trailerBytes), 0, littleEndian) != blockLength)
                return StructuredValidationStatus.Invalid;
            remainingBudget -= 4;
            if (sectionHeader)
            {
                if (ReadUInt16(header, 12, littleEndian) != 1 || ReadUInt16(header, 14, littleEndian) != 0)
                    return StructuredValidationStatus.Invalid;
                long sectionLength = unchecked((long)ReadUInt64(header, 16, littleEndian));
                if (sectionLength < -1) return StructuredValidationStatus.Invalid;
                sectionEnd = sectionLength < 0 ? -1 : blockEnd + sectionLength;
                if (sectionEnd >= 0 && (sectionEnd < blockEnd || sectionEnd > stream.Length))
                    return StructuredValidationStatus.Invalid;
            }
            cursor = blockEnd;
        }
        return sectionEnd < 0 || cursor == sectionEnd
            ? StructuredValidationStatus.Complete
            : StructuredValidationStatus.Invalid;
    }
}
