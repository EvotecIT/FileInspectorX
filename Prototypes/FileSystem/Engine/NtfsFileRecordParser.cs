using System.Text;

namespace FileInspectorX.Prototypes.FileSystem;

/// <summary>Bounded decoder for logical NTFS 3.x records returned by FSCTL_GET_NTFS_FILE_RECORD.</summary>
internal static class NtfsFileRecordParser
{
    internal const ulong SlotMask = 0x0000FFFFFFFFFFFFUL;
    private const int ProtectionStride = 512;
    private static readonly char[] InvalidNameCharacters = { '\\', '/', ':', '\0' };

    // This input is filesystem control output, never a raw on-disk record or disk image.
    internal static NtfsFileRecord Parse(byte[] output, int returned, int sectorBytes)
    {
        if (returned < 60 || returned > output.Length) throw new IOException("Truncated file-record output.");
        int size = checked((int)BitConverter.ToUInt32(output, 8));
        if (size < 48 || size > returned - 12) throw new IOException("Invalid file-record size.");
        const int start = 12;
        return ParseRecord(output, start, size, BitConverter.ToUInt64(output, 0) & SlotMask, sectorBytes);
    }

    // Raw sector trailers must all match before replacing any bytes. Logical API
    // output deliberately bypasses this route because its USA values can be stale.
    internal static NtfsFileRecord? ParseRaw(byte[] bytes, int start, int size, ulong slot, int sectorBytes)
    {
        if (start < 0 || size < 48 || start > bytes.Length - size || slot > SlotMask)
            throw new IOException("Raw record escapes its buffer.");
        uint signature = BitConverter.ToUInt32(bytes, start);
        if (signature == 0 && BitConverter.ToUInt16(bytes, start + 22) == 0) return null;
        if (signature != 0x454C4946) throw new IOException("Invalid raw FILE signature at slot " + slot + ".");
        if ((BitConverter.ToUInt16(bytes, start + 22) & 1) == 0) return null;
        ValidateSequenceLayout(bytes, start, size, sectorBytes);
        int usa = start + BitConverter.ToUInt16(bytes, start + 4);
        ushort expected = BitConverter.ToUInt16(bytes, usa);
        for (int i = 1; i <= size / ProtectionStride; i++)
            if (BitConverter.ToUInt16(bytes, start + i * ProtectionStride - 2) != expected)
                throw new IOException("Raw update-sequence mismatch at slot " + slot + ".");
        for (int i = 1; i <= size / ProtectionStride; i++)
        {
            bytes[start + i * ProtectionStride - 2] = bytes[usa + i * 2];
            bytes[start + i * ProtectionStride - 1] = bytes[usa + i * 2 + 1];
        }
        return ParseRecord(bytes, start, size, slot, sectorBytes);
    }

    private static NtfsFileRecord ParseRecord(byte[] output, int start, int size, ulong slot, int sectorBytes)
    {
        if (BitConverter.ToUInt32(output, start) != 0x454C4946) throw new IOException("Missing FILE signature.");
        ValidateSequenceLayout(output, start, size, sectorBytes);
        int used = checked((int)BitConverter.ToUInt32(output, start + 24));
        int offset = BitConverter.ToUInt16(output, start + 20);
        ushort flags = BitConverter.ToUInt16(output, start + 22);
        if ((flags & 1) == 0 || used > size || used < 48 || offset < 48 || offset % 8 != 0 || offset > used - 4)
            throw new IOException("Invalid in-use file-record header.");
        ushort sequence = BitConverter.ToUInt16(output, start + 16);
        if (sequence == 0) throw new IOException("In-use record has no identity sequence.");
        var record = new NtfsFileRecord
        {
            Id = slot | ((ulong)sequence << 48), BaseId = BitConverter.ToUInt64(output, start + 32),
            LinkCount = BitConverter.ToUInt16(output, start + 18), Directory = (flags & 2) != 0
        };
        while (offset <= used - 4)
        {
            int p = start + offset;
            uint type = BitConverter.ToUInt32(output, p);
            if (type == uint.MaxValue) return record;
            if (used - offset < 24) throw new IOException("Truncated attribute header.");
            int length = checked((int)BitConverter.ToUInt32(output, p + 4));
            bool nonresident = output[p + 8] == 1;
            int minimum = nonresident ? 64 : 24;
            if (output[p + 8] > 1 || length < minimum || length % 8 != 0 || length > used - offset)
                throw new IOException("Invalid attribute length or form.");
            int named = output[p + 9];
            int nameOffset = BitConverter.ToUInt16(output, p + 10);
            if (named != 0 && (nameOffset < minimum || nameOffset > length - named * 2))
                throw new IOException("Attribute name escapes its record.");
            if (!nonresident)
            {
                int valueLength = checked((int)BitConverter.ToUInt32(output, p + 16));
                int valueOffset = BitConverter.ToUInt16(output, p + 20);
                if (valueOffset < 24 || valueOffset > length - valueLength) throw new IOException("Resident value escapes its attribute.");
                int value = p + valueOffset;
                if (type == 0x10)
                {
                    if (valueLength < 36 || record.HasStandardInformation) throw new IOException("Invalid standard information.");
                    record.Created = Timestamp(output, value); record.Written = Timestamp(output, value + 8);
                    record.Accessed = Timestamp(output, value + 24);
                    // Keep Windows attributes, including pin/recall flags. The two NTFS
                    // directory/index flags are internal; directory identity comes from the FILE header.
                    record.Attributes = (FileAttributes)(BitConverter.ToUInt32(output, value + 32) & ~0x30000000u);
                    if (record.Directory) record.Attributes |= FileAttributes.Directory;
                    record.HasStandardInformation = true;
                }
                else if (type == 0x30) ReadName(output, value, valueLength, record);
                else if (type == 0x80 && named == 0)
                {
                    if (record.HasData) throw new IOException("Duplicate unnamed data origin.");
                    record.HasData = true; record.Length = valueLength;
                }
            }
            else if (type == 0x10 || type == 0x30) throw new IOException("Required resident attribute is nonresident.");
            else if (type == 0x80 && named == 0 && BitConverter.ToInt64(output, p + 16) == 0)
            {
                long sizeBytes = BitConverter.ToInt64(output, p + 48);
                if (sizeBytes < 0 || record.HasData) throw new IOException("Invalid unnamed data size or duplicate origin.");
                record.HasData = true; record.Length = sizeBytes;
            }
            offset += length;
        }
        throw new IOException("Missing attribute terminator.");
    }

    private static DateTime Timestamp(byte[] bytes, int offset)
    {
        try { return DateTime.FromFileTimeUtc(BitConverter.ToInt64(bytes, offset)); }
        catch (ArgumentOutOfRangeException e) { throw new IOException("Invalid NTFS timestamp.", e); }
    }

    private static void ReadName(byte[] bytes, int value, int length, NtfsFileRecord record)
    {
        if (length < 66 || bytes[value + 64] == 0 || bytes[value + 64] * 2 > length - 66 || bytes[value + 65] > 3)
            throw new IOException("Invalid FILE_NAME value.");
        record.NameAttributeCount++;
        if (bytes[value + 65] == 2) return; // Count DOS aliases for record completeness, but emit only long-name links.
        // NTFS stores UTF-16 code units, including names with unpaired surrogates.
        // A replacement decoder changes the identity of that path component.
        char[] characters = new char[bytes[value + 64]];
        for (int i = 0; i < characters.Length; i++) characters[i] = (char)BitConverter.ToUInt16(bytes, value + 66 + 2 * i);
        string name = new string(characters);
        ulong parent = BitConverter.ToUInt64(bytes, value);
        if (name == ".." || name == "." && parent != record.Id || name.IndexOfAny(InvalidNameCharacters) >= 0)
            throw new IOException("Unsafe FILE_NAME path component.");
        record.Links.Add(new NtfsLink { ParentId = parent, Name = name });
    }

    private static void ValidateSequenceLayout(byte[] bytes, int start, int size, int sectorBytes)
    {
        int offset = BitConverter.ToUInt16(bytes, start + 4), count = BitConverter.ToUInt16(bytes, start + 6);
        int firstAttribute = BitConverter.ToUInt16(bytes, start + 20);
        if (sectorBytes < 512 || size % ProtectionStride != 0 || count != size / ProtectionStride + 1 || offset < 42 ||
            offset > size - count * 2 || offset + count * 2 > firstAttribute || offset + count * 2 > ProtectionStride - 2)
            throw new IOException("Invalid update sequence array.");
        // Windows supplies logical bytes. In live API output the USA can retain old
        // values after the logical record changes. Applying raw-sector fixups here
        // can overwrite valid attribute bytes; only validate the array's bounds.
    }
}
