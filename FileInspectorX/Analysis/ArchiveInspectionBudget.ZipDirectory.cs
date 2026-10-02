namespace FileInspectorX;

internal sealed partial class ArchiveInspectionBudget
{
    internal int EncryptedEntryCount { get; private set; }

    internal bool CheckCentralDirectory(Stream stream, out int? declaredEntryCount)
    {
        declaredEntryCount = null;
        EncryptedEntryCount = 0;
        InspectionOperation.CheckCancellation();
        if (!stream.CanSeek)
        {
            AddIssue("archive:seek-required");
            return false;
        }
        var length = stream.Length;
        if (length < 22)
        {
            AddIssue("archive:central-directory-invalid");
            return false;
        }

        var originalPosition = stream.Position;
        try
        {
            var tail = new byte[(int)Math.Min(length, 65_557L)];
            stream.Position = length - tail.Length;
            if (ReadFully(stream, tail) != tail.Length)
                return InvalidDirectory();

            // ZipArchive selects the last end-record signature. If a comment
            // contains a later decoy, never validate an earlier directory and
            // then let the framework materialize a different one.
            for (var offset = tail.Length - 22; offset >= 0; offset--)
            {
                if ((offset & 1023) == 0) InspectionOperation.CheckCancellation();
                if (ReadUInt32(tail, offset) != 0x06054b50) continue;
                if (offset + 22 + ReadUInt16(tail, offset + 20) != tail.Length) return InvalidDirectory();

                var eocdPosition = length - tail.Length + offset;
                if (!TryReadDirectory(stream, tail, offset, eocdPosition, out var directory))
                    return false;
                declaredEntryCount = directory.Entries <= int.MaxValue ? (int)directory.Entries : null;

                // Keep values unsigned until after comparison with the limits.
                // A hostile 64-bit count or size must not wrap into a small value.
                if (directory.Entries > (ulong)_maxEntries) AddIssue("archive:entry-count-limit");
                if (directory.Bytes > (ulong)_maxCentralDirectoryBytes) AddIssue("archive:directory-size-limit");
                if (!IsComplete) return false;

                if (!ValidateCentralDirectoryLayout(stream, directory, out var encryptedEntries)) return InvalidDirectory();
                EncryptedEntryCount = encryptedEntries;
                return true;
            }
            return InvalidDirectory();
        }
        finally
        {
            stream.Position = originalPosition;
        }
    }

    private bool TryReadDirectory(Stream stream, byte[] tail, int offset, long eocdPosition, out ZipDirectory directory)
    {
        ulong disk = ReadUInt16(tail, offset + 4);
        ulong directoryDisk = ReadUInt16(tail, offset + 6);
        ulong entriesOnDisk = ReadUInt16(tail, offset + 8);
        ulong entries = ReadUInt16(tail, offset + 10);
        ulong bytes = ReadUInt32(tail, offset + 12);
        ulong start = ReadUInt32(tail, offset + 16);
        directory = new ZipDirectory(entries, bytes, start, eocdPosition);
        bool needsZip64 = disk == ushort.MaxValue || directoryDisk == ushort.MaxValue ||
            entriesOnDisk == ushort.MaxValue || entries == ushort.MaxValue ||
            bytes == uint.MaxValue || start == uint.MaxValue;

        // The locator must be immediately before the classic end record.
        // Usually its signature is already in the fixed-size tail buffer.
        bool hasLocator = false;
        if (eocdPosition >= 20)
        {
            if (offset >= 20) hasLocator = ReadUInt32(tail, offset - 20) == 0x07064b50;
            else
            {
                var signature = new byte[4];
                stream.Position = eocdPosition - 20;
                hasLocator = ReadFully(stream, signature) == 4 && ReadUInt32(signature, 0) == 0x07064b50;
            }
        }
        if (!hasLocator)
        {
            if (needsZip64) return InvalidDirectory();
            if (disk != 0 || directoryDisk != 0 || entriesOnDisk != entries)
                return UnsupportedSplitArchive();
            return true;
        }

        var locator = new byte[20];
        stream.Position = eocdPosition - locator.Length;
        if (ReadFully(stream, locator) != locator.Length) return InvalidDirectory();
        if (ReadUInt32(locator, 4) != 0 || ReadUInt32(locator, 16) != 1)
            return UnsupportedSplitArchive();
        var recordPosition = ReadUInt64(locator, 8);
        var locatorPosition = eocdPosition - locator.Length;
        if (locatorPosition < 56 || recordPosition > (ulong)(locatorPosition - 56))
            return InvalidDirectory();

        // Read only the fixed record. Its extensible sector is range checked
        // and skipped, never allocated using the untrusted size field.
        var record = new byte[56];
        stream.Position = (long)recordPosition;
        if (ReadFully(stream, record) != record.Length || ReadUInt32(record, 0) != 0x06064b50)
            return InvalidDirectory();
        var recordSize = ReadUInt64(record, 4);
        if (recordSize < 44 || recordSize != (ulong)locatorPosition - recordPosition - 12)
            return InvalidDirectory();
        var wideDisk = ReadUInt32(record, 16);
        var wideDirectoryDisk = ReadUInt32(record, 20);
        var wideEntriesOnDisk = ReadUInt64(record, 24);
        var wideEntries = ReadUInt64(record, 32);
        var wideBytes = ReadUInt64(record, 40);
        var wideStart = ReadUInt64(record, 48);
        if (wideDisk != 0 || wideDirectoryDisk != 0 || wideEntriesOnDisk != wideEntries)
            return UnsupportedSplitArchive();
        if (!MatchesClassic(disk, wideDisk, ushort.MaxValue) ||
            !MatchesClassic(directoryDisk, wideDirectoryDisk, ushort.MaxValue) ||
            !MatchesClassic(entriesOnDisk, wideEntriesOnDisk, ushort.MaxValue) ||
            !MatchesClassic(entries, wideEntries, ushort.MaxValue) ||
            !MatchesClassic(bytes, wideBytes, uint.MaxValue) ||
            !MatchesClassic(start, wideStart, uint.MaxValue))
            return InvalidDirectory();
        directory = new ZipDirectory(wideEntries, wideBytes, wideStart, (long)recordPosition);
        return true;
    }

    private bool InvalidDirectory()
    {
        AddIssue("archive:central-directory-invalid");
        return false;
    }

    private bool UnsupportedSplitArchive()
    {
        AddIssue("archive:multi-disk-unsupported");
        return false;
    }

    private static bool MatchesClassic(ulong classic, ulong wide, ulong sentinel) => classic == sentinel || classic == wide;

    private static bool ValidateCentralDirectoryLayout(Stream stream, ZipDirectory directory, out int encryptedEntries)
    {
        encryptedEntries = 0;
        // Validate the same offset ZipArchive will use, and require the exact
        // directory range to end at its following end record. Subtractions keep
        // hostile unsigned offsets from overflowing signed stream positions.
        if (directory.Start > (ulong)directory.End || directory.Bytes != (ulong)directory.End - directory.Start)
            return false;
        if (directory.Bytes == 0) return directory.Entries == 0;
        if (directory.Entries == 0) return false;
        var header = new byte[46];
        var extraHeader = new byte[4];
        ulong consumed = 0;
        stream.Position = (long)directory.Start;
        for (ulong index = 0; index < directory.Entries; index++)
        {
            InspectionOperation.CheckCancellation();
            if (directory.Bytes - consumed < (ulong)header.Length || ReadFully(stream, header) != header.Length)
                return false;
            if (ReadUInt32(header, 0) != 0x02014b50) return false;
            var nameLength = ReadUInt16(header, 28);
            var extraLength = ReadUInt16(header, 30);
            var commentLength = ReadUInt16(header, 32);
            var variableLength = (ulong)nameLength + extraLength + commentLength;
            consumed += (ulong)header.Length + variableLength;
            if (consumed > directory.Bytes) return false;
            bool encrypted = (ReadUInt16(header, 8) & 1) != 0;
            if (encrypted || extraLength == 0) stream.Seek((long)variableLength, SeekOrigin.Current);
            else
            {
                stream.Seek(nameLength, SeekOrigin.Current);
                if (!TryReadEncryptionExtra(stream, extraLength, extraHeader, out encrypted)) return false;
                stream.Seek(commentLength, SeekOrigin.Current);
            }
            if (encrypted) encryptedEntries++;
        }
        if (consumed == directory.Bytes) return true;

        // An optional digital signature must consume the exact remainder.
        var signatureHeader = new byte[6];
        if (directory.Bytes - consumed < (ulong)signatureHeader.Length || ReadFully(stream, signatureHeader) != signatureHeader.Length)
            return false;
        if (ReadUInt32(signatureHeader, 0) != 0x05054b50) return false;
        consumed += (ulong)signatureHeader.Length + ReadUInt16(signatureHeader, 4);
        return consumed == directory.Bytes;
    }

    private static bool TryReadEncryptionExtra(Stream stream, int remaining, byte[] header, out bool encrypted)
    {
        encrypted = false;
        while (remaining > 0)
        {
            if (remaining < header.Length || ReadFully(stream, header) != header.Length) return false;
            int payloadLength = ReadUInt16(header, 2);
            remaining -= header.Length;
            if (payloadLength > remaining) return false;
            if (ReadUInt16(header, 0) == 0x9901) encrypted = true; // WinZip AES cue
            stream.Seek(payloadLength, SeekOrigin.Current);
            remaining -= payloadLength;
        }
        return true;
    }

    private static int ReadFully(Stream stream, byte[] buffer)
    {
        var total = 0;
        while (total < buffer.Length)
        {
            InspectionOperation.CheckCancellation();
            var read = stream.Read(buffer, total, buffer.Length - total);
            InspectionOperation.CheckCancellation();
            if (read <= 0) break;
            total += read;
        }
        return total;
    }

    private static ushort ReadUInt16(byte[] buffer, int offset) => (ushort)(buffer[offset] | (buffer[offset + 1] << 8));
    private static uint ReadUInt32(byte[] buffer, int offset) =>
        (uint)(buffer[offset] | (buffer[offset + 1] << 8) | (buffer[offset + 2] << 16) | (buffer[offset + 3] << 24));
    private static ulong ReadUInt64(byte[] buffer, int offset) => ReadUInt32(buffer, offset) | ((ulong)ReadUInt32(buffer, offset + 4) << 32);

    private readonly struct ZipDirectory
    {
        internal ZipDirectory(ulong entries, ulong bytes, ulong start, long end)
        {
            Entries = entries;
            Bytes = bytes;
            Start = start;
            End = end;
        }
        internal ulong Entries { get; }
        internal ulong Bytes { get; }
        internal ulong Start { get; }
        internal long End { get; }
    }
}
