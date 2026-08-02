namespace FileInspectorX;

/// <summary>
/// Windows-specific binary format detection.
/// </summary>
internal static partial class Signatures {
    private static readonly byte[] ShellLinkClassId = {
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
    };

    internal static bool TryMatchShellLink(ReadOnlySpan<byte> src, out ContentTypeDetectionResult? result)
        => TryMatchShellLink(src, src.Length, out result);

    internal static bool TryMatchShellLink(ReadOnlySpan<byte> src, long? completeLength, out ContentTypeDetectionResult? result) {
        result = null;
        if (src.Length < 76 || src[0] != 0x4C || src[1] != 0 || src[2] != 0 || src[3] != 0)
            return false;

        for (int i = 0; i < ShellLinkClassId.Length; i++)
            if (src[4 + i] != ShellLinkClassId[i]) return false;

        uint showCommand = ReadUInt32LittleEndian(src, 60);
        if (showCommand is not (1u or 3u or 7u) || ReadUInt16LittleEndian(src, 66) != 0 ||
            ReadUInt32LittleEndian(src, 68) != 0 || ReadUInt32LittleEndian(src, 72) != 0) return false;

        ShellLinkParseStatus status = InspectShellLinkStructures(src, completeLength);
        if (status == ShellLinkParseStatus.Invalid) return false;
        result = new ContentTypeDetectionResult {
            Extension = "lnk",
            MimeType = "application/x-ms-shortcut",
            Confidence = status == ShellLinkParseStatus.Complete ? "High" : "Medium",
            Reason = "shell-link:header-clsid" +
                     (status == ShellLinkParseStatus.Complete ? ";flagged-structures" :
                      status == ShellLinkParseStatus.UnrecognizedExtraData ? ";unrecognized-extra-data" : ";sampled-structures")
        };
        return true;
    }

    private enum ShellLinkParseStatus { Invalid, Sampled, UnrecognizedExtraData, Complete }

    private static ShellLinkParseStatus InspectShellLinkStructures(ReadOnlySpan<byte> src, long? completeLength) {
        if (completeLength < 0) return ShellLinkParseStatus.Invalid;
        uint flags = ReadUInt32LittleEndian(src, 20);
        const uint DefinedLinkFlags = 0x07FEF7FF;
        if ((flags & ~DefinedLinkFlags) != 0) return ShellLinkParseStatus.Invalid;
        int cursor = 76;

        if ((flags & 0x00000001) != 0) {
            ShellLinkParseStatus status = EnsureShellLinkRange(cursor, 2, src.Length, completeLength);
            if (status != ShellLinkParseStatus.Complete) return status;
            ushort idListSize = ReadUInt16LittleEndian(src, cursor);
            if (idListSize < 2) return ShellLinkParseStatus.Invalid;
            cursor += 2;
            status = EnsureShellLinkRange(cursor, idListSize, src.Length, completeLength);
            if (status != ShellLinkParseStatus.Complete) return status;
            if (!TryValidateShellLinkIdList(src.Slice(cursor, idListSize))) return ShellLinkParseStatus.Invalid;
            cursor += idListSize;
        }

        if ((flags & 0x00000002) != 0) {
            ShellLinkParseStatus status = EnsureShellLinkRange(cursor, 8, src.Length, completeLength);
            if (status != ShellLinkParseStatus.Complete) return status;
            uint linkInfoSize = ReadUInt32LittleEndian(src, cursor);
            uint linkInfoHeaderSize = ReadUInt32LittleEndian(src, cursor + 4);
            if (linkInfoSize < 0x1C || linkInfoHeaderSize < 0x1C || linkInfoHeaderSize > linkInfoSize)
                return ShellLinkParseStatus.Invalid;
            status = EnsureShellLinkRange(cursor, linkInfoSize, src.Length, completeLength);
            if (status != ShellLinkParseStatus.Complete) return status;
            if (!TryValidateShellLinkLinkInfo(src.Slice(cursor, checked((int)linkInfoSize)))) return ShellLinkParseStatus.Invalid;
            cursor += checked((int)linkInfoSize);
        }

        bool unicode = (flags & 0x00000080) != 0;
        for (uint stringFlag = 0x00000004; stringFlag <= 0x00000040; stringFlag <<= 1) {
            if ((flags & stringFlag) == 0) continue;
            ShellLinkParseStatus status = EnsureShellLinkRange(cursor, 2, src.Length, completeLength);
            if (status != ShellLinkParseStatus.Complete) return status;
            ushort characterCount = ReadUInt16LittleEndian(src, cursor);
            cursor += 2;
            int byteCount = characterCount * (unicode ? 2 : 1);
            status = EnsureShellLinkRange(cursor, byteCount, src.Length, completeLength);
            if (status != ShellLinkParseStatus.Complete) return status;
            cursor += byteCount;
        }

        bool unrecognizedExtraData = false;
        while (true) {
            ShellLinkParseStatus status = EnsureShellLinkRange(cursor, 4, src.Length, completeLength);
            if (status != ShellLinkParseStatus.Complete) return status;
            uint blockSize = ReadUInt32LittleEndian(src, cursor);
            if (blockSize == 0) {
                cursor += 4;
                return completeLength.HasValue && cursor != completeLength.Value
                    ? ShellLinkParseStatus.Invalid
                    : unrecognizedExtraData ? ShellLinkParseStatus.UnrecognizedExtraData : ShellLinkParseStatus.Complete;
            }
            if (blockSize < 8) return ShellLinkParseStatus.Invalid;
            status = EnsureShellLinkRange(cursor, blockSize, src.Length, completeLength);
            if (status != ShellLinkParseStatus.Complete) return status;
            if (!TryValidateShellLinkExtraData(src.Slice(cursor, checked((int)blockSize)), out bool recognized))
                return ShellLinkParseStatus.Invalid;
            unrecognizedExtraData |= !recognized;
            cursor += checked((int)blockSize);
        }
    }

    private static bool TryValidateShellLinkIdList(ReadOnlySpan<byte> idList)
    {
        int cursor = 0;
        while (cursor + 2 <= idList.Length)
        {
            ushort itemSize = ReadUInt16LittleEndian(idList, cursor);
            if (itemSize == 0) return cursor + 2 == idList.Length;
            if (itemSize < 2 || itemSize > idList.Length - cursor) return false;
            cursor += itemSize;
        }
        return false;
    }

    private static bool TryValidateShellLinkLinkInfo(ReadOnlySpan<byte> block)
    {
        if (block.Length < 28 || ReadUInt32LittleEndian(block, 0) != block.Length) return false;
        uint headerSize = ReadUInt32LittleEndian(block, 4);
        uint flags = ReadUInt32LittleEndian(block, 8);
        uint volumeOffset = ReadUInt32LittleEndian(block, 12);
        uint localPathOffset = ReadUInt32LittleEndian(block, 16);
        uint networkOffset = ReadUInt32LittleEndian(block, 20);
        uint suffixOffset = ReadUInt32LittleEndian(block, 24);
        if (headerSize is not (0x1Cu or >= 0x24u) || headerSize > block.Length || flags is < 1 or > 3 ||
            !TryValidateShellLinkAnsiString(block, suffixOffset, headerSize)) return false;
        if ((flags & 1) != 0)
        {
            if (!TryValidateShellLinkVolume(block, volumeOffset, headerSize) ||
                !TryValidateShellLinkAnsiString(block, localPathOffset, headerSize)) return false;
        }
        else if (volumeOffset != 0 || localPathOffset != 0) return false;
        if ((flags & 2) != 0)
        {
            if (!TryValidateShellLinkNetwork(block, networkOffset, headerSize)) return false;
        }
        else if (networkOffset != 0) return false;
        if (headerSize >= 0x24)
        {
            uint localUnicode = ReadUInt32LittleEndian(block, 28);
            uint suffixUnicode = ReadUInt32LittleEndian(block, 32);
            if (localUnicode != 0 && !TryValidateShellLinkUnicodeString(block, localUnicode, headerSize) ||
                suffixUnicode != 0 && !TryValidateShellLinkUnicodeString(block, suffixUnicode, headerSize)) return false;
        }
        return true;
    }

    private static bool TryValidateShellLinkVolume(ReadOnlySpan<byte> linkInfo, uint offset, uint minimumOffset)
    {
        if (offset < minimumOffset || offset > linkInfo.Length - 16) return false;
        int start = (int)offset;
        uint size = ReadUInt32LittleEndian(linkInfo, start);
        if (size < 16 || size > linkInfo.Length - start || ReadUInt32LittleEndian(linkInfo, start + 4) > 6) return false;
        var volume = linkInfo.Slice(start, (int)size);
        uint labelOffset = ReadUInt32LittleEndian(volume, 12);
        if (labelOffset == 0x14)
            return volume.Length >= 20 && TryValidateShellLinkUnicodeString(volume, ReadUInt32LittleEndian(volume, 16), 20);
        return TryValidateShellLinkAnsiString(volume, labelOffset, 16);
    }

    private static bool TryValidateShellLinkNetwork(ReadOnlySpan<byte> linkInfo, uint offset, uint minimumOffset)
    {
        if (offset < minimumOffset || offset > linkInfo.Length - 20) return false;
        int start = (int)offset;
        uint size = ReadUInt32LittleEndian(linkInfo, start);
        if (size < 20 || size > linkInfo.Length - start) return false;
        var network = linkInfo.Slice(start, (int)size);
        uint flags = ReadUInt32LittleEndian(network, 4);
        uint netNameOffset = ReadUInt32LittleEndian(network, 8);
        uint deviceNameOffset = ReadUInt32LittleEndian(network, 12);
        if ((flags & ~3u) != 0 || !TryValidateShellLinkAnsiString(network, netNameOffset, 20) ||
            (flags & 1) != 0 && !TryValidateShellLinkAnsiString(network, deviceNameOffset, 20) ||
            (flags & 1) == 0 && deviceNameOffset != 0) return false;
        if (netNameOffset > 20)
        {
            if (network.Length < 28 || !TryValidateShellLinkUnicodeString(network, ReadUInt32LittleEndian(network, 20), 28)) return false;
            uint deviceUnicode = ReadUInt32LittleEndian(network, 24);
            if ((flags & 1) != 0 && !TryValidateShellLinkUnicodeString(network, deviceUnicode, 28) ||
                (flags & 1) == 0 && deviceUnicode != 0) return false;
        }
        return true;
    }

    private static bool TryValidateShellLinkAnsiString(ReadOnlySpan<byte> block, uint offset, uint minimumOffset)
    {
        if (offset < minimumOffset || offset >= block.Length) return false;
        for (int index = (int)offset; index < block.Length; index++) if (block[index] == 0) return true;
        return false;
    }

    private static bool TryValidateShellLinkUnicodeString(ReadOnlySpan<byte> block, uint offset, uint minimumOffset)
    {
        if (offset < minimumOffset || offset > block.Length - 2 || (offset & 1) != 0) return false;
        for (int index = (int)offset; index + 1 < block.Length; index += 2)
            if (block[index] == 0 && block[index + 1] == 0) return true;
        return false;
    }

    private static ShellLinkParseStatus EnsureShellLinkRange(int offset, long length, int sampledLength, long? completeLength) {
        if (length < 0 || length > int.MaxValue || offset > int.MaxValue - length)
            return ShellLinkParseStatus.Invalid;
        long end = offset + length;
        if (completeLength.HasValue && end > completeLength.Value) return ShellLinkParseStatus.Invalid;
        if (end > sampledLength) return completeLength.HasValue && completeLength.Value <= sampledLength
            ? ShellLinkParseStatus.Invalid
            : ShellLinkParseStatus.Sampled;
        return ShellLinkParseStatus.Complete;
    }
}
