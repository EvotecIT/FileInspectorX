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

        ShellLinkParseStatus status = InspectShellLinkStructures(src, completeLength);
        if (status == ShellLinkParseStatus.Invalid) return false;
        result = new ContentTypeDetectionResult {
            Extension = "lnk",
            MimeType = "application/x-ms-shortcut",
            Confidence = status == ShellLinkParseStatus.Complete ? "High" : "Medium",
            Reason = "shell-link:header-clsid" +
                     (status == ShellLinkParseStatus.Complete ? ";flagged-structures" : ";sampled-structures")
        };
        return true;
    }

    private enum ShellLinkParseStatus { Invalid, Sampled, Complete }

    private static ShellLinkParseStatus InspectShellLinkStructures(ReadOnlySpan<byte> src, long? completeLength) {
        if (completeLength < 0) return ShellLinkParseStatus.Invalid;
        uint flags = ReadUInt32LittleEndian(src, 20);
        int cursor = 76;

        if ((flags & 0x00000001) != 0) {
            ShellLinkParseStatus status = EnsureShellLinkRange(cursor, 2, src.Length, completeLength);
            if (status != ShellLinkParseStatus.Complete) return status;
            ushort idListSize = ReadUInt16LittleEndian(src, cursor);
            if (idListSize < 2) return ShellLinkParseStatus.Invalid;
            cursor += 2;
            status = EnsureShellLinkRange(cursor, idListSize, src.Length, completeLength);
            if (status != ShellLinkParseStatus.Complete) return status;
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

        while (true) {
            ShellLinkParseStatus status = EnsureShellLinkRange(cursor, 4, src.Length, completeLength);
            if (status != ShellLinkParseStatus.Complete) return status;
            uint blockSize = ReadUInt32LittleEndian(src, cursor);
            if (blockSize == 0) {
                cursor += 4;
                return completeLength.HasValue && cursor != completeLength.Value
                    ? ShellLinkParseStatus.Invalid
                    : ShellLinkParseStatus.Complete;
            }
            if (blockSize < 4) return ShellLinkParseStatus.Invalid;
            status = EnsureShellLinkRange(cursor, blockSize, src.Length, completeLength);
            if (status != ShellLinkParseStatus.Complete) return status;
            cursor += checked((int)blockSize);
        }
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
